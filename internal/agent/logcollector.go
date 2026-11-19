package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// ---------- file tailing ----------

type tailState struct {
	Offset int64  `json:"offset"`
	Ident  string `json:"ident"` // device+inode, detects rotation
}

func (a *Agent) logcollector(ctx context.Context) {
	posPath := filepath.Join(a.lc.StateDir, "logcollector.pos.json")
	pos := map[string]*tailState{}
	if b, err := os.ReadFile(posPath); err == nil {
		json.Unmarshal(b, &pos)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var files []string
	lastGlob := time.Time{}
	lastSave := time.Now()
	formats := map[string]string{}
	for {
		select {
		case <-ctx.Done():
			savePos(posPath, pos)
			return
		case <-tick.C:
		}
		if time.Since(lastGlob) > 10*time.Second {
			files = files[:0]
			for _, lf := range a.Config().LogFiles {
				matches, _ := filepath.Glob(lf.Path)
				for _, m := range matches {
					files = append(files, m)
					formats[m] = lf.Format
				}
			}
			lastGlob = time.Now()
		}
		for _, f := range files {
			a.readNew(f, formats[f], pos)
		}
		if time.Since(lastSave) > 5*time.Second {
			savePos(posPath, pos)
			lastSave = time.Now()
		}
	}
}

func savePos(p string, pos map[string]*tailState) {
	b, _ := json.Marshal(pos)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, p)
	}
}

func (a *Agent) readNew(path, format string, pos map[string]*tailState) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	ident := fileIdent(fi)
	st, ok := pos[path]
	if !ok {
		// New file: start at the end (like Wazuh, don't replay history)
		pos[path] = &tailState{Offset: fi.Size(), Ident: ident}
		return
	}
	if st.Ident != ident || fi.Size() < st.Offset {
		st.Offset, st.Ident = 0, ident // rotated or truncated
	}
	if fi.Size() == st.Offset {
		return
	}
	f.Seek(st.Offset, io.SeekStart)
	r := bufio.NewReaderSize(io.LimitReader(f, 8<<20), 64*1024) // at most 8 MiB per tick per file
	var read int64
	for {
		line, err := r.ReadString('\n')
		if err != nil { // partial last line: wait for the rest
			break
		}
		read += int64(len(line))
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if len(line) > 65536 {
			line = line[:65536]
		}
		a.Emit(proto.Event{Type: proto.TypeLog, Location: path, Log: line, Data: map[string]string{"log_format": format}})
	}
	st.Offset += read
}

// ---------- command monitoring ----------

func (a *Agent) commandMonitor(ctx context.Context) {
	last := map[string]time.Time{}
	var mu sync.Mutex
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		for _, c := range a.Config().Commands {
			alias := c.Alias
			if alias == "" {
				alias = c.Command
			}
			mu.Lock()
			due := time.Since(last[alias]) >= interval(c.IntervalSec, 360, 10)
			if due {
				last[alias] = time.Now()
			}
			mu.Unlock()
			if !due {
				continue
			}
			go func(cmd, alias string) {
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				out, err := exec.CommandContext(cctx, "/bin/sh", "-c", cmd).CombinedOutput()
				if err != nil && len(out) == 0 {
					out = []byte("error: " + err.Error())
				}
				if len(out) > 256*1024 {
					out = out[:256*1024]
				}
				a.Emit(proto.Event{Type: proto.TypeCommand, Location: "command_" + alias, Log: strings.TrimSpace(string(out)),
					Data: map[string]string{"alias": alias, "command": cmd}})
			}(c.Command, alias)
		}
	}
}
