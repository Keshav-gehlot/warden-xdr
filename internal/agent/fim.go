package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// fileRec is one entry of the FIM baseline (the syscheck database).
type fileRec struct {
	SHA256 string `json:"s"`
	Size   int64  `json:"z"`
	Mode   string `json:"m"`
	UID    string `json:"u"`
	GID    string `json:"g"`
	MTime  int64  `json:"t"`
}

func (a *Agent) fimLoop(ctx context.Context) {
	dbPath := filepath.Join(a.lc.StateDir, "syscheck.db.json")
	base := map[string]fileRec{}
	haveBaseline := false
	if b, err := os.ReadFile(dbPath); err == nil && json.Unmarshal(b, &base) == nil {
		haveBaseline = true
	}
	periodic(ctx, 10*time.Second, func() time.Duration { return interval(a.Config().FIM.IntervalSec, 300, 10) }, a.trigFIM, func() {
		start := time.Now()
		cur := a.fimScan(ctx)
		if cur == nil {
			return
		}
		changes := 0
		if haveBaseline {
			changes = a.fimDiff(base, cur)
		} else {
			log.Printf("syscheck: baseline created (%d files)", len(cur))
		}
		base, haveBaseline = cur, true
		b, _ := json.Marshal(base)
		os.WriteFile(dbPath+".tmp", b, 0600)
		os.Rename(dbPath+".tmp", dbPath)
		if changes > 0 {
			log.Printf("syscheck: scan done in %s, %d files, %d changes", time.Since(start).Round(time.Millisecond), len(cur), changes)
		}
	})
}

func (a *Agent) fimScan(ctx context.Context) map[string]fileRec {
	cfg := a.Config().FIM
	var ignore []*regexp.Regexp
	for _, p := range cfg.Ignore {
		if re, err := regexp.Compile(p); err == nil {
			ignore = append(ignore, re)
		}
	}
	maxSize := int64(cfg.MaxFileMB) << 20
	if maxSize <= 0 {
		maxSize = 50 << 20
	}
	out := map[string]fileRec{}
	for _, dir := range cfg.Directories {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			for _, re := range ignore {
				if re.MatchString(p) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if d.IsDir() || d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			uid, gid := fileOwner(fi)
			r := fileRec{Size: fi.Size(), Mode: fi.Mode().Perm().String(), UID: uid, GID: gid, MTime: fi.ModTime().Unix()}
			if fi.Size() <= maxSize {
				r.SHA256 = hashFile(p)
			}
			out[p] = r
			return nil
		})
	}
	return out
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Agent) fimDiff(old, cur map[string]fileRec) int {
	n := 0
	emit := func(path, event string, r fileRec, prev *fileRec, changed []string) {
		n++
		d := map[string]string{"event": event, "path": path, "sha256": r.SHA256, "size": strconv.FormatInt(r.Size, 10),
			"mode": r.Mode, "uid": r.UID, "gid": r.GID, "mtime": strconv.FormatInt(r.MTime, 10)}
		if prev != nil {
			d["sha256_before"], d["size_before"], d["mode_before"] = prev.SHA256, strconv.FormatInt(prev.Size, 10), prev.Mode
			d["changed_attributes"] = strings.Join(changed, ",")
		}
		a.Emit(proto.Event{Type: proto.TypeFIM, Location: "syscheck", Data: d})
	}
	for p, r := range cur {
		o, ok := old[p]
		if !ok {
			emit(p, "added", r, nil, nil)
			continue
		}
		var changed []string
		if o.SHA256 != r.SHA256 {
			changed = append(changed, "sha256")
		}
		if o.Size != r.Size {
			changed = append(changed, "size")
		}
		if o.Mode != r.Mode {
			changed = append(changed, "permission")
		}
		if o.UID != r.UID || o.GID != r.GID {
			changed = append(changed, "owner")
		}
		if len(changed) > 0 {
			emit(p, "modified", r, &o, changed)
		}
	}
	for p, o := range old {
		if _, ok := cur[p]; !ok {
			emit(p, "deleted", o, nil, nil)
		}
	}
	return n
}
