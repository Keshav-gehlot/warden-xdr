package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/engine"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

func (s *Server) enqueue(a *store.Agent, e proto.Event) bool {
	select {
	case s.queue <- queued{agent: a, ev: e}:
		return true
	default:
		return false
	}
}

func (s *Server) analysisLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.queue:
			s.process(q.agent, q.ev)
		}
	}
}

// process is the per-event pipeline: module side effects → decode → rules →
// alert → outputs (DB, live stream, webhooks, active response).
func (s *Server) process(a *store.Agent, e proto.Event) {
	s.metricsMu.Lock()
	s.evCount++
	s.metricsMu.Unlock()
	if s.cfg.Archive {
		s.st.ArchiveEvent(a.ID, e)
	}
	ev := &engine.Event{AgentID: a.ID, AgentName: a.Name, Type: e.Type, Location: e.Location,
		FullLog: e.Log, Timestamp: e.Timestamp, Fields: map[string]string{}}
	for k, v := range e.Data {
		ev.Fields[k] = v
	}

	switch e.Type {
	case proto.TypeLog:
		engine.PreDecode(ev)
	case proto.TypeCommand:
		s.diffCommand(a, ev)
	case proto.TypeFIM:
		s.recordFIM(a, ev)
	case proto.TypeSCA:
		s.recordSCA(a, ev)
	case proto.TypeAR:
		if id, err := strconv.ParseInt(ev.Fields["command_id"], 10, 64); err == nil && id > 0 {
			st := "done"
			if ev.Fields["status"] == "failed" || ev.Fields["status"] == "error" {
				st = "failed"
			}
			s.st.CompleteCommand(id, a.ID, st, ev.Fields["output"])
		}
		if ev.FullLog == "" {
			ev.FullLog = fmt.Sprintf("active response %s %s: %s %s", ev.Fields["command"], ev.Fields["status"], ev.Fields["target"], ev.Fields["output"])
		}
	case proto.TypeAgent:
		ev.FullLog = fmt.Sprintf("agent %s (%s) %s", a.Name, a.ID, ev.Fields["event"])
	}
	if ev.FullLog == "" {
		ev.FullLog = summarize(ev.Fields)
	}

	res := s.eng.Analyze(ev)
	if res == nil || res.Rule.Level < s.cfg.AlertLevel {
		return
	}
	r := res.Rule
	al := &store.Alert{Timestamp: ev.Timestamp.Unix(), AgentID: a.ID, AgentName: a.Name, RuleID: r.ID, Level: r.Level,
		Description: r.Description, Groups: r.Groups, Mitre: r.Mitre, Compliance: r.Compliance, Decoder: ev.Decoder,
		Location: ev.Location, FullLog: ev.FullLog, Fields: ev.Fields, SrcIP: ev.Fields["srcip"], FiredTimes: res.FiredTimes}
	if al.Groups == nil {
		al.Groups = []string{}
	}
	if al.Mitre == nil {
		al.Mitre = []string{}
	}
	if err := s.st.InsertAlert(al); err != nil {
		log.Printf("insert alert: %v", err)
		return
	}
	s.metricsMu.Lock()
	s.alCount++
	s.metricsMu.Unlock()
	b, _ := json.Marshal(al)
	s.broadcast(b)
	s.webhooks(al)
	if r.ActiveResponse != nil {
		s.activeResponse(a, r, ev)
	}
}

func summarize(m map[string]string) string {
	var parts []string
	for _, k := range []string{"event", "path", "title", "result", "cve", "package", "check", "message"} {
		if v, ok := m[k]; ok && v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

// ---------- module side effects ----------

func (s *Server) recordFIM(a *store.Agent, ev *engine.Event) {
	f := ev.Fields
	size, _ := strconv.ParseInt(f["size"], 10, 64)
	mt, _ := strconv.ParseInt(f["mtime"], 10, 64)
	s.st.UpsertFIM(store.FIMFile{AgentID: a.ID, Path: f["path"], SHA256: f["sha256"], Size: size, Mode: f["mode"],
		UID: f["uid"], GID: f["gid"], MTime: mt, LastEvent: f["event"], UpdatedAt: ev.Timestamp.Unix()})
	if ev.FullLog == "" {
		ev.FullLog = fmt.Sprintf("File '%s' %s", f["path"], f["event"])
		if f["changed_attributes"] != "" {
			ev.FullLog += " (" + f["changed_attributes"] + ")"
		}
	}
}

func (s *Server) recordSCA(a *store.Agent, ev *engine.Event) {
	f := ev.Fields
	cid, _ := strconv.Atoi(f["check_id"])
	var comp map[string][]string
	json.Unmarshal([]byte(f["compliance"]), &comp)
	prev, _ := s.st.UpsertSCA(store.SCAResult{AgentID: a.ID, PolicyID: f["policy_id"], PolicyName: f["policy"], CheckID: cid,
		Title: f["title"], Result: f["result"], Reason: f["reason"], Remediation: f["remediation"], Compliance: comp,
		UpdatedAt: ev.Timestamp.Unix()})
	f["previous_result"] = prev
	if ev.FullLog == "" {
		ev.FullLog = fmt.Sprintf("SCA %s check %d: %s → %s", f["policy_id"], cid, f["title"], f["result"])
	}
}

func (s *Server) diffCommand(a *store.Agent, ev *engine.Event) {
	alias := ev.Fields["alias"]
	key := a.ID + "|" + alias
	s.cmdMu.Lock()
	prev, seen := s.lastCmd[key]
	s.lastCmd[key] = ev.FullLog
	s.cmdMu.Unlock()
	ev.Program = "command"
	if seen && prev != ev.FullLog {
		ev.Fields["changed"] = "yes"
		ev.Fields["previous_output"] = prev
	} else {
		ev.Fields["changed"] = "no"
	}
}

// ---------- outputs ----------

func (s *Server) broadcast(b []byte) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for c := range s.subs {
		select {
		case c <- b:
		default: // slow client: drop
		}
	}
}

var hookClient = &http.Client{Timeout: 10 * time.Second}

func (s *Server) webhooks(al *store.Alert) {
	for _, h := range s.cfg.Webhooks {
		if al.Level < h.MinLevel || h.URL == "" {
			continue
		}
		var body []byte
		if h.Format == "slack" {
			body, _ = json.Marshal(map[string]string{"text": fmt.Sprintf("*[warden] Level %d* rule %d on %s (%s): %s\n```%s```",
				al.Level, al.RuleID, al.AgentName, al.AgentID, al.Description, al.FullLog)})
		} else {
			body, _ = json.Marshal(al)
		}
		go func(url string, b []byte) {
			resp, err := hookClient.Post(url, "application/json", bytes.NewReader(b))
			if err != nil {
				log.Printf("webhook %s: %v", url, err)
				return
			}
			resp.Body.Close()
		}(h.URL, body)
	}
}

// activeResponse queues the rule's command on the agent that produced the event.
func (s *Server) activeResponse(a *store.Agent, r *engine.Rule, ev *engine.Event) {
	if !s.cfg.ActiveResponse.Enabled || a.ID == "000" {
		return
	}
	field := r.ActiveResponse.Field
	if field == "" {
		field = "srcip"
	}
	target := ev.Fields[field]
	if target == "" {
		return
	}
	if field == "srcip" {
		ip := net.ParseIP(target)
		if ip == nil || ip.IsLoopback() {
			return
		}
		for _, w := range s.cfg.ActiveResponse.Whitelist {
			if _, n, err := net.ParseCIDR(w); err == nil && n.Contains(ip) || w == target {
				return
			}
		}
	}
	key := a.ID + "|" + r.ActiveResponse.Command + "|" + target
	tmo := r.ActiveResponse.Timeout
	s.arMu.Lock()
	if exp, ok := s.arActive[key]; ok && time.Now().Before(exp) {
		s.arMu.Unlock()
		return
	}
	dur := time.Duration(tmo) * time.Second
	if tmo == 0 {
		dur = 24 * time.Hour
	}
	s.arActive[key] = time.Now().Add(dur)
	s.arMu.Unlock()
	id, err := s.st.QueueCommand(a.ID, r.ActiveResponse.Command, map[string]string{"target": target, "rule": strconv.Itoa(r.ID)}, tmo, "rule "+strconv.Itoa(r.ID))
	if err == nil {
		log.Printf("active response #%d queued: %s %s on agent %s (rule %d)", id, r.ActiveResponse.Command, target, a.ID, r.ID)
	}
}
