package server

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/engine"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
	"github.com/goccy/go-yaml"
)

// ---------- users & sessions ----------

func hashPassword(pass, salt string) string {
	k, _ := pbkdf2.Key(sha256.New, pass, []byte(salt), 210000, 32)
	return hex.EncodeToString(k)
}

func (s *Server) ensureAdmin() error {
	if s.st.UserCount() > 0 {
		return nil
	}
	pass := os.Getenv("WARDEN_ADMIN_PASSWORD")
	if pass == "" {
		pass = s.secretFile("admin-password.txt")
	}
	salt := randHex(16)
	return s.st.SetUser("admin", hashPassword(pass, salt), salt)
}

// SetPassword is used by the `warden-manager passwd` subcommand.
func SetPassword(cfg *Config, user, pass string) error {
	st, err := store.Open(filepath.Join(cfg.DataDir, "warden.db"))
	if err != nil {
		return err
	}
	defer st.DB.Close()
	salt := randHex(16)
	return st.SetUser(user, hashPassword(pass, salt), salt)
}

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.URL.Query().Get("token") // EventSource cannot set headers
		}
		s.sessMu.Lock()
		exp, ok := s.sessions[tok]
		s.sessMu.Unlock()
		if !ok || time.Now().After(exp) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	hash, salt, err := s.st.GetUser(req.Username)
	if err != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(hashPassword(req.Password, salt))) != 1 {
		log.Printf("dashboard: failed login for %q from %s", req.Username, clientIP(r))
		time.Sleep(700 * time.Millisecond)
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	tok := randHex(32)
	s.sessMu.Lock()
	s.sessions[tok] = time.Now().Add(12 * time.Hour)
	s.sessMu.Unlock()
	writeJSON(w, 200, map[string]string{"token": tok, "user": req.Username})
}

// ---------- routing ----------

func (s *Server) apiMux() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "version": proto.Version})
	})
	m.HandleFunc("POST /api/login", s.handleLogin)
	a := func(p string, h http.HandlerFunc) { m.HandleFunc(p, s.authed(h)) }
	a("GET /api/overview", s.apiOverview)
	a("GET /api/alerts", s.apiAlerts)
	a("GET /api/alerts/stream", s.apiStream)
	a("GET /api/agents", s.apiAgents)
	a("GET /api/agents/{id}", s.apiAgent)
	a("DELETE /api/agents/{id}", s.apiDeleteAgent)
	a("PUT /api/agents/{id}/group", s.apiSetGroup)
	a("GET /api/agents/{id}/inventory", s.apiInventory)
	a("POST /api/agents/{id}/commands", s.apiQueueCommand)
	a("GET /api/commands", s.apiCommands)
	a("GET /api/fim", s.apiFIM)
	a("GET /api/sca", s.apiSCA)
	a("GET /api/vulns", s.apiVulns)
	a("POST /api/vulns/sync", s.apiVulnSync)
	a("GET /api/rules", s.apiRules)
	a("POST /api/rules/reload", s.apiReload)
	a("POST /api/logtest", s.apiLogtest)
	a("GET /api/mitre", s.apiMitre)
	a("GET /api/groups", s.apiGroups)
	a("PUT /api/groups/{name}", s.apiPutGroup)
	a("GET /api/manager", s.apiManager)
	m.Handle("/", http.FileServerFS(s.web))
	return secHeaders(m)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

func qint(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

// ---------- handlers ----------

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request) {
	hours := qint(r, "hours", 24)
	st, _ := s.st.Stats(time.Now().Add(-time.Duration(hours) * time.Hour).Unix())
	agents, _ := s.st.ListAgents()
	counts := map[string]int{}
	for _, a := range agents {
		counts[a.Status]++
	}
	st["agents"] = counts
	st["agents_total"] = len(agents)
	writeJSON(w, 200, st)
}

func (s *Server) apiManager(w http.ResponseWriter, r *http.Request) {
	d, rl := s.eng.Counts()
	s.metricsMu.Lock()
	ev, al := s.evCount, s.alCount
	s.metricsMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"version": proto.Version, "uptime_sec": int(time.Since(s.started).Seconds()), "decoders": d, "rules": rl,
		"events_processed": ev, "alerts_generated": al, "queue_len": len(s.queue), "queue_cap": cap(s.queue),
		"cert_fingerprint": s.certFP, "feed": s.st.FeedStats(), "alert_level": s.cfg.AlertLevel,
		"active_response": s.cfg.ActiveResponse.Enabled, "syslog": s.cfg.ListenSyslog,
	})
}

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	aq := store.AlertQuery{AgentID: q.Get("agent"), MinLevel: qint(r, "level", 0), RuleID: qint(r, "rule", 0),
		Group: q.Get("group"), Mitre: q.Get("mitre"), Search: q.Get("q"), Limit: qint(r, "limit", 100), Offset: qint(r, "offset", 0)}
	if h := qint(r, "hours", 0); h > 0 {
		aq.Since = time.Now().Add(-time.Duration(h) * time.Hour).Unix()
	}
	items, total, err := s.st.QueryAlerts(aq)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if items == nil {
		items = []store.Alert{}
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items})
}

func (s *Server) apiStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	c := make(chan []byte, 64)
	s.subMu.Lock()
	s.subs[c] = struct{}{}
	s.subMu.Unlock()
	defer func() { s.subMu.Lock(); delete(s.subs, c); s.subMu.Unlock() }()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-c:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func (s *Server) apiAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.st.ListAgents()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if agents == nil {
		agents = []*store.Agent{}
	}
	writeJSON(w, 200, agents)
}

func (s *Server) apiAgent(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAgent(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) apiDeleteAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteAgent(r.PathValue("id")); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (s *Server) apiSetGroup(w http.ResponseWriter, r *http.Request) {
	var req struct{ Group string }
	json.NewDecoder(r.Body).Decode(&req)
	if !validName.MatchString(req.Group) {
		writeJSON(w, 400, map[string]string{"error": "invalid group"})
		return
	}
	if _, err := os.Stat(filepath.Join(s.groupDir(req.Group), "agent.yml")); err != nil {
		writeJSON(w, 400, map[string]string{"error": "group has no agent.yml"})
		return
	}
	s.st.SetAgentGroup(r.PathValue("id"), req.Group)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) apiInventory(w http.ResponseWriter, r *http.Request) {
	inv, err := s.st.GetInventory(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "no inventory yet"})
		return
	}
	writeJSON(w, 200, inv)
}

var allowedCommands = map[string]bool{"firewall-drop": true, "host-deny": true, "kill-process": true, "disable-account": true,
	"fim-scan": true, "inventory-scan": true, "sca-scan": true, "rootcheck-scan": true, "restart": true}

func (s *Server) apiQueueCommand(w http.ResponseWriter, r *http.Request) {
	var req proto.Command
	json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req)
	if !allowedCommands[req.Name] {
		writeJSON(w, 400, map[string]string{"error": "unknown command"})
		return
	}
	id, err := s.st.QueueCommand(r.PathValue("id"), req.Name, req.Args, req.Timeout, "dashboard")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}

func (s *Server) apiCommands(w http.ResponseWriter, r *http.Request) {
	c, _ := s.st.ListCommands(r.URL.Query().Get("agent"), qint(r, "limit", 200))
	if c == nil {
		c = []store.CommandRow{}
	}
	writeJSON(w, 200, c)
}

func (s *Server) apiFIM(w http.ResponseWriter, r *http.Request) {
	f, _ := s.st.ListFIM(r.URL.Query().Get("agent"), r.URL.Query().Get("q"), qint(r, "limit", 500))
	if f == nil {
		f = []store.FIMFile{}
	}
	writeJSON(w, 200, f)
}

func (s *Server) apiSCA(w http.ResponseWriter, r *http.Request) {
	res, _ := s.st.ListSCA(r.URL.Query().Get("agent"))
	if res == nil {
		res = []store.SCAResult{}
	}
	writeJSON(w, 200, res)
}

func (s *Server) apiVulns(w http.ResponseWriter, r *http.Request) {
	v, _ := s.st.ListVulns(r.URL.Query().Get("agent"), r.URL.Query().Get("severity"))
	if v == nil {
		v = []store.Vuln{}
	}
	writeJSON(w, 200, map[string]any{"items": v, "feed": s.st.FeedStats()})
}

func (s *Server) apiVulnSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ecosystems []string `json:"ecosystems"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req)
	n, err := s.syncOSV(req.Ecosystems)
	if err != nil && len(n) == 0 {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	agents, _ := s.st.ListAgents()
	for _, a := range agents {
		if inv, err := s.st.GetInventory(a.ID); err == nil {
			s.scanVulns(a, inv)
		}
	}
	writeJSON(w, 200, map[string]any{"synced": n})
}

func (s *Server) apiRules(w http.ResponseWriter, r *http.Request) {
	rules := s.eng.Rules()
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	writeJSON(w, 200, rules)
}

func (s *Server) apiReload(w http.ResponseWriter, r *http.Request) {
	if err := s.reloadRules(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	d, rl := s.eng.Counts()
	writeJSON(w, 200, map[string]int{"decoders": d, "rules": rl})
}

// apiLogtest is the equivalent of wazuh-logtest: run a line through the
// decoders and rules without storing anything. Correlation state is shared,
// so repeated submissions can trigger frequency rules.
func (s *Server) apiLogtest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Log      string            `json:"log"`
		Type     string            `json:"type"`
		Location string            `json:"location"`
		Fields   map[string]string `json:"fields"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	if req.Type == "" {
		req.Type = proto.TypeLog
	}
	ev := &engine.Event{AgentID: "logtest", Type: req.Type, FullLog: req.Log, Location: req.Location, Timestamp: time.Now(), Fields: map[string]string{}}
	for k, v := range req.Fields {
		ev.Fields[k] = v
	}
	if req.Type == proto.TypeLog {
		engine.PreDecode(ev)
	}
	res := s.eng.Analyze(ev)
	out := map[string]any{"predecoded": map[string]string{"hostname": ev.Hostname, "program": ev.Program, "message": ev.Message},
		"decoder": ev.Decoder, "fields": ev.Fields}
	if res != nil {
		out["rule"] = res.Rule
		out["alert"] = res.Rule.Level >= s.cfg.AlertLevel
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiMitre(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-time.Duration(qint(r, "hours", 24*7)) * time.Hour).Unix()
	st, _ := s.st.Stats(since)
	counts := map[string]int{}
	if rows, ok := st["mitre"].([]map[string]any); ok {
		for _, row := range rows {
			counts[row["key"].(string)] = row["count"].(int)
		}
	}
	covered := map[string][]int{}
	for _, rl := range s.eng.Rules() {
		for _, t := range rl.Mitre {
			covered[t] = append(covered[t], rl.ID)
		}
	}
	type item struct {
		engine.MitreTechnique
		Alerts int   `json:"alerts"`
		Rules  []int `json:"rules"`
	}
	var out []item
	for id, t := range engine.Mitre {
		out = append(out, item{t, counts[id], covered[id]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, 200, out)
}

func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	dirs, _ := os.ReadDir(filepath.Join(s.cfg.RulesetDir, "shared"))
	agents, _ := s.st.ListAgents()
	var out []map[string]any
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(s.groupDir(d.Name()), "agent.yml"))
		n := 0
		for _, a := range agents {
			if a.Group == d.Name() {
				n++
			}
		}
		h := ""
		if b, err := s.configBundle(d.Name()); err == nil {
			h = b.Hash
		}
		out = append(out, map[string]any{"name": d.Name(), "config": string(raw), "agents": n, "hash": h})
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiPutGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "invalid group name"})
		return
	}
	var req struct {
		Config string `json:"config"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	var probe proto.AgentConfig
	if err := yaml.Unmarshal([]byte(req.Config), &probe); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid YAML: " + err.Error()})
		return
	}
	os.MkdirAll(s.groupDir(name), 0750)
	if err := os.WriteFile(filepath.Join(s.groupDir(name), "agent.yml"), []byte(req.Config), 0640); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "saved"})
}
