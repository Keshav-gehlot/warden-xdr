package server

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

const maxBody = 32 << 20

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) agentMux() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/enroll", s.handleEnroll)
	m.HandleFunc("POST /v1/events", s.signed(s.handleEvents))
	m.HandleFunc("POST /v1/control", s.signed(s.handleControl))
	m.HandleFunc("POST /v1/config", s.signed(s.handleConfig))
	m.HandleFunc("POST /v1/inventory", s.signed(s.handleInventory))
	return m
}

func readBody(r *http.Request) ([]byte, error) {
	var rd io.Reader = http.MaxBytesReader(nil, r.Body, maxBody)
	b, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(zr, 8*maxBody))
	}
	return b, nil
}

// trustProxy is set when TLS is terminated by a reverse proxy; only then are
// X-Forwarded-For headers believed.
var trustProxy bool

func clientIP(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		http.Error(w, "bad body", 400)
		return
	}
	var req proto.EnrollRequest
	if json.Unmarshal(body, &req) != nil || !validName.MatchString(req.Name) {
		http.Error(w, "invalid request (name must match "+validName.String()+")", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.cfg.EnrollPass)) != 1 {
		log.Printf("enroll: bad password from %s for %q", clientIP(r), req.Name)
		time.Sleep(time.Second)
		http.Error(w, "invalid enrollment password", 401)
		return
	}
	if old, err := s.st.AgentByName(req.Name); err == nil {
		// Re-enrollment with the same name replaces the old key (like manage_agents -r).
		s.st.DeleteAgent(old.ID)
	}
	id, err := s.st.NextAgentID()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	group := req.Group
	if group == "" || !validName.MatchString(group) {
		group = "default"
	}
	a := &store.Agent{ID: id, Name: req.Name, Key: randHex(32), Group: group, IP: clientIP(r), OS: req.OS,
		Version: req.Version, RegisteredAt: time.Now().Unix()}
	if err := s.st.InsertAgent(a); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("enrolled agent %s (%s) from %s, group %s", a.ID, a.Name, a.IP, group)
	s.enqueue(a, proto.Event{Type: proto.TypeAgent, Timestamp: time.Now(), Location: "warden-manager",
		Data: map[string]string{"event": "enrolled", "agent": a.Name, "ip": a.IP}})
	writeJSON(w, 200, proto.EnrollResponse{AgentID: id, Key: a.Key})
}

type agentHandler func(w http.ResponseWriter, r *http.Request, a *store.Agent, body []byte)

// signed authenticates an agent request with its HMAC key.
func (s *Server) signed(h agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(proto.HeaderAgentID)
		a, err := s.st.GetAgent(id)
		if err != nil {
			http.Error(w, "unknown agent", 401)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		if !proto.Verify(a.Key, id, r.Header.Get(proto.HeaderTimestamp), r.Method, r.URL.Path, raw, r.Header.Get(proto.HeaderSignature), 5*time.Minute) {
			http.Error(w, "bad signature", 401)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		body, err := readBody(r)
		if err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		h(w, r, a, body)
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, a *store.Agent, body []byte) {
	var b proto.EventBatch
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	for _, e := range b.Events {
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		if !s.enqueue(a, e) {
			http.Error(w, "analysis queue full", 503) // agent keeps the batch and retries
			return
		}
	}
	writeJSON(w, 200, map[string]int{"accepted": len(b.Events)})
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request, a *store.Agent, body []byte) {
	var req proto.ControlRequest
	json.Unmarshal(body, &req)
	bundle, err := s.configBundle(a.Group)
	hash := ""
	if err == nil {
		hash = bundle.Hash
	}
	s.st.TouchAgent(a.ID, clientIP(r), req.OS, req.Version, req.ConfigHash)
	cmds, _ := s.st.TakeCommands(a.ID)
	writeJSON(w, 200, proto.ControlResponse{ConfigHash: hash, Commands: cmds})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request, a *store.Agent, body []byte) {
	b, err := s.configBundle(a.Group)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, b)
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request, a *store.Agent, body []byte) {
	var inv proto.Inventory
	if err := json.Unmarshal(body, &inv); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.st.SaveInventory(a.ID, &inv); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	a.OS = inv.OS
	go s.scanVulns(a, &inv)
	writeJSON(w, 200, map[string]int{"packages": len(inv.Packages)})
}
