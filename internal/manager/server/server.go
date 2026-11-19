// Package server wires the manager together: agent protocol, analysis
// pipeline, active response, vulnerability detector, REST API and dashboard.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/engine"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/vuln"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
	"github.com/goccy/go-yaml"
)

type queued struct {
	agent *store.Agent
	ev    proto.Event
}

type Server struct {
	cfg     *Config
	st      *store.Store
	eng     *engine.Engine
	web     fs.FS
	cert    tls.Certificate
	certFP  string
	queue   chan queued
	started time.Time

	sessMu   sync.Mutex
	sessions map[string]time.Time

	subMu sync.Mutex
	subs  map[chan []byte]struct{}

	arMu     sync.Mutex
	arActive map[string]time.Time // agent|command|target → expiry (dedupe)

	cmdMu   sync.Mutex
	lastCmd map[string]string // agent|alias → last command output

	statusMu   sync.Mutex
	lastStatus map[string]string

	metricsMu sync.Mutex
	evCount   int64
	alCount   int64
}

func New(cfg *Config, web fs.FS) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0750); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "warden.db"))
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, st: st, eng: engine.New(), web: web, queue: make(chan queued, 20000), started: time.Now(),
		sessions: map[string]time.Time{}, subs: map[chan []byte]struct{}{}, arActive: map[string]time.Time{},
		lastCmd: map[string]string{}, lastStatus: map[string]string{}}
	trustProxy = cfg.TLSOff
	if err := s.reloadRules(); err != nil {
		return nil, err
	}
	s.cert, s.certFP, err = loadOrCreateCert(cfg.TLSCert, cfg.TLSKey, cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if err := s.ensureAdmin(); err != nil {
		return nil, err
	}
	if s.cfg.EnrollPass == "" {
		s.cfg.EnrollPass = s.secretFile("enrollment-password.txt")
	}
	if len(cfg.Vuln.Feeds) > 0 {
		if n, err := vuln.LoadJSONFeeds(st, cfg.Vuln.Feeds...); err != nil {
			log.Printf("vuln feeds: %v", err)
		} else {
			log.Printf("vuln feeds loaded: %v", n)
		}
	}
	return s, nil
}

// secretFile returns the content of a 0600 file in the data dir, creating it
// with a random value on first use.
func (s *Server) secretFile(name string) string {
	p := filepath.Join(s.cfg.DataDir, name)
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b))
	}
	v := randHex(12)
	os.WriteFile(p, []byte(v+"\n"), 0600)
	log.Printf("generated %s (stored in %s)", strings.TrimSuffix(name, ".txt"), p)
	return v
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) reloadRules() error {
	err := s.eng.Load(filepath.Join(s.cfg.RulesetDir, "decoders"), filepath.Join(s.cfg.RulesetDir, "rules"))
	if err == nil {
		d, r := s.eng.Counts()
		log.Printf("ruleset loaded: %d decoders, %d rules", d, r)
	}
	return err
}

// Run starts every listener and background loop; it blocks until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	go s.analysisLoop(ctx)
	go s.housekeeping(ctx)
	go s.vulnLoop(ctx)
	if s.cfg.ListenSyslog != "" {
		go s.syslogLoop(ctx)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
	var servers []*http.Server
	if s.cfg.SinglePort != "" {
		mux := http.NewServeMux()
		mux.Handle("/v1/", s.agentMux())
		mux.Handle("/", s.apiMux())
		servers = append(servers, &http.Server{Addr: s.cfg.SinglePort, Handler: mux, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second})
	} else {
		servers = append(servers,
			&http.Server{Addr: s.cfg.ListenAgents, Handler: s.agentMux(), TLSConfig: tlsCfg,
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second},
			&http.Server{Addr: s.cfg.ListenAPI, Handler: s.apiMux(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second})
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) {
			if s.cfg.TLSOff {
				errc <- srv.ListenAndServe()
			} else {
				errc <- srv.ListenAndServeTLS("", "")
			}
		}(srv)
	}
	if s.cfg.SinglePort != "" {
		log.Printf("agents + dashboard on %s (tls=%v), cert fingerprint %s", s.cfg.SinglePort, !s.cfg.TLSOff, s.certFP)
	} else {
		log.Printf("agent service on %s, dashboard/API on https://%s, cert fingerprint %s", s.cfg.ListenAgents, s.cfg.ListenAPI, s.certFP)
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(sctx)
	}
	return s.st.DB.Close()
}

// ---------- group configuration ----------

func (s *Server) groupDir(group string) string {
	return filepath.Join(s.cfg.RulesetDir, "shared", filepath.Base(group))
}

func (s *Server) configBundle(group string) (*proto.ConfigBundle, error) {
	raw, err := os.ReadFile(filepath.Join(s.groupDir(group), "agent.yml"))
	if err != nil && group != "default" {
		raw, err = os.ReadFile(filepath.Join(s.groupDir("default"), "agent.yml"))
	}
	if err != nil {
		return nil, err
	}
	b := &proto.ConfigBundle{Group: group}
	if err := yaml.Unmarshal(raw, &b.Config); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(raw)
	for _, name := range b.Config.SCA.Policies {
		praw, err := os.ReadFile(filepath.Join(s.cfg.RulesetDir, "sca", filepath.Base(name)))
		if err != nil {
			log.Printf("sca policy %s: %v", name, err)
			continue
		}
		var p proto.SCAPolicy
		if err := yaml.Unmarshal(praw, &p); err != nil {
			log.Printf("sca policy %s: %v", name, err)
			continue
		}
		h.Write(praw)
		b.Policies = append(b.Policies, p)
	}
	b.Hash = hex.EncodeToString(h.Sum(nil))[:16]
	return b, nil
}

// ---------- background loops ----------

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		agents, _ := s.st.ListAgents()
		for _, a := range agents {
			s.statusMu.Lock()
			prev := s.lastStatus[a.ID]
			s.lastStatus[a.ID] = a.Status
			s.statusMu.Unlock()
			if prev == "active" && a.Status == "disconnected" {
				s.enqueue(a, proto.Event{Type: proto.TypeAgent, Timestamp: time.Now(), Location: "warden-manager",
					Data: map[string]string{"event": "disconnected", "agent": a.Name}})
			}
		}
		s.sessMu.Lock()
		for k, exp := range s.sessions {
			if time.Now().After(exp) {
				delete(s.sessions, k)
			}
		}
		s.sessMu.Unlock()
		s.arMu.Lock()
		for k, exp := range s.arActive {
			if time.Now().After(exp) {
				delete(s.arActive, k)
			}
		}
		s.arMu.Unlock()
		if time.Since(last) > time.Hour {
			s.st.Retention(s.cfg.Retention.AlertDays, s.cfg.Retention.EventDays)
			last = time.Now()
		}
	}
}

// syslogLoop receives syslog over UDP from agentless devices (firewalls,
// routers, switches). Events are attributed to the manager (agent 000).
func (s *Server) syslogLoop(ctx context.Context) {
	pc, err := net.ListenPacket("udp", s.cfg.ListenSyslog)
	if err != nil {
		log.Printf("syslog listener: %v", err)
		return
	}
	go func() { <-ctx.Done(); pc.Close() }()
	log.Printf("syslog receiver on udp %s", s.cfg.ListenSyslog)
	mgr := &store.Agent{ID: "000", Name: "warden-manager"}
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(addr.String())
		for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\r\n\x00"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				s.enqueue(mgr, proto.Event{Type: proto.TypeLog, Timestamp: time.Now(), Location: "syslog:" + host, Log: line})
			}
		}
	}
}

func (s *Server) vulnLoop(ctx context.Context) {
	if s.cfg.Vuln.OSVAutoSync {
		s.syncOSV(nil)
	}
	h := s.cfg.Vuln.IntervalHours
	if h <= 0 {
		h = 6
	}
	t := time.NewTicker(time.Duration(h) * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.cfg.Vuln.OSVAutoSync {
			s.syncOSV(nil)
		}
		agents, _ := s.st.ListAgents()
		for _, a := range agents {
			if inv, err := s.st.GetInventory(a.ID); err == nil {
				s.scanVulns(a, inv)
			}
		}
	}
}

// syncOSV downloads OSV advisories for the given ecosystems (or for every
// ecosystem used by enrolled agents plus configured extras).
func (s *Server) syncOSV(ecos []string) (map[string]int, error) {
	if len(ecos) == 0 {
		set := map[string]bool{}
		for _, e := range s.cfg.Vuln.OSVEcosystems {
			set[e] = true
		}
		agents, _ := s.st.ListAgents()
		for _, a := range agents {
			if e := vuln.Ecosystem(a.OS); e != "" {
				set[e] = true
			}
		}
		for e := range set {
			ecos = append(ecos, e)
		}
	}
	// OSV publishes one zip per base ecosystem ("Debian", "Ubuntu", "Alpine").
	byBase := map[string][]string{}
	for _, e := range ecos {
		base := strings.SplitN(e, ":", 2)[0]
		byBase[base] = append(byBase[base], e)
	}
	total := map[string]int{}
	var lastErr error
	for base, list := range byBase {
		log.Printf("vulnerability feed: syncing OSV %s %v", base, list)
		n, err := vuln.SyncOSV(s.st, vuln.OSVZipURL(base), list)
		if err != nil {
			log.Printf("vulnerability feed %s: %v", base, err)
			lastErr = err
			continue
		}
		for k, v := range n {
			total[k] = v
		}
	}
	return total, lastErr
}

func (s *Server) scanVulns(a *store.Agent, inv *proto.Inventory) {
	vs, err := vuln.Match(s.st, inv)
	if err != nil {
		log.Printf("vuln match %s: %v", a.ID, err)
		return
	}
	fresh, err := s.st.ReplaceVulns(a.ID, vs)
	if err != nil {
		log.Printf("vuln store %s: %v", a.ID, err)
		return
	}
	for _, v := range fresh {
		s.enqueue(a, proto.Event{Type: "vulnerability-detector", Timestamp: time.Now(), Location: "vulnerability-detector",
			Log: fmt.Sprintf("%s affects %s %s (fixed in %s)", v.CVE, v.Package, v.Version, orDash(v.Fixed)),
			Data: map[string]string{"cve": v.CVE, "package": v.Package, "version": v.Version, "fixed": v.Fixed,
				"severity": v.Severity, "score": fmt.Sprintf("%.1f", v.Score), "summary": v.Summary}})
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
