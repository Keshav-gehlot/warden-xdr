// Package agent implements warden-agent: enrollment, transport and the
// endpoint modules (logcollector, syscheck/FIM, syscollector/inventory, SCA,
// rootcheck and active response).
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
	"github.com/goccy/go-yaml"
)

// LocalConfig is the agent's own bootstrap configuration (agent.yml).
type LocalConfig struct {
	Manager     string `yaml:"manager"`             // host:port of the manager agent service
	EnrollPass  string `yaml:"enrollment_password"` // shared enrollment secret
	Name        string `yaml:"name"`                // defaults to hostname
	Group       string `yaml:"group"`
	StateDir    string `yaml:"state_dir"`
	Fingerprint string `yaml:"manager_fingerprint"` // optional explicit certificate pin
	TLSMode     string `yaml:"manager_tls"`         // "pin" (default) or "system" (public CA, e.g. Render)
	ControlSec  int    `yaml:"control_interval"`    // heartbeat interval (default 10s)
}

func LoadLocalConfig(path string) (*LocalConfig, error) {
	c := &LocalConfig{StateDir: "/var/lib/warden-agent", Group: "default", ControlSec: 10}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
	}
	env := func(k string, p *string) {
		if v := os.Getenv(k); v != "" {
			*p = v
		}
	}
	env("WARDEN_MANAGER", &c.Manager)
	env("WARDEN_ENROLLMENT_PASSWORD", &c.EnrollPass)
	env("WARDEN_AGENT_NAME", &c.Name)
	env("WARDEN_GROUP", &c.Group)
	env("WARDEN_STATE_DIR", &c.StateDir)
	env("WARDEN_MANAGER_FINGERPRINT", &c.Fingerprint)
	env("WARDEN_MANAGER_TLS", &c.TLSMode)
	if c.Name == "" {
		c.Name, _ = os.Hostname()
	}
	if c.ControlSec <= 0 {
		c.ControlSec = 10
	}
	if c.Manager == "" {
		return nil, errors.New("manager address is required (agent.yml 'manager' or WARDEN_MANAGER)")
	}
	return c, nil
}

type state struct {
	AgentID     string `json:"agent_id"`
	Key         string `json:"key"`
	Fingerprint string `json:"manager_fingerprint"`
	Manager     string `json:"manager"`
}

type Agent struct {
	lc     *LocalConfig
	client *Client
	st     state
	bundle atomic.Pointer[proto.ConfigBundle]
	events chan proto.Event

	trigFIM, trigInv, trigSCA, trigRoot chan struct{}
	restart                             chan struct{}

	arMu     sync.Mutex
	arTimers map[string]*time.Timer
}

func New(lc *LocalConfig) *Agent {
	os.MkdirAll(lc.StateDir, 0700)
	return &Agent{lc: lc, events: make(chan proto.Event, 50000),
		trigFIM: make(chan struct{}, 1), trigInv: make(chan struct{}, 1), trigSCA: make(chan struct{}, 1),
		trigRoot: make(chan struct{}, 1), restart: make(chan struct{}, 1), arTimers: map[string]*time.Timer{}}
}

func (a *Agent) statePath() string { return filepath.Join(a.lc.StateDir, "client.keys.json") }

func (a *Agent) loadState() bool {
	b, err := os.ReadFile(a.statePath())
	if err != nil {
		return false
	}
	return json.Unmarshal(b, &a.st) == nil && a.st.AgentID != "" && a.st.Manager == a.lc.Manager
}

func (a *Agent) saveState() error {
	b, _ := json.MarshalIndent(a.st, "", "  ")
	return os.WriteFile(a.statePath(), b, 0600)
}

func (a *Agent) enroll() error {
	fp := a.lc.Fingerprint
	a.client = NewClient(a.lc.Manager, fp, a.lc.TLSMode)
	resp, err := a.client.Enroll(proto.EnrollRequest{Name: a.lc.Name, Password: a.lc.EnrollPass, Group: a.lc.Group,
		OS: OSInfo(), Version: proto.Version})
	if err != nil {
		return err
	}
	a.st = state{AgentID: resp.AgentID, Key: resp.Key, Fingerprint: a.client.fingerprint, Manager: a.lc.Manager}
	log.Printf("enrolled as agent %s; pinned manager certificate %s", resp.AgentID, a.st.Fingerprint)
	return a.saveState()
}

// Emit queues an event for delivery. It never blocks: if the buffer is full
// the event is dropped and counted (like Wazuh's agent buffer flood control).
var dropped atomic.Int64

func (a *Agent) Emit(e proto.Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	select {
	case a.events <- e:
	default:
		if dropped.Add(1)%1000 == 1 {
			log.Printf("event buffer full, dropping events (%d so far)", dropped.Load())
		}
	}
}

func (a *Agent) Config() *proto.AgentConfig {
	if b := a.bundle.Load(); b != nil {
		return &b.Config
	}
	return defaultConfig()
}

func defaultConfig() *proto.AgentConfig {
	c := &proto.AgentConfig{}
	c.LogFiles = []proto.LogFile{{Path: "/var/log/auth.log", Format: "syslog"}, {Path: "/var/log/secure", Format: "syslog"}, {Path: "/var/log/syslog", Format: "syslog"}}
	c.FIM = proto.FIMConfig{IntervalSec: 300, Directories: []string{"/etc", "/usr/bin", "/usr/sbin"}, MaxFileMB: 50}
	c.Inventory.IntervalSec = 3600
	c.SCA.IntervalSec = 43200
	c.Rootcheck.IntervalSec = 43200
	c.ActiveResponse.Enabled = true
	return c
}

// Run enrolls if needed, then runs every module until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if a.loadState() {
		a.client = NewClient(a.lc.Manager, a.st.Fingerprint, a.lc.TLSMode)
	} else {
		for {
			err := a.enroll()
			if err == nil {
				break
			}
			log.Printf("enrollment failed: %v (retrying in 15s)", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(15 * time.Second):
			}
		}
	}
	a.client.SetIdentity(a.st.AgentID, a.st.Key)
	log.Printf("agent %s (%s) connecting to %s", a.st.AgentID, a.lc.Name, a.lc.Manager)

	a.Emit(proto.Event{Type: proto.TypeAgent, Location: "warden-agent", Data: map[string]string{"event": "started", "version": proto.Version}})
	a.control(ctx) // first heartbeat fetches the group config before modules start

	var wg sync.WaitGroup
	for _, f := range []func(context.Context){a.sender, a.controlLoop, a.logcollector, a.commandMonitor, a.fimLoop, a.inventoryLoop, a.scaLoop, a.rootcheckLoop} {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(f)
	}
	select {
	case <-ctx.Done():
	case <-a.restart:
	}
	// best-effort goodbye
	a.client.Post("/v1/events", proto.EventBatch{Events: []proto.Event{{Type: proto.TypeAgent, Timestamp: time.Now(), Location: "warden-agent",
		Data: map[string]string{"event": "stopped"}}}}, nil)
	return ctx.Err()
}

// RestartRequested reports whether Run returned because of a restart command.
func (a *Agent) RestartRequested() <-chan struct{} { return a.restart }

// sender batches events and ships them, keeping a failed batch for retry.
func (a *Agent) sender(ctx context.Context) {
	var batch []proto.Event
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	backoff := time.Second
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := a.client.Post("/v1/events", proto.EventBatch{Events: batch}, nil); err != nil {
			log.Printf("send %d events: %v (retry in %s)", len(batch), err, backoff)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			return
		}
		backoff = time.Second
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-a.events:
			if len(batch) < 20000 {
				batch = append(batch, e)
			}
			if len(batch) >= 500 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (a *Agent) controlLoop(ctx context.Context) {
	t := time.NewTicker(time.Duration(a.lc.ControlSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.control(ctx)
		}
	}
}

func (a *Agent) control(ctx context.Context) {
	hash := ""
	if b := a.bundle.Load(); b != nil {
		hash = b.Hash
	}
	var resp proto.ControlResponse
	if err := a.client.Post("/v1/control", proto.ControlRequest{Version: proto.Version, ConfigHash: hash, OS: OSInfo()}, &resp); err != nil {
		log.Printf("control: %v", err)
		if errors.Is(err, ErrUnauthorized) {
			log.Printf("agent key rejected by manager; re-enrolling")
			os.Remove(a.statePath())
			select {
			case a.restart <- struct{}{}:
			default:
			}
		}
		return
	}
	if resp.ConfigHash != "" && resp.ConfigHash != hash {
		var b proto.ConfigBundle
		if err := a.client.Post("/v1/config", struct{}{}, &b); err != nil {
			log.Printf("config: %v", err)
		} else {
			first := a.bundle.Load() == nil
			a.bundle.Store(&b)
			log.Printf("applied group '%s' configuration (hash %s, %d SCA policies)", b.Group, b.Hash, len(b.Policies))
			if !first {
				trigger(a.trigSCA)
			}
		}
	}
	for _, c := range resp.Commands {
		go a.execute(c)
	}
}

func trigger(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// interval returns the configured interval or a default, never below min.
func interval(sec, def, min int) time.Duration {
	if sec <= 0 {
		sec = def
	}
	if sec < min {
		sec = min
	}
	return time.Duration(sec) * time.Second
}

// periodic runs fn immediately (after delay) and then on every interval or trigger.
func periodic(ctx context.Context, delay time.Duration, every func() time.Duration, trig chan struct{}, fn func()) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	for {
		fn()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every()):
		case <-trig:
		}
	}
}
