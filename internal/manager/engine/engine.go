// Package engine is the analysis daemon (the equivalent of wazuh-analysisd):
// pre-decoding → decoding → rule tree evaluation → frequency correlation.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
)

// Event is a pre-decoded event entering the rule engine.
type Event struct {
	AgentID   string
	AgentName string
	Type      string // log, command, syscheck, sca, ...
	Location  string
	FullLog   string
	Timestamp time.Time

	Hostname string
	Program  string
	Message  string
	Decoder  string
	Fields   map[string]string
}

// ---------- decoders ----------

type Decoder struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`     // optional: only decode events of this type
	Program  string            `yaml:"program"`  // regex against syslog program name
	Prematch string            `yaml:"prematch"` // regex against message
	Regex    []string          `yaml:"regex"`    // named-group regexes; every match merges fields
	Static   map[string]string `yaml:"fields"`   // constant fields added on match

	program, prematch *regexp.Regexp
	regex             []*regexp.Regexp
}

// ---------- rules ----------

type ARSpec struct {
	Command string `yaml:"command" json:"command"`
	Timeout int    `yaml:"timeout" json:"timeout"`
	Field   string `yaml:"field" json:"field"` // field passed as the target (default srcip)
}

type Rule struct {
	ID          int                 `yaml:"id" json:"id"`
	Level       int                 `yaml:"level" json:"level"`
	Description string              `yaml:"description" json:"description"`
	Groups      []string            `yaml:"groups" json:"groups"`
	Mitre       []string            `yaml:"mitre" json:"mitre,omitempty"`
	Compliance  map[string][]string `yaml:"compliance" json:"compliance,omitempty"`

	// conditions
	Type      string            `yaml:"type" json:"type,omitempty"`
	DecodedAs string            `yaml:"decoded_as" json:"decoded_as,omitempty"`
	Program   string            `yaml:"program" json:"program,omitempty"`
	Location  string            `yaml:"location" json:"location,omitempty"`
	Match     string            `yaml:"match" json:"match,omitempty"`
	NotMatch  string            `yaml:"not_match" json:"not_match,omitempty"`
	Field     map[string]string `yaml:"field" json:"field,omitempty"`
	IfSID     []int             `yaml:"if_sid" json:"if_sid,omitempty"`
	IfGroup   string            `yaml:"if_group" json:"if_group,omitempty"`

	// correlation
	IfMatchedSID   int      `yaml:"if_matched_sid" json:"if_matched_sid,omitempty"`
	IfMatchedGroup string   `yaml:"if_matched_group" json:"if_matched_group,omitempty"`
	Frequency      int      `yaml:"frequency" json:"frequency,omitempty"`
	Timeframe      int      `yaml:"timeframe" json:"timeframe,omitempty"`
	SameField      []string `yaml:"same_field" json:"same_field,omitempty"`
	Ignore         int      `yaml:"ignore" json:"ignore,omitempty"` // seconds to suppress repeats

	ActiveResponse *ARSpec `yaml:"active_response" json:"active_response,omitempty"`
	File           string  `yaml:"-" json:"file"`

	program, location, match, notMatch *regexp.Regexp
	field                              map[string]*regexp.Regexp
	depth                              int
}

// Result of analysing one event.
type Result struct {
	Rule       *Rule
	Event      *Event
	FiredTimes int
}

type hit struct {
	ts     time.Time
	fields map[string]string
}

type Engine struct {
	mu          sync.RWMutex
	decoders    []*Decoder
	rules       map[int]*Rule
	ordered     []*Rule
	roots       []*Rule
	bySID       map[int][]*Rule
	byGroup     map[string][]*Rule
	freqBySID   map[int][]*Rule
	freqByGroup map[string][]*Rule

	histMu   sync.Mutex
	history  map[string][]hit     // correlation key → recent matches
	lastFire map[string]time.Time // ignore handling
	fired    map[int]int
}

func New() *Engine {
	return &Engine{history: map[string][]hit{}, lastFire: map[string]time.Time{}, fired: map[int]int{}}
}

// Load reads every *.yml in the decoders and rules directories.
func (e *Engine) Load(decoderDir, ruleDir string) error {
	var decs []*Decoder
	files, _ := filepath.Glob(filepath.Join(decoderDir, "*.yml"))
	sort.Strings(files)
	for _, f := range files {
		var ds []*Decoder
		if err := readYAML(f, &ds); err != nil {
			return err
		}
		for _, d := range ds {
			if err := d.compile(); err != nil {
				return fmt.Errorf("%s: decoder %s: %w", f, d.Name, err)
			}
		}
		decs = append(decs, ds...)
	}

	rules := map[int]*Rule{}
	var ordered []*Rule
	files, _ = filepath.Glob(filepath.Join(ruleDir, "*.yml"))
	sort.Strings(files)
	for _, f := range files {
		var rs []*Rule
		if err := readYAML(f, &rs); err != nil {
			return err
		}
		for _, r := range rs {
			if _, dup := rules[r.ID]; dup {
				return fmt.Errorf("%s: duplicate rule id %d", f, r.ID)
			}
			if err := r.compile(); err != nil {
				return fmt.Errorf("%s: rule %d: %w", f, r.ID, err)
			}
			r.File = filepath.Base(f)
			rules[r.ID] = r
			ordered = append(ordered, r)
		}
	}

	bySID, byGroup := map[int][]*Rule{}, map[string][]*Rule{}
	freqBySID, freqByGroup := map[int][]*Rule{}, map[string][]*Rule{}
	var roots []*Rule
	for _, r := range ordered {
		switch {
		case r.IfMatchedSID != 0:
			freqBySID[r.IfMatchedSID] = append(freqBySID[r.IfMatchedSID], r)
		case r.IfMatchedGroup != "":
			freqByGroup[r.IfMatchedGroup] = append(freqByGroup[r.IfMatchedGroup], r)
		case len(r.IfSID) > 0:
			for _, p := range r.IfSID {
				if rules[p] == nil {
					return fmt.Errorf("rule %d: if_sid %d does not exist", r.ID, p)
				}
				bySID[p] = append(bySID[p], r)
			}
		case r.IfGroup != "":
			byGroup[r.IfGroup] = append(byGroup[r.IfGroup], r)
		default:
			roots = append(roots, r)
		}
	}
	e.mu.Lock()
	e.decoders, e.rules, e.ordered, e.roots = decs, rules, ordered, roots
	e.bySID, e.byGroup, e.freqBySID, e.freqByGroup = bySID, byGroup, freqBySID, freqByGroup
	e.mu.Unlock()
	return nil
}

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func compileOpt(s string) (*regexp.Regexp, error) {
	if s == "" {
		return nil, nil
	}
	return regexp.Compile(s)
}

func (d *Decoder) compile() (err error) {
	if d.program, err = compileOpt(d.Program); err != nil {
		return
	}
	if d.prematch, err = compileOpt(d.Prematch); err != nil {
		return
	}
	for _, s := range d.Regex {
		re, err := regexp.Compile(s)
		if err != nil {
			return err
		}
		d.regex = append(d.regex, re)
	}
	return nil
}

func (r *Rule) compile() (err error) {
	if r.program, err = compileOpt(r.Program); err != nil {
		return
	}
	if r.location, err = compileOpt(r.Location); err != nil {
		return
	}
	if r.match, err = compileOpt(r.Match); err != nil {
		return
	}
	if r.notMatch, err = compileOpt(r.NotMatch); err != nil {
		return
	}
	r.field = map[string]*regexp.Regexp{}
	for k, v := range r.Field {
		if r.field[k], err = regexp.Compile(v); err != nil {
			return
		}
	}
	if r.Frequency > 0 && r.Timeframe == 0 {
		r.Timeframe = 60
	}
	return nil
}

// Rules returns a snapshot of loaded rules (for the API).
func (e *Engine) Rules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]*Rule(nil), e.ordered...)
}

func (e *Engine) Rule(id int) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules[id]
}

func (e *Engine) Counts() (int, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.decoders), len(e.rules)
}

// ---------- pre-decoding ----------

var (
	reSyslog3164 = regexp.MustCompile(`^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$`)
	reSyslogISO  = regexp.MustCompile(`^(?:<\d+>\d?\s*)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$`)
)

// PreDecode splits a syslog header (RFC3164 / ISO8601) or flattens JSON.
func PreDecode(ev *Event) {
	if ev.Fields == nil {
		ev.Fields = map[string]string{}
	}
	ev.Message = ev.FullLog
	line := strings.TrimSpace(ev.FullLog)
	if strings.HasPrefix(line, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			flatten("", m, ev.Fields)
			ev.Decoder = "json"
			if p, ok := ev.Fields["program"]; ok {
				ev.Program = p
			}
			return
		}
	}
	for _, re := range []*regexp.Regexp{reSyslog3164, reSyslogISO} {
		if m := re.FindStringSubmatch(line); m != nil {
			ev.Hostname, ev.Program, ev.Message = m[2], m[3], m[5]
			if m[4] != "" {
				ev.Fields["pid"] = m[4]
			}
			return
		}
	}
}

func flatten(prefix string, m map[string]any, out map[string]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			flatten(key, t, out)
		case string:
			out[key] = t
		case float64:
			out[key] = strconv.FormatFloat(t, 'f', -1, 64)
		case nil:
		default:
			b, _ := json.Marshal(t)
			out[key] = string(b)
		}
	}
}

// ---------- decoding ----------

func (e *Engine) decode(ev *Event) {
	if ev.Type != "log" && ev.Type != "command" {
		if ev.Decoder == "" {
			ev.Decoder = ev.Type // syscheck, sca, active_response, ...
		}
		return
	}
	for _, d := range e.decoders {
		if d.Type != "" && d.Type != ev.Type {
			continue
		}
		if d.program != nil && !d.program.MatchString(ev.Program) {
			continue
		}
		if d.program == nil && d.prematch == nil {
			continue
		}
		if d.prematch != nil && !d.prematch.MatchString(ev.Message) {
			continue
		}
		ev.Decoder = d.Name
		for _, re := range d.regex {
			m := re.FindStringSubmatch(ev.Message)
			if m == nil {
				continue
			}
			for i, n := range re.SubexpNames() {
				if n != "" && m[i] != "" {
					ev.Fields[n] = m[i]
				}
			}
		}
		for k, v := range d.Static {
			ev.Fields[k] = v
		}
		return
	}
}

// ---------- rule matching ----------

func (r *Rule) matches(ev *Event) bool {
	if r.Type != "" && r.Type != ev.Type {
		return false
	}
	if r.DecodedAs != "" && r.DecodedAs != ev.Decoder {
		return false
	}
	if r.program != nil && !r.program.MatchString(ev.Program) {
		return false
	}
	if r.location != nil && !r.location.MatchString(ev.Location) {
		return false
	}
	if r.match != nil && !r.match.MatchString(ev.FullLog) {
		return false
	}
	if r.notMatch != nil && r.notMatch.MatchString(ev.FullLog) {
		return false
	}
	for k, re := range r.field {
		v, ok := ev.Fields[k]
		if !ok || !re.MatchString(v) {
			return false
		}
	}
	return true
}

func (e *Engine) children(r *Rule) []*Rule {
	out := e.bySID[r.ID]
	for _, g := range r.Groups {
		out = append(out, e.byGroup[g]...)
	}
	return out
}

func (e *Engine) walk(cands []*Rule, ev *Event, depth int, seen map[int]bool) *Rule {
	if depth > 16 {
		return nil
	}
	for _, r := range cands {
		if seen[r.ID] || !r.matches(ev) {
			continue
		}
		seen[r.ID] = true
		if c := e.walk(e.children(r), ev, depth+1, seen); c != nil {
			return c
		}
		return r
	}
	return nil
}

// Analyze runs one event through decoding and the rule tree. It returns nil if
// no rule matched or the match was suppressed.
func (e *Engine) Analyze(ev *Event) *Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if ev.Fields == nil {
		ev.Fields = map[string]string{}
	}
	e.decode(ev)
	r := e.walk(e.roots, ev, 0, map[int]bool{})
	if r == nil {
		return nil
	}
	r = e.correlate(r, ev)

	e.histMu.Lock()
	defer e.histMu.Unlock()
	if r.Ignore > 0 {
		k := strconv.Itoa(r.ID) + "|" + sameKey(r.SameField, ev.Fields)
		if t, ok := e.lastFire[k]; ok && ev.Timestamp.Sub(t) < time.Duration(r.Ignore)*time.Second {
			return nil // suppressed by "ignore"
		}
		e.lastFire[k] = ev.Timestamp
	}
	e.fired[r.ID]++
	return &Result{Rule: r, Event: ev, FiredTimes: e.fired[r.ID]}
}

func sameKey(fields []string, m map[string]string) string {
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(m[f])
		b.WriteByte('|')
	}
	return b.String()
}

// correlate records the match and escalates to a frequency rule when the
// threshold is reached inside the timeframe. Hits are kept per correlation key:
// "s:<rule id>" for if_matched_sid and "g:<group>" for if_matched_group.
func (e *Engine) correlate(r *Rule, ev *Event) *Rule {
	type cand struct {
		key string
		f   *Rule
	}
	var cands []cand
	for _, f := range e.freqBySID[r.ID] {
		cands = append(cands, cand{"s:" + strconv.Itoa(r.ID), f})
	}
	for _, g := range r.Groups {
		for _, f := range e.freqByGroup[g] {
			cands = append(cands, cand{"g:" + g, f})
		}
	}
	if len(cands) == 0 {
		return r
	}
	e.histMu.Lock()
	defer e.histMu.Unlock()
	fieldsCopy := make(map[string]string, len(ev.Fields))
	for k, v := range ev.Fields {
		fieldsCopy[k] = v
	}
	maxTF := map[string]int{}
	for _, c := range cands {
		if c.f.Timeframe > maxTF[c.key] {
			maxTF[c.key] = c.f.Timeframe
		}
	}
	for key, tf := range maxTF {
		h := append(e.history[key], hit{ts: ev.Timestamp, fields: fieldsCopy})
		cut := ev.Timestamp.Add(-time.Duration(tf) * time.Second)
		i := 0
		for i < len(h) && h[i].ts.Before(cut) {
			i++
		}
		h = h[i:]
		if len(h) > 10000 {
			h = h[len(h)-10000:]
		}
		e.history[key] = h
	}

	sameAs := func(x hit, f *Rule) bool {
		for _, sf := range f.SameField {
			if x.fields[sf] != ev.Fields[sf] {
				return false
			}
		}
		return true
	}
	for _, c := range cands {
		if !c.f.matches(ev) {
			continue
		}
		start := ev.Timestamp.Add(-time.Duration(c.f.Timeframe) * time.Second)
		n := 0
		for _, x := range e.history[c.key] {
			if !x.ts.Before(start) && sameAs(x, c.f) {
				n++
			}
		}
		if n >= c.f.Frequency {
			// consume the counted hits so the next alert needs a fresh burst
			var keep []hit
			for _, x := range e.history[c.key] {
				if x.ts.Before(start) || !sameAs(x, c.f) {
					keep = append(keep, x)
				}
			}
			e.history[c.key] = keep
			ev.Fields["frequency"] = strconv.Itoa(n)
			return c.f
		}
	}
	return r
}
