// Package store is the manager's state database (the equivalent of wazuh-db),
// backed by a single SQLite file in WAL mode.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct{ DB *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, name TEXT UNIQUE, key TEXT, grp TEXT DEFAULT 'default',
  ip TEXT, os TEXT, version TEXT, registered_at INTEGER, last_seen INTEGER, config_hash TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, agent_id TEXT, type TEXT,
  location TEXT, log TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, agent_id TEXT, agent_name TEXT,
  rule_id INTEGER, level INTEGER, description TEXT, groups TEXT, mitre TEXT, compliance TEXT,
  decoder TEXT, location TEXT, full_log TEXT, fields TEXT, srcip TEXT, firedtimes INTEGER
);
CREATE INDEX IF NOT EXISTS al_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS al_agent ON alerts(agent_id, ts);
CREATE INDEX IF NOT EXISTS al_rule ON alerts(rule_id);
CREATE TABLE IF NOT EXISTS fim_files (
  agent_id TEXT, path TEXT, sha256 TEXT, size INTEGER, mode TEXT, uid TEXT, gid TEXT,
  mtime INTEGER, last_event TEXT, updated_at INTEGER, PRIMARY KEY(agent_id, path)
);
CREATE TABLE IF NOT EXISTS inventory (agent_id TEXT PRIMARY KEY, data TEXT, scanned_at INTEGER);
CREATE TABLE IF NOT EXISTS sca_results (
  agent_id TEXT, policy_id TEXT, policy_name TEXT, check_id INTEGER, title TEXT, result TEXT,
  reason TEXT, remediation TEXT, compliance TEXT, updated_at INTEGER,
  PRIMARY KEY(agent_id, policy_id, check_id)
);
CREATE TABLE IF NOT EXISTS vulns (
  agent_id TEXT, cve TEXT, package TEXT, version TEXT, fixed TEXT, severity TEXT, score REAL,
  summary TEXT, detected_at INTEGER, PRIMARY KEY(agent_id, cve, package)
);
CREATE TABLE IF NOT EXISTS vuln_feed (
  cve TEXT, ecosystem TEXT, package TEXT, introduced TEXT, fixed TEXT, severity TEXT,
  score REAL, summary TEXT, PRIMARY KEY(cve, ecosystem, package, introduced)
);
CREATE INDEX IF NOT EXISTS vf_pkg ON vuln_feed(ecosystem, package);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, name TEXT, args TEXT, timeout INTEGER,
  status TEXT, origin TEXT, created_at INTEGER, sent_at INTEGER, result TEXT
);
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, pass_hash TEXT, salt TEXT);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; SQLite serialises anyway and this avoids SQLITE_BUSY
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{DB: db}, nil
}

func j(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---------- agents ----------

type Agent struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Key          string       `json:"-"`
	Group        string       `json:"group"`
	IP           string       `json:"ip"`
	OS           proto.OSInfo `json:"os"`
	Version      string       `json:"version"`
	RegisteredAt int64        `json:"registered_at"`
	LastSeen     int64        `json:"last_seen"`
	ConfigHash   string       `json:"config_hash"`
	Status       string       `json:"status"`
}

func (s *Store) NextAgentID() (string, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	for {
		n++
		id := fmt.Sprintf("%03d", n)
		var x int
		if s.DB.QueryRow(`SELECT 1 FROM agents WHERE id=?`, id).Scan(&x) == sql.ErrNoRows {
			return id, err
		}
	}
}

func (s *Store) InsertAgent(a *Agent) error {
	_, err := s.DB.Exec(`INSERT INTO agents(id,name,key,grp,ip,os,version,registered_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Key, a.Group, a.IP, j(a.OS), a.Version, a.RegisteredAt, a.LastSeen)
	return err
}

func (s *Store) DeleteAgent(id string) error {
	for _, t := range []string{"agents WHERE id", "fim_files WHERE agent_id", "inventory WHERE agent_id",
		"sca_results WHERE agent_id", "vulns WHERE agent_id", "commands WHERE agent_id"} {
		if _, err := s.DB.Exec(`DELETE FROM `+t+`=?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) TouchAgent(id, ip string, os proto.OSInfo, version, cfgHash string) error {
	_, err := s.DB.Exec(`UPDATE agents SET last_seen=?, ip=?, os=?, version=?, config_hash=? WHERE id=?`,
		time.Now().Unix(), ip, j(os), version, cfgHash, id)
	return err
}

func (s *Store) SetAgentGroup(id, group string) error {
	_, err := s.DB.Exec(`UPDATE agents SET grp=? WHERE id=?`, group, id)
	return err
}

const agentCols = `id,name,key,grp,COALESCE(ip,''),COALESCE(os,'{}'),COALESCE(version,''),registered_at,COALESCE(last_seen,0),COALESCE(config_hash,'')`

func scanAgent(r interface{ Scan(...any) error }) (*Agent, error) {
	a := &Agent{}
	var osj string
	if err := r.Scan(&a.ID, &a.Name, &a.Key, &a.Group, &a.IP, &osj, &a.Version, &a.RegisteredAt, &a.LastSeen, &a.ConfigHash); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(osj), &a.OS)
	switch {
	case a.LastSeen == 0:
		a.Status = "never_connected"
	case time.Since(time.Unix(a.LastSeen, 0)) > 60*time.Second:
		a.Status = "disconnected"
	default:
		a.Status = "active"
	}
	return a, nil
}

func (s *Store) GetAgent(id string) (*Agent, error) {
	return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id=?`, id))
}

func (s *Store) AgentByName(name string) (*Agent, error) {
	return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents WHERE name=?`, name))
}

func (s *Store) ListAgents() ([]*Agent, error) {
	rows, err := s.DB.Query(`SELECT ` + agentCols + ` FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// ---------- events / alerts ----------

func (s *Store) ArchiveEvent(agentID string, e proto.Event) error {
	_, err := s.DB.Exec(`INSERT INTO events(ts,agent_id,type,location,log,data) VALUES(?,?,?,?,?,?)`,
		e.Timestamp.Unix(), agentID, e.Type, e.Location, e.Log, j(e.Data))
	return err
}

type Alert struct {
	ID          int64               `json:"id"`
	Timestamp   int64               `json:"timestamp"`
	AgentID     string              `json:"agent_id"`
	AgentName   string              `json:"agent_name"`
	RuleID      int                 `json:"rule_id"`
	Level       int                 `json:"level"`
	Description string              `json:"description"`
	Groups      []string            `json:"groups"`
	Mitre       []string            `json:"mitre"`
	Compliance  map[string][]string `json:"compliance"`
	Decoder     string              `json:"decoder"`
	Location    string              `json:"location"`
	FullLog     string              `json:"full_log"`
	Fields      map[string]string   `json:"fields"`
	SrcIP       string              `json:"srcip"`
	FiredTimes  int                 `json:"firedtimes"`
}

func (s *Store) InsertAlert(a *Alert) error {
	res, err := s.DB.Exec(`INSERT INTO alerts(ts,agent_id,agent_name,rule_id,level,description,groups,mitre,compliance,decoder,location,full_log,fields,srcip,firedtimes)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.Timestamp, a.AgentID, a.AgentName, a.RuleID, a.Level, a.Description, j(a.Groups), j(a.Mitre), j(a.Compliance),
		a.Decoder, a.Location, a.FullLog, j(a.Fields), a.SrcIP, a.FiredTimes)
	if err == nil {
		a.ID, _ = res.LastInsertId()
	}
	return err
}

type AlertQuery struct {
	AgentID  string
	MinLevel int
	RuleID   int
	Group    string
	Mitre    string
	Search   string
	Since    int64
	Limit    int
	Offset   int
}

func (s *Store) QueryAlerts(q AlertQuery) ([]Alert, int, error) {
	var where []string
	var args []any
	add := func(c string, v any) { where = append(where, c); args = append(args, v) }
	if q.AgentID != "" {
		add("agent_id=?", q.AgentID)
	}
	if q.MinLevel > 0 {
		add("level>=?", q.MinLevel)
	}
	if q.RuleID > 0 {
		add("rule_id=?", q.RuleID)
	}
	if q.Group != "" {
		add("groups LIKE ?", `%"`+q.Group+`"%`)
	}
	if q.Mitre != "" {
		add("mitre LIKE ?", `%"`+q.Mitre+`%`)
	}
	if q.Since > 0 {
		add("ts>=?", q.Since)
	}
	if q.Search != "" {
		where = append(where, "(full_log LIKE ? OR description LIKE ? OR srcip LIKE ?)")
		p := "%" + q.Search + "%"
		args = append(args, p, p, p)
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM alerts`+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	rows, err := s.DB.Query(`SELECT id,ts,agent_id,agent_name,rule_id,level,description,groups,mitre,compliance,decoder,location,full_log,fields,COALESCE(srcip,''),firedtimes
		FROM alerts`+w+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var g, m, c, f string
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.AgentID, &a.AgentName, &a.RuleID, &a.Level, &a.Description, &g, &m, &c, &a.Decoder, &a.Location, &a.FullLog, &f, &a.SrcIP, &a.FiredTimes); err != nil {
			return nil, 0, err
		}
		json.Unmarshal([]byte(g), &a.Groups)
		json.Unmarshal([]byte(m), &a.Mitre)
		json.Unmarshal([]byte(c), &a.Compliance)
		json.Unmarshal([]byte(f), &a.Fields)
		out = append(out, a)
	}
	return out, total, nil
}

// Stats returns aggregate numbers for the overview page.
func (s *Store) Stats(since int64) (map[string]any, error) {
	out := map[string]any{}
	var total, high int
	s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(level>=12),0) FROM alerts WHERE ts>=?`, since).Scan(&total, &high)
	out["alerts"], out["high"] = total, high
	var auth int
	s.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE ts>=? AND groups LIKE '%authentication_fail%'`, since).Scan(&auth)
	out["auth_failures"] = auth

	kv := func(q string, args ...any) []map[string]any {
		rows, err := s.DB.Query(q, args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		var r []map[string]any
		for rows.Next() {
			var k string
			var v int
			var d sql.NullString
			if err := rows.Scan(&k, &d, &v); err == nil {
				r = append(r, map[string]any{"key": k, "label": d.String, "count": v})
			}
		}
		return r
	}
	out["by_level"] = kv(`SELECT CAST(level AS TEXT), '', COUNT(*) FROM alerts WHERE ts>=? GROUP BY level ORDER BY level`, since)
	out["top_rules"] = kv(`SELECT CAST(rule_id AS TEXT), MAX(description), COUNT(*) c FROM alerts WHERE ts>=? GROUP BY rule_id ORDER BY c DESC LIMIT 10`, since)
	out["top_agents"] = kv(`SELECT agent_id, MAX(agent_name), COUNT(*) c FROM alerts WHERE ts>=? GROUP BY agent_id ORDER BY c DESC LIMIT 10`, since)
	out["top_srcip"] = kv(`SELECT srcip, '', COUNT(*) c FROM alerts WHERE ts>=? AND srcip<>'' GROUP BY srcip ORDER BY c DESC LIMIT 10`, since)
	// hourly histogram
	out["timeline"] = kv(`SELECT CAST((ts/3600)*3600 AS TEXT), '', COUNT(*) FROM alerts WHERE ts>=? GROUP BY ts/3600 ORDER BY ts/3600`, since)
	// MITRE technique counts (mitre is a JSON array)
	out["mitre"] = kv(`SELECT je.value, '', COUNT(*) c FROM alerts, json_each(alerts.mitre) je WHERE ts>=? GROUP BY je.value ORDER BY c DESC`, since)
	var vulnCrit, vulnTotal, scaFail, scaPass int
	s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(severity IN ('Critical','High')),0) FROM vulns`).Scan(&vulnTotal, &vulnCrit)
	s.DB.QueryRow(`SELECT COALESCE(SUM(result='failed'),0), COALESCE(SUM(result='passed'),0) FROM sca_results`).Scan(&scaFail, &scaPass)
	out["vulns"], out["vulns_high"], out["sca_failed"], out["sca_passed"] = vulnTotal, vulnCrit, scaFail, scaPass
	return out, nil
}

// Retention deletes alerts/events older than the given number of days.
func (s *Store) Retention(alertDays, eventDays int) {
	now := time.Now()
	s.DB.Exec(`DELETE FROM alerts WHERE ts<?`, now.AddDate(0, 0, -alertDays).Unix())
	s.DB.Exec(`DELETE FROM events WHERE ts<?`, now.AddDate(0, 0, -eventDays).Unix())
}

// ---------- FIM ----------

type FIMFile struct {
	AgentID   string `json:"agent_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Mode      string `json:"mode"`
	UID       string `json:"uid"`
	GID       string `json:"gid"`
	MTime     int64  `json:"mtime"`
	LastEvent string `json:"last_event"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *Store) UpsertFIM(f FIMFile) error {
	if f.LastEvent == "deleted" {
		_, err := s.DB.Exec(`UPDATE fim_files SET last_event='deleted', updated_at=? WHERE agent_id=? AND path=?`, f.UpdatedAt, f.AgentID, f.Path)
		return err
	}
	_, err := s.DB.Exec(`INSERT INTO fim_files VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id,path) DO UPDATE SET sha256=excluded.sha256,size=excluded.size,mode=excluded.mode,
		uid=excluded.uid,gid=excluded.gid,mtime=excluded.mtime,last_event=excluded.last_event,updated_at=excluded.updated_at`,
		f.AgentID, f.Path, f.SHA256, f.Size, f.Mode, f.UID, f.GID, f.MTime, f.LastEvent, f.UpdatedAt)
	return err
}

func (s *Store) ListFIM(agentID, search string, limit int) ([]FIMFile, error) {
	if limit <= 0 {
		limit = 500
	}
	q := `SELECT agent_id,path,sha256,size,mode,uid,gid,mtime,last_event,updated_at FROM fim_files WHERE 1=1`
	var args []any
	if agentID != "" {
		q += ` AND agent_id=?`
		args = append(args, agentID)
	}
	if search != "" {
		q += ` AND path LIKE ?`
		args = append(args, "%"+search+"%")
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	rows, err := s.DB.Query(q, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FIMFile
	for rows.Next() {
		var f FIMFile
		rows.Scan(&f.AgentID, &f.Path, &f.SHA256, &f.Size, &f.Mode, &f.UID, &f.GID, &f.MTime, &f.LastEvent, &f.UpdatedAt)
		out = append(out, f)
	}
	return out, nil
}

// ---------- inventory ----------

func (s *Store) SaveInventory(agentID string, inv *proto.Inventory) error {
	_, err := s.DB.Exec(`INSERT INTO inventory VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET data=excluded.data, scanned_at=excluded.scanned_at`,
		agentID, j(inv), inv.ScannedAt.Unix())
	return err
}

func (s *Store) GetInventory(agentID string) (*proto.Inventory, error) {
	var d string
	if err := s.DB.QueryRow(`SELECT data FROM inventory WHERE agent_id=?`, agentID).Scan(&d); err != nil {
		return nil, err
	}
	inv := &proto.Inventory{}
	return inv, json.Unmarshal([]byte(d), inv)
}

// ---------- SCA ----------

type SCAResult struct {
	AgentID     string              `json:"agent_id"`
	PolicyID    string              `json:"policy_id"`
	PolicyName  string              `json:"policy_name"`
	CheckID     int                 `json:"check_id"`
	Title       string              `json:"title"`
	Result      string              `json:"result"`
	Reason      string              `json:"reason"`
	Remediation string              `json:"remediation"`
	Compliance  map[string][]string `json:"compliance"`
	UpdatedAt   int64               `json:"updated_at"`
}

// UpsertSCA stores a result and returns the previous result ("" if new).
func (s *Store) UpsertSCA(r SCAResult) (string, error) {
	var prev string
	s.DB.QueryRow(`SELECT result FROM sca_results WHERE agent_id=? AND policy_id=? AND check_id=?`, r.AgentID, r.PolicyID, r.CheckID).Scan(&prev)
	_, err := s.DB.Exec(`INSERT INTO sca_results VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id,policy_id,check_id) DO UPDATE SET title=excluded.title,result=excluded.result,reason=excluded.reason,
		remediation=excluded.remediation,compliance=excluded.compliance,updated_at=excluded.updated_at,policy_name=excluded.policy_name`,
		r.AgentID, r.PolicyID, r.PolicyName, r.CheckID, r.Title, r.Result, r.Reason, r.Remediation, j(r.Compliance), r.UpdatedAt)
	return prev, err
}

func (s *Store) ListSCA(agentID string) ([]SCAResult, error) {
	q := `SELECT agent_id,policy_id,policy_name,check_id,title,result,reason,remediation,compliance,updated_at FROM sca_results`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id=?`
		args = append(args, agentID)
	}
	rows, err := s.DB.Query(q+` ORDER BY agent_id, policy_id, check_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCAResult
	for rows.Next() {
		var r SCAResult
		var c string
		rows.Scan(&r.AgentID, &r.PolicyID, &r.PolicyName, &r.CheckID, &r.Title, &r.Result, &r.Reason, &r.Remediation, &c, &r.UpdatedAt)
		json.Unmarshal([]byte(c), &r.Compliance)
		out = append(out, r)
	}
	return out, nil
}

// ---------- vulnerabilities ----------

type Vuln struct {
	AgentID    string  `json:"agent_id"`
	CVE        string  `json:"cve"`
	Package    string  `json:"package"`
	Version    string  `json:"version"`
	Fixed      string  `json:"fixed"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	Summary    string  `json:"summary"`
	DetectedAt int64   `json:"detected_at"`
}

type FeedEntry struct {
	CVE, Ecosystem, Package, Introduced, Fixed, Severity, Summary string
	Score                                                         float64
}

func (s *Store) ReplaceFeed(ecosystem string, entries []FeedEntry) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`DELETE FROM vuln_feed WHERE ecosystem=?`, ecosystem)
	st, err := tx.Prepare(`INSERT OR REPLACE INTO vuln_feed VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, e := range entries {
		st.Exec(e.CVE, e.Ecosystem, e.Package, e.Introduced, e.Fixed, e.Severity, e.Score, e.Summary)
	}
	st.Close()
	return tx.Commit()
}

func (s *Store) FeedFor(ecosystem, pkg string) ([]FeedEntry, error) {
	rows, err := s.DB.Query(`SELECT cve,ecosystem,package,introduced,fixed,severity,score,summary FROM vuln_feed WHERE ecosystem=? AND package=?`, ecosystem, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedEntry
	for rows.Next() {
		var e FeedEntry
		rows.Scan(&e.CVE, &e.Ecosystem, &e.Package, &e.Introduced, &e.Fixed, &e.Severity, &e.Score, &e.Summary)
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) FeedStats() map[string]int {
	out := map[string]int{}
	rows, err := s.DB.Query(`SELECT ecosystem, COUNT(*) FROM vuln_feed GROUP BY ecosystem`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int
		rows.Scan(&k, &v)
		out[k] = v
	}
	return out
}

// ReplaceVulns swaps the agent's vulnerability list and returns the CVE/package
// pairs that are new since the previous scan.
func (s *Store) ReplaceVulns(agentID string, vs []Vuln) ([]Vuln, error) {
	old := map[string]bool{}
	rows, err := s.DB.Query(`SELECT cve||'|'||package FROM vulns WHERE agent_id=?`, agentID)
	if err == nil {
		for rows.Next() {
			var k string
			rows.Scan(&k)
			old[k] = true
		}
		rows.Close()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	tx.Exec(`DELETE FROM vulns WHERE agent_id=?`, agentID)
	var fresh []Vuln
	for _, v := range vs {
		tx.Exec(`INSERT OR REPLACE INTO vulns VALUES(?,?,?,?,?,?,?,?,?)`, agentID, v.CVE, v.Package, v.Version, v.Fixed, v.Severity, v.Score, v.Summary, v.DetectedAt)
		if !old[v.CVE+"|"+v.Package] {
			fresh = append(fresh, v)
		}
	}
	return fresh, tx.Commit()
}

func (s *Store) ListVulns(agentID, severity string) ([]Vuln, error) {
	q := `SELECT agent_id,cve,package,version,fixed,severity,score,summary,detected_at FROM vulns WHERE 1=1`
	var args []any
	if agentID != "" {
		q += ` AND agent_id=?`
		args = append(args, agentID)
	}
	if severity != "" {
		q += ` AND severity=?`
		args = append(args, severity)
	}
	rows, err := s.DB.Query(q+` ORDER BY score DESC, cve LIMIT 5000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vuln
	for rows.Next() {
		var v Vuln
		rows.Scan(&v.AgentID, &v.CVE, &v.Package, &v.Version, &v.Fixed, &v.Severity, &v.Score, &v.Summary, &v.DetectedAt)
		out = append(out, v)
	}
	return out, nil
}

// ---------- commands (active response queue) ----------

type CommandRow struct {
	ID        int64             `json:"id"`
	AgentID   string            `json:"agent_id"`
	Name      string            `json:"name"`
	Args      map[string]string `json:"args"`
	Timeout   int               `json:"timeout"`
	Status    string            `json:"status"`
	Origin    string            `json:"origin"`
	CreatedAt int64             `json:"created_at"`
	SentAt    int64             `json:"sent_at"`
	Result    string            `json:"result"`
}

func (s *Store) QueueCommand(agentID, name string, args map[string]string, timeout int, origin string) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO commands(agent_id,name,args,timeout,status,origin,created_at) VALUES(?,?,?,?, 'queued', ?, ?)`,
		agentID, name, j(args), timeout, origin, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// TakeCommands returns queued commands for the agent and marks them sent.
func (s *Store) TakeCommands(agentID string) ([]proto.Command, error) {
	rows, err := s.DB.Query(`SELECT id,name,args,timeout FROM commands WHERE agent_id=? AND status='queued' ORDER BY id LIMIT 50`, agentID)
	if err != nil {
		return nil, err
	}
	var out []proto.Command
	for rows.Next() {
		var c proto.Command
		var a string
		rows.Scan(&c.ID, &c.Name, &a, &c.Timeout)
		json.Unmarshal([]byte(a), &c.Args)
		out = append(out, c)
	}
	rows.Close()
	now := time.Now().Unix()
	for _, c := range out {
		s.DB.Exec(`UPDATE commands SET status='sent', sent_at=? WHERE id=?`, now, c.ID)
	}
	return out, nil
}

func (s *Store) CompleteCommand(id int64, agentID, status, result string) {
	s.DB.Exec(`UPDATE commands SET status=?, result=? WHERE id=? AND agent_id=?`, status, result, id, agentID)
}

func (s *Store) ListCommands(agentID string, limit int) ([]CommandRow, error) {
	q := `SELECT id,agent_id,name,args,timeout,status,COALESCE(origin,''),created_at,COALESCE(sent_at,0),COALESCE(result,'') FROM commands`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id=?`
		args = append(args, agentID)
	}
	rows, err := s.DB.Query(q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandRow
	for rows.Next() {
		var c CommandRow
		var a string
		rows.Scan(&c.ID, &c.AgentID, &c.Name, &a, &c.Timeout, &c.Status, &c.Origin, &c.CreatedAt, &c.SentAt, &c.Result)
		json.Unmarshal([]byte(a), &c.Args)
		out = append(out, c)
	}
	return out, nil
}

// ---------- users ----------

func (s *Store) UserCount() int {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) SetUser(name, hash, salt string) error {
	_, err := s.DB.Exec(`INSERT INTO users VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET pass_hash=excluded.pass_hash, salt=excluded.salt`, name, hash, salt)
	return err
}

func (s *Store) GetUser(name string) (hash, salt string, err error) {
	err = s.DB.QueryRow(`SELECT pass_hash, salt FROM users WHERE username=?`, name).Scan(&hash, &salt)
	return
}
