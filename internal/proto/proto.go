// Package proto defines the wire format shared by warden-agent and warden-manager.
package proto

import "time"

const Version = "0.1.0"

// Event types emitted by agent modules.
const (
	TypeLog       = "log"      // logcollector line
	TypeCommand   = "command"  // logcollector command output
	TypeFIM       = "syscheck" // file integrity change
	TypeSCA       = "sca"      // configuration assessment result
	TypeAR        = "active_response"
	TypeAgent     = "agent"     // agent lifecycle (start/stop)
	TypeRootcheck = "rootcheck" // anomaly / rootkit check
)

// EnrollRequest is sent once by a new agent (POST /v1/enroll).
type EnrollRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Group    string `json:"group,omitempty"`
	OS       OSInfo `json:"os"`
	Version  string `json:"version"`
}

type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	Key     string `json:"key"` // hex HMAC key, used to sign every later request
}

type OSInfo struct {
	Platform string `json:"platform"` // linux, windows, darwin
	Name     string `json:"name"`     // e.g. Ubuntu
	ID       string `json:"id"`       // os-release ID: ubuntu, debian, alpine, rhel
	Version  string `json:"version"`  // os-release VERSION_ID
	Codename string `json:"codename,omitempty"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
}

// Event is one unit of security data shipped by an agent.
type Event struct {
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Location  string            `json:"location"` // file path, command, module name
	Log       string            `json:"log,omitempty"`
	Data      map[string]string `json:"data,omitempty"` // structured fields (FIM, SCA, AR)
}

type EventBatch struct {
	Events []Event `json:"events"`
}

// ControlRequest is the agent heartbeat (POST /v1/control). The response
// carries queued commands and the current hash of the agent's group config.
type ControlRequest struct {
	Version    string `json:"version"`
	ConfigHash string `json:"config_hash"`
	OS         OSInfo `json:"os"`
}

type ControlResponse struct {
	ConfigHash string    `json:"config_hash"`
	Commands   []Command `json:"commands"`
}

// Command is an active-response or maintenance task for an agent.
type Command struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"` // firewall-drop, host-deny, kill-process, fim-scan, inventory-scan, sca-scan, restart
	Args    map[string]string `json:"args,omitempty"`
	Timeout int               `json:"timeout,omitempty"` // seconds; >0 means auto-revert
}

// Inventory (syscollector) snapshot, POST /v1/inventory.
type Inventory struct {
	OS         OSInfo    `json:"os"`
	Packages   []Package `json:"packages"`
	Ports      []Port    `json:"ports"`
	Processes  []Process `json:"processes"`
	Interfaces []Iface   `json:"interfaces"`
	ScannedAt  time.Time `json:"scanned_at"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Format  string `json:"format"` // deb, rpm, apk
	Source  string `json:"source,omitempty"`
}

type Port struct {
	Protocol string `json:"protocol"`
	LocalIP  string `json:"local_ip"`
	Port     int    `json:"port"`
	State    string `json:"state"`
	PID      int    `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
}

type Process struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	User    string `json:"user"`
	Cmdline string `json:"cmdline"`
}

type Iface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	Addr []string `json:"addresses"`
}

// AgentConfig is the centrally managed (group) configuration pushed to agents.
type AgentConfig struct {
	LogFiles  []LogFile    `yaml:"logcollector" json:"logcollector"`
	Commands  []CommandMon `yaml:"commands" json:"commands"`
	FIM       FIMConfig    `yaml:"syscheck" json:"syscheck"`
	Inventory struct {
		IntervalSec int `yaml:"interval" json:"interval"`
	} `yaml:"syscollector" json:"syscollector"`
	SCA struct {
		IntervalSec int      `yaml:"interval" json:"interval"`
		Policies    []string `yaml:"policies" json:"policies"` // policy file names served by manager
	} `yaml:"sca" json:"sca"`
	Rootcheck struct {
		IntervalSec int `yaml:"interval" json:"interval"`
	} `yaml:"rootcheck" json:"rootcheck"`
	ActiveResponse struct {
		Enabled bool `yaml:"enabled" json:"enabled"`
	} `yaml:"active_response" json:"active_response"`
}

type LogFile struct {
	Path   string `yaml:"path" json:"path"`
	Format string `yaml:"format" json:"format"` // syslog, json, plain
}

type CommandMon struct {
	Command     string `yaml:"command" json:"command"`
	Alias       string `yaml:"alias" json:"alias"`
	IntervalSec int    `yaml:"interval" json:"interval"`
}

type FIMConfig struct {
	IntervalSec int      `yaml:"interval" json:"interval"`
	Directories []string `yaml:"directories" json:"directories"`
	Ignore      []string `yaml:"ignore" json:"ignore"`
	MaxFileMB   int      `yaml:"max_file_mb" json:"max_file_mb"`
}

// SCA policy file format (Wazuh-compatible rule syntax).
type SCAPolicy struct {
	Policy struct {
		ID          string `yaml:"id" json:"id"`
		Name        string `yaml:"name" json:"name"`
		Description string `yaml:"description" json:"description"`
	} `yaml:"policy" json:"policy"`
	Requirements *SCACheck  `yaml:"requirements" json:"requirements,omitempty"`
	Checks       []SCACheck `yaml:"checks" json:"checks"`
}

type SCACheck struct {
	ID          int                 `yaml:"id" json:"id"`
	Title       string              `yaml:"title" json:"title"`
	Description string              `yaml:"description" json:"description"`
	Rationale   string              `yaml:"rationale" json:"rationale"`
	Remediation string              `yaml:"remediation" json:"remediation"`
	Compliance  map[string][]string `yaml:"compliance" json:"compliance"`
	Condition   string              `yaml:"condition" json:"condition"` // all, any, none
	Rules       []string            `yaml:"rules" json:"rules"`
}

// ConfigBundle is returned by GET /v1/config: the merged group configuration
// plus the SCA policies it references.
type ConfigBundle struct {
	Hash     string      `json:"hash"`
	Group    string      `json:"group"`
	Config   AgentConfig `json:"config"`
	Policies []SCAPolicy `json:"policies"`
}

// Request signing headers (HMAC-SHA256 with the agent key).
const (
	HeaderAgentID   = "X-Warden-Agent"
	HeaderTimestamp = "X-Warden-Timestamp"
	HeaderSignature = "X-Warden-Signature"
)
