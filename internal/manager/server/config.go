package server

import (
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

type Webhook struct {
	URL      string `yaml:"url"`
	MinLevel int    `yaml:"min_level"`
	Format   string `yaml:"format"` // json (default) or slack
}

type Config struct {
	ListenAgents string `yaml:"listen_agents"` // HTTPS agent protocol (enroll, events, control)
	ListenAPI    string `yaml:"listen_api"`    // HTTPS dashboard + REST API
	ListenSyslog string `yaml:"listen_syslog"` // UDP syslog for agentless devices ("" = off)
	DataDir      string `yaml:"data_dir"`
	RulesetDir   string `yaml:"ruleset_dir"` // contains decoders/, rules/, sca/, shared/
	EnrollPass   string `yaml:"enrollment_password"`
	AlertLevel   int    `yaml:"alert_level"`
	Archive      bool   `yaml:"archive_events"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	Retention    struct {
		AlertDays int `yaml:"alerts_days"`
		EventDays int `yaml:"events_days"`
	} `yaml:"retention"`
	ActiveResponse struct {
		Enabled   bool     `yaml:"enabled"`
		Whitelist []string `yaml:"whitelist"`
	} `yaml:"active_response"`
	Vuln struct {
		IntervalHours int      `yaml:"interval_hours"`
		Feeds         []string `yaml:"feeds"`          // local JSON feeds loaded at start
		OSVAutoSync   bool     `yaml:"osv_auto_sync"`  // download OSV data for agents' ecosystems
		OSVEcosystems []string `yaml:"osv_ecosystems"` // extra ecosystems to always sync
	} `yaml:"vulnerability_detector"`
	Webhooks []Webhook `yaml:"webhooks"`
}

func DefaultConfig() *Config {
	c := &Config{
		ListenAgents: ":1514",
		ListenAPI:    ":55000",
		DataDir:      "./data",
		RulesetDir:   "./ruleset",
		EnrollPass:   "",
		AlertLevel:   3,
	}
	c.Retention.AlertDays, c.Retention.EventDays = 90, 7
	c.ActiveResponse.Enabled = true
	c.ActiveResponse.Whitelist = []string{"127.0.0.1", "::1"}
	c.Vuln.IntervalHours = 6
	return c
}

func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
		base := filepath.Dir(path)
		for _, p := range []*string{&c.DataDir, &c.RulesetDir} {
			if !filepath.IsAbs(*p) {
				*p = filepath.Join(base, *p)
			}
		}
		for i, f := range c.Vuln.Feeds {
			if !filepath.IsAbs(f) {
				c.Vuln.Feeds[i] = filepath.Join(base, f)
			}
		}
	}
	if v := os.Getenv("WARDEN_ENROLLMENT_PASSWORD"); v != "" {
		c.EnrollPass = v
	}
	return c, nil
}
