package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

func TestSCARules(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	os.WriteFile(cfg, []byte("# PermitRootLogin yes\nPermitRootLogin no\nMaxAuthTries 6\nX11Forwarding yes\n"), 0644)
	pw := filepath.Join(dir, "passwd")
	os.WriteFile(pw, []byte("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n"), 0644)

	cases := []struct {
		rule string
		want bool
	}{
		{"f:" + cfg, true},
		{"f:" + dir + "/missing", false},
		{"not f:" + dir + "/missing", true},
		{"f:" + cfg + ` -> r:^\s*PermitRootLogin\s+no`, true},
		{"f:" + cfg + ` -> r:^\s*PasswordAuthentication\s+no`, false},
		{"f:" + cfg + ` -> n:^\s*MaxAuthTries\s+(\d+) compare <= 4`, false},
		{"f:" + cfg + ` -> n:^\s*MaxAuthTries\s+(\d+) compare > 4`, true},
		{"f:" + pw + ` -> !r:^root: && r:^[^:]*:[^:]*:0:`, true},
		{"d:" + dir + ` -> ^sshd_ -> r:X11Forwarding yes`, true},
		{"c:echo hello world -> r:^hello", true},
		{`p:^definitely-not-running-xyz$`, false},
	}
	for _, c := range cases {
		got, err := evalRule(c.rule)
		if err != nil {
			t.Fatalf("%s: %v", c.rule, err)
		}
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.rule, got, c.want)
		}
	}
	res, _ := evalCheck(proto.SCACheck{Condition: "none", Rules: []string{"f:" + cfg + ` -> r:^\s*X11Forwarding\s+yes`}})
	if res != "failed" {
		t.Errorf("none-condition check: got %s", res)
	}
}
