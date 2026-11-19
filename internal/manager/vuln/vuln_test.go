package vuln

import (
	"testing"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "2.0", 1},
		{"3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12", -1},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u8", -1},
		{"1.2.3-r0", "1.2.3-r1", -1},
		{"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"1.0a", "1.0", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAffected(t *testing.T) {
	if !affected("1.2", "0", "1.3") || affected("1.3", "0", "1.3") || !affected("5.0", "4.0", "") || affected("3.9", "4.0", "") {
		t.Fatal("affected() range logic wrong")
	}
}

func TestCVSS(t *testing.T) {
	if s := CVSSScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); s != 9.8 {
		t.Errorf("got %v want 9.8", s)
	}
	if s := CVSSScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"); s != 6.1 {
		t.Errorf("got %v want 6.1", s)
	}
}

func TestEcosystem(t *testing.T) {
	for os, want := range map[proto.OSInfo]string{
		{ID: "debian", Version: "12"}:     "Debian:12",
		{ID: "ubuntu", Version: "22.04"}:  "Ubuntu:22.04:LTS",
		{ID: "ubuntu", Version: "23.10"}:  "Ubuntu:23.10",
		{ID: "alpine", Version: "3.19.1"}: "Alpine:v3.19",
		{ID: "rocky", Version: "9.3"}:     "Rocky Linux:9",
	} {
		if got := Ecosystem(os); got != want {
			t.Errorf("Ecosystem(%v)=%q want %q", os, got, want)
		}
	}
}
