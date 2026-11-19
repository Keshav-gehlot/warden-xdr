package agent

import (
	"bufio"
	"context"
	"encoding/hex"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// syscollector: OS, packages, listening ports, processes and interfaces.
func (a *Agent) inventoryLoop(ctx context.Context) {
	periodic(ctx, 5*time.Second, func() time.Duration { return interval(a.Config().Inventory.IntervalSec, 3600, 60) }, a.trigInv, func() {
		inv := collectInventory()
		if err := a.client.Post("/v1/inventory", inv, nil); err != nil {
			log.Printf("syscollector: upload: %v", err)
			return
		}
		log.Printf("syscollector: sent %d packages, %d ports, %d processes", len(inv.Packages), len(inv.Ports), len(inv.Processes))
	})
}

func collectInventory() *proto.Inventory {
	procs := processes()
	return &proto.Inventory{OS: OSInfo(), Packages: packages(), Ports: ports(procs), Processes: procs, Interfaces: interfaces(), ScannedAt: time.Now()}
}

// ---------- packages ----------

func packages() []proto.Package {
	var out []proto.Package
	out = append(out, dpkgPackages("/var/lib/dpkg/status")...)
	out = append(out, apkPackages("/lib/apk/db/installed")...)
	if len(out) == 0 {
		if _, err := exec.LookPath("rpm"); err == nil {
			o, err := exec.Command("rpm", "-qa", "--qf", `%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`).Output()
			if err == nil {
				for _, l := range strings.Split(string(o), "\n") {
					f := strings.Split(l, "\t")
					if len(f) >= 3 {
						out = append(out, proto.Package{Name: f[0], Version: f[1], Arch: f[2], Format: "rpm"})
					}
				}
			}
		}
	}
	return out
}

func dpkgPackages(path string) []proto.Package {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []proto.Package
	var p proto.Package
	installed := false
	flush := func() {
		if installed && p.Name != "" {
			p.Format = "deb"
			out = append(out, p)
		}
		p, installed = proto.Package{}, false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		switch k {
		case "Package":
			p.Name = v
		case "Status":
			installed = strings.HasSuffix(v, " installed")
		case "Version":
			p.Version = v
		case "Architecture":
			p.Arch = v
		case "Source":
			p.Source = strings.Fields(v)[0] // "openssl (3.0.2-0ubuntu1)" → openssl
		}
	}
	flush()
	return out
}

func apkPackages(path string) []proto.Package {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []proto.Package
	var p proto.Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			if p.Name != "" {
				p.Format = "apk"
				out = append(out, p)
			}
			p = proto.Package{}
			continue
		}
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		switch l[0] {
		case 'P':
			p.Name = l[2:]
		case 'V':
			p.Version = l[2:]
		case 'A':
			p.Arch = l[2:]
		case 'o':
			p.Source = l[2:]
		}
	}
	if p.Name != "" {
		p.Format = "apk"
		out = append(out, p)
	}
	return out
}

// ---------- processes ----------

func processes() []proto.Process {
	dirs, _ := os.ReadDir("/proc")
	users := passwdUsers()
	var out []proto.Process
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		base := "/proc/" + d.Name()
		stat, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue
		}
		s := string(stat)
		lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if lp < 0 || rp < lp {
			continue
		}
		name := s[lp+1 : rp]
		rest := strings.Fields(s[rp+1:])
		ppid := 0
		if len(rest) > 1 {
			ppid, _ = strconv.Atoi(rest[1])
		}
		cmd, _ := os.ReadFile(base + "/cmdline")
		uid := ""
		if st, err := os.ReadFile(base + "/status"); err == nil {
			for _, l := range strings.Split(string(st), "\n") {
				if strings.HasPrefix(l, "Uid:") {
					if f := strings.Fields(l); len(f) > 1 {
						uid = f[1]
					}
				}
			}
		}
		user := users[uid]
		if user == "" {
			user = uid
		}
		cl := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(cl) > 512 {
			cl = cl[:512]
		}
		out = append(out, proto.Process{PID: pid, PPID: ppid, Name: name, User: user, Cmdline: cl})
	}
	return out
}

func passwdUsers() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 2 {
			m[f[2]] = f[0]
		}
	}
	return m
}

// ---------- ports ----------

var tcpStates = map[string]string{"01": "established", "02": "syn_sent", "06": "time_wait", "08": "close_wait", "0A": "listening"}

func ports(procs []proto.Process) []proto.Port {
	inodePID := socketInodes()
	pname := map[int]string{}
	for _, p := range procs {
		pname[p.PID] = p.Name
	}
	var out []proto.Port
	for _, t := range []struct{ file, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"}} {
		b, err := os.ReadFile(t.file)
		if err != nil {
			continue
		}
		for i, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if i == 0 || len(f) < 10 {
				continue
			}
			st := tcpStates[f[3]]
			if strings.HasPrefix(t.proto, "tcp") && st != "listening" {
				continue // inventory lists listening TCP and bound UDP sockets
			}
			if strings.HasPrefix(t.proto, "udp") {
				st = "bound"
			}
			ipHex, portHex, ok := strings.Cut(f[1], ":")
			if !ok {
				continue
			}
			port, _ := strconv.ParseInt(portHex, 16, 32)
			pid := inodePID[f[9]]
			out = append(out, proto.Port{Protocol: t.proto, LocalIP: hexIP(ipHex), Port: int(port), State: st, PID: pid, Process: pname[pid]})
		}
	}
	return out
}

func hexIP(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	// /proc stores addresses as host-endian 32-bit words
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String()
}

func socketInodes() map[string]int {
	m := map[string]int{}
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range fds {
		l, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		pid, _ := strconv.Atoi(strings.Split(fd, "/")[2])
		m[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = pid
	}
	return m
}

// ---------- interfaces ----------

func interfaces() []proto.Iface {
	ifs, _ := net.Interfaces()
	var out []proto.Iface
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		var as []string
		for _, a := range addrs {
			as = append(as, a.String())
		}
		out = append(out, proto.Iface{Name: i.Name, MAC: i.HardwareAddr.String(), Addr: as})
	}
	return out
}
