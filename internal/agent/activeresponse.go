package agent

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// execute runs a command pushed by the manager. Arguments are validated and
// passed to exec without a shell, so a crafted log line cannot inject commands.
func (a *Agent) execute(c proto.Command) {
	target := c.Args["target"]
	report := func(status, out string) {
		a.Emit(proto.Event{Type: proto.TypeAR, Location: "active-response", Data: map[string]string{
			"command_id": strconv.FormatInt(c.ID, 10), "command": c.Name, "target": target, "status": status, "output": out}})
	}
	if !a.Config().ActiveResponse.Enabled && isResponse(c.Name) {
		report("failed", "active response disabled in agent group config")
		return
	}
	log.Printf("command #%d: %s %s", c.ID, c.Name, target)
	switch c.Name {
	case "fim-scan":
		trigger(a.trigFIM)
		report("ok", "syscheck scan triggered")
	case "inventory-scan":
		trigger(a.trigInv)
		report("ok", "inventory scan triggered")
	case "sca-scan":
		trigger(a.trigSCA)
		report("ok", "SCA scan triggered")
	case "rootcheck-scan":
		trigger(a.trigRoot)
		report("ok", "rootcheck scan triggered")
	case "restart":
		report("ok", "restarting agent")
		time.Sleep(2 * time.Second)
		select {
		case a.restart <- struct{}{}:
		default:
		}
	case "firewall-drop":
		ip := net.ParseIP(target)
		if ip == nil {
			report("failed", "invalid IP address")
			return
		}
		out, err := firewall(ip, true)
		if err != nil {
			report("failed", out+err.Error())
			return
		}
		report("ok", "blocked "+ip.String())
		a.scheduleRevert(c, func() (string, error) { return firewall(ip, false) })
	case "host-deny":
		ip := net.ParseIP(target)
		if ip == nil {
			report("failed", "invalid IP address")
			return
		}
		line := "ALL: " + ip.String() + "\n"
		f, err := os.OpenFile("/etc/hosts.deny", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			report("failed", err.Error())
			return
		}
		f.WriteString(line)
		f.Close()
		report("ok", "added "+ip.String()+" to /etc/hosts.deny")
		a.scheduleRevert(c, func() (string, error) {
			b, err := os.ReadFile("/etc/hosts.deny")
			if err != nil {
				return "", err
			}
			return "", os.WriteFile("/etc/hosts.deny", []byte(strings.Replace(string(b), line, "", 1)), 0644)
		})
	case "kill-process":
		pid, err := strconv.Atoi(target)
		if err != nil || pid <= 1 || pid == os.Getpid() {
			report("failed", "invalid pid")
			return
		}
		if err := killPID(pid); err != nil {
			report("failed", err.Error())
			return
		}
		report("ok", "killed pid "+target)
	case "disable-account":
		if !userRe.MatchString(target) || target == "root" {
			report("failed", "invalid or protected user")
			return
		}
		out, err := exec.Command("usermod", "-L", "-e", "1", target).CombinedOutput()
		if err != nil {
			report("failed", string(out)+err.Error())
			return
		}
		report("ok", "locked account "+target)
		a.scheduleRevert(c, func() (string, error) {
			o, err := exec.Command("usermod", "-U", "-e", "", target).CombinedOutput()
			return string(o), err
		})
	default:
		report("failed", "unknown command")
	}
}

func isResponse(name string) bool {
	switch name {
	case "firewall-drop", "host-deny", "kill-process", "disable-account":
		return true
	}
	return false
}

func (a *Agent) scheduleRevert(c proto.Command, undo func() (string, error)) {
	if c.Timeout <= 0 {
		return
	}
	key := c.Name + "|" + c.Args["target"]
	a.arMu.Lock()
	if t, ok := a.arTimers[key]; ok {
		t.Stop()
	}
	a.arTimers[key] = time.AfterFunc(time.Duration(c.Timeout)*time.Second, func() {
		a.arMu.Lock()
		delete(a.arTimers, key)
		a.arMu.Unlock()
		out, err := undo()
		status := "reverted"
		if err != nil {
			status, out = "failed", "revert: "+out+err.Error()
		}
		a.Emit(proto.Event{Type: proto.TypeAR, Location: "active-response", Data: map[string]string{
			"command_id": "0", "command": c.Name, "target": c.Args["target"], "status": status, "output": out}})
	})
	a.arMu.Unlock()
}

// firewall adds or removes a DROP rule using nftables if present, else iptables.
func firewall(ip net.IP, add bool) (string, error) {
	v6 := ip.To4() == nil
	if nft, err := exec.LookPath("nft"); err == nil {
		fam := "ip"
		if v6 {
			fam = "ip6"
		}
		set := "blocked4"
		typ := "ipv4_addr"
		if v6 {
			set, typ = "blocked6", "ipv6_addr"
		}
		setup := [][]string{
			{"add", "table", "inet", "warden"},
			{"add", "set", "inet", "warden", set, "{", "type", typ, ";", "}"},
			{"add", "chain", "inet", "warden", "input", "{", "type", "filter", "hook", "input", "priority", "-10", ";", "}"},
		}
		for _, s := range setup {
			exec.Command(nft, s...).Run()
		}
		// idempotent drop rule referencing the set
		if out, _ := exec.Command(nft, "list", "chain", "inet", "warden", "input").Output(); !strings.Contains(string(out), "@"+set) {
			exec.Command(nft, "add", "rule", "inet", "warden", "input", fam, "saddr", "@"+set, "drop").Run()
		}
		op := "add"
		if !add {
			op = "delete"
		}
		out, err := exec.Command(nft, op, "element", "inet", "warden", set, "{", ip.String(), "}").CombinedOutput()
		return string(out), err
	}
	bin := "iptables"
	if v6 {
		bin = "ip6tables"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return "", fmt.Errorf("neither nft nor %s available", bin)
	}
	op := "-I"
	if !add {
		op = "-D"
	}
	out, err := exec.Command(bin, op, "INPUT", "-s", ip.String(), "-j", "DROP").CombinedOutput()
	return string(out), err
}
