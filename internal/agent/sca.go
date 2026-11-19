package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// Security Configuration Assessment with Wazuh-compatible rule syntax:
//
//	f:/path                          file exists
//	f:/path -> r:REGEX && !r:REGEX   some line of the file satisfies every content condition
//	f:/path -> n:REGEX(\d+) compare <= 4   numeric capture compared with a value
//	d:/dir                           directory exists
//	d:/dir -> FILE_REGEX -> r:REGEX  some file in dir (name regex) has a matching line
//	c:command -> r:REGEX             some output line of the command matches
//	p:REGEX                          a running process name/cmdline matches
//	not <rule>  or  !<rule>          negation
func (a *Agent) scaLoop(ctx context.Context) {
	last := map[string]string{} // policy|check → result, so only changes are sent
	periodic(ctx, 20*time.Second, func() time.Duration { return interval(a.Config().SCA.IntervalSec, 43200, 60) }, a.trigSCA, func() {
		b := a.bundle.Load()
		if b == nil {
			return
		}
		sent, total := 0, 0
		for _, p := range b.Policies {
			if p.Requirements != nil {
				if res, _ := evalCheck(*p.Requirements); res != "passed" {
					log.Printf("sca: policy %s not applicable on this host", p.Policy.ID)
					continue
				}
			}
			for _, c := range p.Checks {
				total++
				res, reason := evalCheck(c)
				k := p.Policy.ID + "|" + strconv.Itoa(c.ID)
				if last[k] == res {
					continue
				}
				last[k] = res
				sent++
				comp, _ := json.Marshal(c.Compliance)
				a.Emit(proto.Event{Type: proto.TypeSCA, Location: "sca", Data: map[string]string{
					"policy_id": p.Policy.ID, "policy": p.Policy.Name, "check_id": strconv.Itoa(c.ID), "title": c.Title,
					"result": res, "reason": reason, "remediation": c.Remediation, "rationale": c.Rationale, "compliance": string(comp)}})
			}
		}
		log.Printf("sca: evaluated %d checks, %d changed", total, sent)
	})
}

func evalCheck(c proto.SCACheck) (result, reason string) {
	cond := strings.ToLower(c.Condition)
	if cond == "" {
		cond = "all"
	}
	var trues int
	var firstFalse, firstTrue string
	for _, r := range c.Rules {
		ok, err := evalRule(r)
		if err != nil {
			return "not applicable", err.Error()
		}
		if ok {
			trues++
			if firstTrue == "" {
				firstTrue = r
			}
		} else if firstFalse == "" {
			firstFalse = r
		}
	}
	n := len(c.Rules)
	switch cond {
	case "all":
		if trues == n {
			return "passed", ""
		}
		return "failed", "rule not satisfied: " + firstFalse
	case "any":
		if trues > 0 {
			return "passed", ""
		}
		return "failed", "no rule satisfied"
	case "none":
		if trues == 0 {
			return "passed", ""
		}
		return "failed", "rule matched: " + firstTrue
	}
	return "not applicable", "unknown condition " + cond
}

func evalRule(rule string) (bool, error) {
	rule = strings.TrimSpace(rule)
	neg := false
	if strings.HasPrefix(rule, "not ") {
		neg, rule = true, strings.TrimSpace(rule[4:])
	} else if strings.HasPrefix(rule, "!") {
		neg, rule = true, rule[1:]
	}
	if len(rule) < 3 || rule[1] != ':' {
		return false, fmt.Errorf("invalid rule %q", rule)
	}
	kind := rule[0]
	parts := strings.Split(rule[2:], " -> ")
	target := strings.TrimSpace(parts[0])
	var ok bool
	var err error
	switch kind {
	case 'f':
		ok, err = checkFile(target, parts[1:])
	case 'd':
		ok, err = checkDir(target, parts[1:])
	case 'c':
		ok, err = checkCommand(target, parts[1:])
	case 'p':
		ok, err = checkProcess(target)
	default:
		return false, fmt.Errorf("unsupported rule type %q", kind)
	}
	if err != nil {
		return false, err
	}
	return ok != neg, nil
}

func checkFile(path string, conds []string) (bool, error) {
	if len(conds) == 0 {
		_, err := os.Stat(path)
		return err == nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer f.Close()
	return linesMatch(bufio.NewScanner(f), conds[0])
}

func checkDir(dir string, conds []string) (bool, error) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false, nil
	}
	if len(conds) == 0 {
		return true, nil
	}
	nameRe, err := regexp.Compile(strings.TrimPrefix(strings.TrimSpace(conds[0]), "r:"))
	if err != nil {
		return false, err
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !nameRe.MatchString(e.Name()) {
			continue
		}
		if len(conds) == 1 {
			return true, nil
		}
		if ok, err := checkFile(filepath.Join(dir, e.Name()), conds[1:]); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func checkCommand(cmd string, conds []string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).CombinedOutput()
	if len(conds) == 0 {
		return len(strings.TrimSpace(string(out))) > 0, nil
	}
	return linesMatch(bufio.NewScanner(strings.NewReader(string(out))), conds[0])
}

func checkProcess(pattern string) (bool, error) {
	re, err := regexp.Compile(strings.TrimPrefix(pattern, "r:"))
	if err != nil {
		return false, err
	}
	for _, p := range processes() {
		if re.MatchString(p.Name) || re.MatchString(p.Cmdline) {
			return true, nil
		}
	}
	return false, nil
}

type contentCond struct {
	neg     bool
	re      *regexp.Regexp
	numeric bool
	op      string
	val     float64
}

var numCmp = regexp.MustCompile(`^(.*)\s+compare\s+(<=|>=|==|!=|<|>)\s+(-?[\d.]+)$`)

func parseConds(expr string) ([]contentCond, error) {
	var out []contentCond
	for _, p := range strings.Split(expr, " && ") {
		p = strings.TrimSpace(p)
		c := contentCond{}
		if strings.HasPrefix(p, "!") {
			c.neg, p = true, p[1:]
		}
		switch {
		case strings.HasPrefix(p, "r:"):
			p = p[2:]
		case strings.HasPrefix(p, "n:"):
			m := numCmp.FindStringSubmatch(p[2:])
			if m == nil {
				return nil, fmt.Errorf("bad numeric condition %q", p)
			}
			c.numeric, c.op = true, m[2]
			c.val, _ = strconv.ParseFloat(m[3], 64)
			p = m[1]
		default:
			return nil, fmt.Errorf("unsupported content condition %q", p)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		c.re = re
		out = append(out, c)
	}
	return out, nil
}

func (c contentCond) match(line string) bool {
	if c.numeric {
		m := c.re.FindStringSubmatch(line)
		if len(m) < 2 {
			return c.neg
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return c.neg
		}
		var ok bool
		switch c.op {
		case "<=":
			ok = v <= c.val
		case ">=":
			ok = v >= c.val
		case "<":
			ok = v < c.val
		case ">":
			ok = v > c.val
		case "==":
			ok = v == c.val
		case "!=":
			ok = v != c.val
		}
		return ok != c.neg
	}
	return c.re.MatchString(line) != c.neg
}

// linesMatch is true when at least one line satisfies every condition.
func linesMatch(sc *bufio.Scanner, expr string) (bool, error) {
	conds, err := parseConds(expr)
	if err != nil {
		return false, err
	}
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		all := true
		for _, c := range conds {
			if !c.match(line) {
				all = false
				break
			}
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}
