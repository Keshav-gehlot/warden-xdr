// Package vuln implements the vulnerability detector: an OSV-based feed and a
// matcher that compares an agent's installed packages against it.
package vuln

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// Ecosystem maps an agent OS to the OSV ecosystem name.
func Ecosystem(os proto.OSInfo) string {
	v := os.Version
	switch strings.ToLower(os.ID) {
	case "debian":
		if i := strings.Index(v, "."); i > 0 {
			v = v[:i]
		}
		return "Debian:" + v
	case "ubuntu":
		eco := "Ubuntu:" + v
		if lts(v) {
			eco += ":LTS"
		}
		return eco
	case "alpine":
		parts := strings.Split(v, ".")
		if len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1]
		}
	case "rocky":
		return "Rocky Linux:" + major(v)
	case "almalinux":
		return "AlmaLinux:" + major(v)
	}
	return ""
}

func major(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

func lts(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	y, _ := strconv.Atoi(parts[0])
	return y%2 == 0 && parts[1] == "04"
}

// ---------- Debian/dpkg version comparison (also good enough for apk/rpm) ----------

// Compare returns -1, 0 or 1 comparing two package versions using the dpkg
// algorithm (epoch:upstream-revision, with ~ sorting before everything).
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func split(v string) (int, string, string) {
	epoch := 0
	if i := strings.Index(v, ":"); i > 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	rev := ""
	if i := strings.LastIndex(v, "-"); i > 0 {
		rev = v[i+1:]
		v = v[:i]
	}
	return epoch, v, rev
}

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case unicode.IsLetter(rune(c)):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			if firstDiff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ---------- matcher ----------

// Match returns the vulnerabilities affecting the given inventory.
func Match(st *store.Store, inv *proto.Inventory) ([]store.Vuln, error) {
	eco := Ecosystem(inv.OS)
	if eco == "" {
		return nil, nil
	}
	now := time.Now().Unix()
	seen := map[string]bool{}
	var out []store.Vuln
	for _, p := range inv.Packages {
		names := []string{p.Name}
		if p.Source != "" && p.Source != p.Name {
			names = append(names, p.Source) // Debian advisories are keyed by source package
		}
		for _, n := range names {
			entries, err := st.FeedFor(eco, n)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if !affected(p.Version, e.Introduced, e.Fixed) {
					continue
				}
				k := e.CVE + "|" + p.Name
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, store.Vuln{CVE: e.CVE, Package: p.Name, Version: p.Version, Fixed: e.Fixed,
					Severity: e.Severity, Score: e.Score, Summary: e.Summary, DetectedAt: now})
			}
		}
	}
	return out, nil
}

func affected(installed, introduced, fixed string) bool {
	if introduced != "" && introduced != "0" && Compare(installed, introduced) < 0 {
		return false
	}
	if fixed == "" {
		return true // no fix released yet
	}
	return Compare(installed, fixed) < 0
}

// ---------- OSV feed sync ----------

type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
		DatabaseSpecific  map[string]any `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// OSVZipURL returns the bulk-download URL for an OSV ecosystem.
func OSVZipURL(eco string) string {
	return "https://osv-vulnerabilities.storage.googleapis.com/" + strings.ReplaceAll(eco, " ", "%20") + "/all.zip"
}

// SyncOSV loads an OSV all.zip (from a URL or a local path) and replaces the
// feed entries for every requested ecosystem (e.g. "Debian:12").
func SyncOSV(st *store.Store, src string, ecosystems []string) (map[string]int, error) {
	var data []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		cl := &http.Client{Timeout: 10 * time.Minute}
		resp, err := cl.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("download %s: %s", src, resp.Status)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else if data, err = os.ReadFile(src); err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, e := range ecosystems {
		want[e] = true
	}
	byEco := map[string][]store.FeedEntry{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var rec osvRecord
		err = json.NewDecoder(rc).Decode(&rec)
		rc.Close()
		if err != nil {
			continue
		}
		byEco = mergeRecord(rec, want, byEco)
	}
	counts := map[string]int{}
	for eco, entries := range byEco {
		if err := st.ReplaceFeed(eco, entries); err != nil {
			return nil, err
		}
		counts[eco] = len(entries)
	}
	return counts, nil
}

// LoadJSONFeeds loads one or more JSON arrays of feed entries (the bundled
// offline demo feed, custom/internal advisories) and merges them per ecosystem.
func LoadJSONFeeds(st *store.Store, paths ...string) (map[string]int, error) {
	byEco := map[string][]store.FeedEntry{}
	for _, path := range paths {
		if err := readJSONFeed(path, byEco); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	counts := map[string]int{}
	for eco, es := range byEco {
		if err := st.ReplaceFeed(eco, es); err != nil {
			return nil, err
		}
		counts[eco] = len(es)
	}
	return counts, nil
}

func readJSONFeed(path string, byEco map[string][]store.FeedEntry) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw []struct {
		CVE        string  `json:"cve"`
		Ecosystem  string  `json:"ecosystem"`
		Package    string  `json:"package"`
		Introduced string  `json:"introduced"`
		Fixed      string  `json:"fixed"`
		Severity   string  `json:"severity"`
		Score      float64 `json:"score"`
		Summary    string  `json:"summary"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for _, r := range raw {
		byEco[r.Ecosystem] = append(byEco[r.Ecosystem], store.FeedEntry{CVE: r.CVE, Ecosystem: r.Ecosystem, Package: r.Package,
			Introduced: r.Introduced, Fixed: r.Fixed, Severity: r.Severity, Score: r.Score, Summary: r.Summary})
	}
	return nil
}

func mergeRecord(rec osvRecord, want map[string]bool, byEco map[string][]store.FeedEntry) map[string][]store.FeedEntry {
	cve := rec.ID
	for _, a := range append(append([]string{}, rec.Aliases...), rec.Upstream...) {
		if strings.HasPrefix(a, "CVE-") {
			cve = a
			break
		}
	}
	summary := rec.Summary
	if summary == "" {
		summary = rec.Details
	}
	if len(summary) > 300 {
		summary = summary[:300] + "…"
	}
	score, sev := 0.0, ""
	for _, s := range rec.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			if sc := CVSSScore(s.Score); sc > score {
				score = sc
			}
		}
	}
	if v, ok := rec.DatabaseSpecific["severity"].(string); ok {
		sev = normSeverity(v)
	}
	for _, a := range rec.Affected {
		eco := a.Package.Ecosystem
		if len(want) > 0 && !want[eco] {
			continue
		}
		asev := sev
		if v, ok := a.EcosystemSpecific["urgency"].(string); ok && asev == "" {
			asev = urgencySeverity(v)
		}
		if v, ok := a.DatabaseSpecific["severity"].(string); ok {
			asev = normSeverity(v)
		}
		if asev == "" {
			asev = scoreSeverity(score)
		}
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			intro := ""
			for _, ev := range r.Events {
				if v, ok := ev["introduced"]; ok {
					intro = v
				}
				if v, ok := ev["fixed"]; ok {
					byEco[eco] = append(byEco[eco], store.FeedEntry{CVE: cve, Ecosystem: eco, Package: a.Package.Name,
						Introduced: intro, Fixed: v, Severity: asev, Score: score, Summary: summary})
					intro = ""
				}
			}
			if intro != "" { // introduced without a fix
				byEco[eco] = append(byEco[eco], store.FeedEntry{CVE: cve, Ecosystem: eco, Package: a.Package.Name,
					Introduced: intro, Severity: asev, Score: score, Summary: summary})
			}
		}
	}
	return byEco
}

func normSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "Critical"
	case "high", "important":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low", "negligible", "unimportant":
		return "Low"
	}
	return ""
}

func urgencySeverity(u string) string {
	switch strings.ToLower(strings.TrimSuffix(u, "*")) {
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low", "unimportant", "not yet assigned":
		return "Low"
	}
	return ""
}

func scoreSeverity(s float64) string {
	switch {
	case s >= 9:
		return "Critical"
	case s >= 7:
		return "High"
	case s >= 4:
		return "Medium"
	case s > 0:
		return "Low"
	}
	return "Unknown"
}

// CVSSScore computes the CVSS v3.x base score from a vector string.
func CVSSScore(vec string) float64 {
	if !strings.HasPrefix(vec, "CVSS:3") {
		return 0
	}
	m := map[string]string{}
	for _, p := range strings.Split(vec, "/")[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	iss := 1 - (1-cia[m["C"]])*(1-cia[m["I"]])*(1-cia[m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	var base float64
	if changed {
		base = math.Min(1.08*(impact+expl), 10)
	} else {
		base = math.Min(impact+expl, 10)
	}
	return math.Ceil(base*10) / 10
}
