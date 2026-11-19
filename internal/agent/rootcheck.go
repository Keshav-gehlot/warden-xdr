package agent

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// Rootcheck looks for host anomalies: processes hidden from /proc listings,
// known rootkit artefacts, interfaces in promiscuous mode, SUID binaries in
// temp directories and world-writable files in /etc.
var rootkitFiles = []string{
	"/dev/.udev/rules.d/", "/usr/bin/sourcemask", "/usr/bin/ras2xm", "/dev/ptyxx", "/usr/lib/libext-2.so.7",
	"/etc/rc.d/init.d/rc.modules", "/usr/sbin/xntps", "/lib/libproc.a", "/usr/lib/.fx", "/dev/.lib/lib/lib",
	"/usr/share/.aPa", "/etc/ld.so.hash", "/usr/lib/libsh", "/lib/lblip.tk", "/dev/.oz", "/usr/include/file.h",
	"/usr/include/hosts.h", "/usr/include/lidps1.h", "/usr/include/proc.h", "/etc/sysconfig/console/load.zk",
	"/lib/libkeyutils.so.1.9", "/usr/lib/libkeyutils.so.1.9", "/etc/ld.so.preload",
}

func (a *Agent) rootcheckLoop(ctx context.Context) {
	reported := map[string]bool{}
	periodic(ctx, 60*time.Second, func() time.Duration { return interval(a.Config().Rootcheck.IntervalSec, 43200, 60) }, a.trigRoot, func() {
		report := func(check, title, detail string) {
			k := check + "|" + detail
			if reported[k] {
				return
			}
			reported[k] = true
			a.Emit(proto.Event{Type: proto.TypeRootcheck, Location: "rootcheck", Log: title + ": " + detail,
				Data: map[string]string{"check": check, "title": title, "detail": detail}})
		}
		hiddenProcesses(report)
		for _, f := range rootkitFiles {
			if fi, err := os.Lstat(f); err == nil {
				if f == "/etc/ld.so.preload" && fi.Size() == 0 {
					continue
				}
				report("rootkit_file", "Known rootkit/preload artefact present", f)
			}
		}
		ifaces, _ := filepath.Glob("/sys/class/net/*/flags")
		for _, p := range ifaces {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			v, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 64)
			if err == nil && v&0x100 != 0 {
				report("promisc", "Interface in promiscuous mode", filepath.Base(filepath.Dir(p)))
			}
		}
		for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
			filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if fi, err := d.Info(); err == nil && fi.Mode()&os.ModeSetuid != 0 {
					report("suid_tmp", "SUID file in temporary directory", p)
				}
				return nil
			})
		}
		filepath.WalkDir("/etc", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			if fi, err := d.Info(); err == nil && fi.Mode().Perm()&0o002 != 0 {
				report("world_writable", "World-writable file in /etc", p)
			}
			return nil
		})
	})
}

// hiddenProcesses compares kill(pid,0) with the /proc directory listing; a PID
// that exists but is not listed is being hidden (classic LKM/LD_PRELOAD rootkit).
func hiddenProcesses(report func(check, title, detail string)) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	listed := map[int]bool{}
	maxPID := 0
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			listed[pid] = true
			if pid > maxPID {
				maxPID = pid
			}
		}
	}
	if maxPID > 4194304 {
		maxPID = 4194304
	}
	for pid := 1; pid <= maxPID; pid++ {
		if listed[pid] || !pidAlive(pid) {
			continue
		}
		// re-check: process may have just started or exited, or be a thread
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			if _, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
				if b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); strings.Contains(string(b), "Tgid:\t"+strconv.Itoa(pid)+"\n") {
					report("hidden_process", "Process hidden from /proc listing", strconv.Itoa(pid))
				}
			}
		}
	}
}
