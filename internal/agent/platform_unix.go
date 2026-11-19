//go:build linux || darwin || freebsd

package agent

import (
	"io/fs"
	"strconv"
	"syscall"
)

func fileOwner(fi fs.FileInfo) (string, string) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10), strconv.FormatUint(uint64(st.Gid), 10)
	}
	return "", ""
}

func fileIdent(fi fs.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10)
	}
	return ""
}

// pidAlive reports whether a PID exists, using kill(pid, 0).
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func killPID(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
