//go:build !(linux || darwin || freebsd)

package agent

import (
	"errors"
	"io/fs"
)

func fileOwner(fi fs.FileInfo) (string, string) { return "", "" }

func fileIdent(fi fs.FileInfo) string { return fi.ModTime().String() }

func pidAlive(pid int) bool { return false }

func killPID(pid int) error { return errors.New("kill-process not supported on this platform") }
