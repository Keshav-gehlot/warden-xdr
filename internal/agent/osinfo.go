package agent

import (
	"bufio"
	"os"
	"runtime"
	"strings"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// OSInfo reads /etc/os-release and the kernel version.
func OSInfo() proto.OSInfo {
	h, _ := os.Hostname()
	info := proto.OSInfo{Platform: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, Name: runtime.GOOS}
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "NAME":
				info.Name = v
			case "ID":
				info.ID = v
			case "VERSION_ID":
				info.Version = v
			case "VERSION_CODENAME":
				info.Codename = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	return info
}
