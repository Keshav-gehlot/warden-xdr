// Package web embeds the dashboard so the manager ships as a single binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// FS returns the dashboard files rooted at static/.
func FS() fs.FS {
	sub, _ := fs.Sub(static, "static")
	return sub
}
