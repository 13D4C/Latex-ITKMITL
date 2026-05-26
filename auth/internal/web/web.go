// Package web embeds the built Svelte SPA so the runtime image only needs
// the Go binary — no separate static-file container.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var distFS embed.FS

// FS returns the dist/ directory as a usable filesystem rooted at "/".
func FS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
