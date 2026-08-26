// Package web carries the built React dashboard inside the API binary.
//
// Embedding it means the dashboard is one container rather than two, and the
// SPA can never be served by a build that does not match the API it talks to.
package web

import (
	"embed"
	"io/fs"
)

// dist is filled by the Docker build, which compiles dashboard/web with Vite
// and copies the output here before compiling the Go binary. A placeholder
// index.html is versioned so that `go build` also works without Node.
//
//go:embed all:dist
var dist embed.FS

// FS returns the built application, rooted at dist.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("web: " + err.Error())
	}
	return sub
}
