package installassets

import (
	"embed"
	"io/fs"
)

//go:embed install/edge-install.sh
var files embed.FS

// FS returns the embedded installer file set.
func FS() fs.FS {
	return files
}
