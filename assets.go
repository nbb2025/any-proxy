package installassets

import (
	"embed"
	"io/fs"
)

//go:embed install/edge-install.sh install/edge-uninstall.sh install/edgectl.sh
var files embed.FS

// FS returns the embedded installer file set.
func FS() fs.FS {
	return files
}
