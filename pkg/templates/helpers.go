package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

func loadTemplate(name, embedded, customPath string, funcMap template.FuncMap) (*template.Template, error) {
	if customPath != "" {
		return template.New(name).Funcs(funcMap).ParseFiles(customPath)
	}
	return template.New(name).Funcs(funcMap).Parse(embedded)
}

// EnsureDir ensures the parent directory exists.
func EnsureDir(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	return os.MkdirAll(filepath.Clean(path), 0o755)
}
