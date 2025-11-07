package templates

import (
	"bytes"
	_ "embed"
	"os"
)

//go:embed haproxy.cfg.tmpl
var haproxyTemplate string

// RenderHAProxy writes HAProxy config and reports whether the file changed.
func RenderHAProxy(data HAProxyTemplateData, outputPath, templatePath string) (bool, error) {
	tpl, err := loadTemplate("haproxy", haproxyTemplate, templatePath, nil)
	if err != nil {
		return false, err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return false, err
	}

	newBytes := buf.Bytes()
	existing, err := os.ReadFile(outputPath)
	if err == nil {
		if bytes.Equal(existing, newBytes) {
			return false, os.Chmod(outputPath, 0o644)
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}

	if err := os.WriteFile(outputPath, newBytes, 0o644); err != nil {
		return false, err
	}
	return true, nil
}
