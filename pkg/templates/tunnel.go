package templates

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
)

//go:embed tunnel_stream.conf.tmpl
var tunnelTemplate string

// RenderTunnel writes the rendered stream config to disk.
func RenderTunnel(data TunnelTemplateData, outputPath string, templatePath string) error {
	tpl, err := loadTemplate("tunnel", tunnelTemplate, templatePath, nil)
	if err != nil {
		return fmt.Errorf("load template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
