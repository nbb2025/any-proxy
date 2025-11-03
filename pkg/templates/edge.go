package templates

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"text/template"
	"time"
)

//go:embed edge_nginx.conf.tmpl
var edgeTemplate string

var edgeFuncMap = template.FuncMap{
	"now": func() time.Time { return time.Now().UTC() },
}

// RenderEdge writes the rendered HTTP config to disk.
func RenderEdge(data EdgeTemplateData, outputPath string, templatePath string) error {
	tpl, err := loadTemplate("edge", edgeTemplate, templatePath, edgeFuncMap)
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
