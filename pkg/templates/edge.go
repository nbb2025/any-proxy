package templates

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"
)

//go:embed edge_nginx.conf.tmpl
var edgeTemplate string

var edgeFuncMap = template.FuncMap{
	"now":            func() time.Time { return time.Now().UTC() },
	"sslPolicyFor":   sslPolicyFor,
	"certificateFor": certificateFor,
	"hstsSeconds":    hstsSeconds,
	"tlsProtocols":   tlsProtocols,
}

// RenderEdge writes the rendered HTTP config to disk and reports whether the file changed.
func RenderEdge(data EdgeTemplateData, outputPath string, templatePath string) (bool, error) {
	tpl, err := loadTemplate("edge", edgeTemplate, templatePath, edgeFuncMap)
	if err != nil {
		return false, fmt.Errorf("load template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return false, fmt.Errorf("execute template: %w", err)
	}

	newBytes := buf.Bytes()
	existing, err := os.ReadFile(outputPath)
	if err == nil {
		if bytes.Equal(existing, newBytes) {
			return false, os.Chmod(outputPath, 0o644)
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("read output: %w", err)
	}

	if err := os.WriteFile(outputPath, newBytes, 0o644); err != nil {
		return false, fmt.Errorf("write output: %w", err)
	}
	return true, nil
}

func certificateFor(certs map[string]CertificateMaterial, accountID string) *CertificateMaterial {
	if cert, ok := certs[accountID]; ok {
		return &cert
	}
	return nil
}

func sslPolicyFor(policies []SSLPolicy, domain EdgeDomain) *SSLPolicy {
	for _, policy := range policies {
		if policy.Scope.AppliesToDomain(domain.AccountID, domain.Domain) {
			return &policy
		}
	}
	return nil
}

func hstsSeconds(d time.Duration) int64 {
	if d <= 0 {
		return int64((24 * time.Hour).Seconds())
	}
	return int64(d.Seconds())
}

func tlsProtocols(minVersion string) string {
	min := strings.TrimSpace(strings.ToLower(minVersion))
	switch min {
	case "tls1.3", "tls13":
		return "TLSv1.3"
	case "tls1.2", "tls12":
		return "TLSv1.2 TLSv1.3"
	case "tls1.1", "tls11":
		return "TLSv1.1 TLSv1.2 TLSv1.3"
	case "tls1.0", "tls10":
		return "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
	default:
		return "TLSv1.2 TLSv1.3"
	}
}
