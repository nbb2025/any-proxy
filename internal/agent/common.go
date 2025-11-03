package agent

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Logger is the minimal logging interface shared by agents.
type Logger interface {
	Printf(format string, v ...any)
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}

// HTTPClient is satisfied by *http.Client and enables injection during tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func normalizeBaseURL(base string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("control plane url can not be empty")
	}
	base = strings.TrimSuffix(base, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return "", fmt.Errorf("control plane url must include scheme (http/https)")
	}
	return base, nil
}

func defaultDuration(val, fallback time.Duration) time.Duration {
	if val <= 0 {
		return fallback
	}
	return val
}
