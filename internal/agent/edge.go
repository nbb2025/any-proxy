package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"anyproxy.dev/any-proxy/internal/configstore"
	"anyproxy.dev/any-proxy/pkg/templates"
)

// EdgeOptions describes configuration for the edge agent.
type EdgeOptions struct {
	ControlPlaneURL string
	NodeID          string
	OutputPath      string
	TemplatePath    string
	AuthToken       string
	ReloadCommand   []string
	WatchTimeout    time.Duration
	RetryInterval   time.Duration
	Client          HTTPClient
	Logger          Logger
	DryRun          bool
}

// EdgeAgent watches the control plane for domain updates and renders nginx config.
type EdgeAgent struct {
	opts    EdgeOptions
	baseURL string
	client  HTTPClient
	logger  Logger
	version int64
}

// NewEdgeAgent prepares an edge agent with sane defaults.
func NewEdgeAgent(opts EdgeOptions) (*EdgeAgent, error) {
	if opts.NodeID == "" {
		return nil, fmt.Errorf("node id is required")
	}
	if opts.OutputPath == "" {
		return nil, fmt.Errorf("output path is required")
	}

	baseURL, err := normalizeBaseURL(opts.ControlPlaneURL)
	if err != nil {
		return nil, err
	}

	logger := opts.Logger
	if logger == nil {
		logger = noopLogger{}
	}

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: defaultDuration(opts.WatchTimeout, 60*time.Second) + 5*time.Second}
	}

	opts.WatchTimeout = defaultDuration(opts.WatchTimeout, 55*time.Second)
	opts.RetryInterval = defaultDuration(opts.RetryInterval, 5*time.Second)

	if err := templates.EnsureDir(filepath.Dir(opts.OutputPath)); err != nil {
		return nil, fmt.Errorf("ensure output dir: %w", err)
	}

	return &EdgeAgent{
		opts:    opts,
		baseURL: baseURL,
		client:  client,
		logger:  logger,
	}, nil
}

// Run starts the watch loop.
func (a *EdgeAgent) Run(ctx context.Context) error {
	a.logger.Printf("[edge] starting watch loop node=%s controlPlane=%s", a.opts.NodeID, a.baseURL)

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("[edge] context closed, stopping: %v", ctx.Err())
			return ctx.Err()
		default:
		}

		snap, changed, err := a.fetchSnapshot(ctx, a.version)
		if err != nil {
			a.logger.Printf("[edge] fetch snapshot error: %v", err)
			select {
			case <-time.After(a.opts.RetryInterval):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if !changed {
			continue
		}
		a.version = snap.Version

		if err := a.applySnapshot(ctx, snap); err != nil {
			a.logger.Printf("[edge] apply snapshot error: %v", err)
			select {
			case <-time.After(a.opts.RetryInterval):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (a *EdgeAgent) fetchSnapshot(ctx context.Context, since int64) (configstore.ConfigSnapshot, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, a.opts.WatchTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/v1/config/snapshot?since=%d", a.baseURL, since)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return configstore.ConfigSnapshot{}, false, fmt.Errorf("build request: %w", err)
	}
	if token := strings.TrimSpace(a.opts.AuthToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return configstore.ConfigSnapshot{}, false, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return configstore.ConfigSnapshot{}, false, fmt.Errorf("read body: %w", err)
		}
		var snap configstore.ConfigSnapshot
		if err := json.Unmarshal(body, &snap); err != nil {
			return configstore.ConfigSnapshot{}, false, fmt.Errorf("decode body: %w", err)
		}
		return snap, true, nil
	case http.StatusNotModified:
		return configstore.ConfigSnapshot{}, false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return configstore.ConfigSnapshot{}, false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func (a *EdgeAgent) applySnapshot(ctx context.Context, snap configstore.ConfigSnapshot) error {
	data := transformEdgeSnapshot(snap, a.opts.NodeID)
	if len(data.Domains) == 0 {
		a.logger.Printf("[edge] no domains assigned to node %s, writing placeholder", a.opts.NodeID)
	}
	data.GeneratedAt = time.Now().UTC()
	data.NodeID = a.opts.NodeID
	data.Version = snap.Version

	if err := templates.RenderEdge(data, a.opts.OutputPath, a.opts.TemplatePath); err != nil {
		return fmt.Errorf("render edge template: %w", err)
	}

	if a.opts.DryRun {
		a.logger.Printf("[edge] dry-run: skip reload")
		return nil
	}

	if len(a.opts.ReloadCommand) > 0 {
		if err := runCommand(ctx, a.opts.ReloadCommand, a.logger); err != nil {
			return fmt.Errorf("reload command failed: %w", err)
		}
		a.logger.Printf("[edge] reloaded via %s", strings.Join(a.opts.ReloadCommand, " "))
	}
	return nil
}

func transformEdgeSnapshot(snap configstore.ConfigSnapshot, nodeID string) templates.EdgeTemplateData {
	out := templates.EdgeTemplateData{
		NodeID:  nodeID,
		Version: snap.Version,
	}

	for _, route := range snap.Domains {
		if !routeAssigned(route.EdgeNodes, nodeID) {
			continue
		}

		upstreamName := makeIdentifier("upstream", route.ID, route.Domain)

		var enablePersist bool
		upstreams := make([]templates.EdgeUpstream, 0, len(route.Upstreams))
		for _, ups := range route.Upstreams {
			if ups.UsePersistent {
				enablePersist = true
			}
			upstreams = append(upstreams, templates.EdgeUpstream{
				Address:       ups.Address,
				Weight:        ups.Weight,
				MaxFails:      ups.MaxFails,
				FailTimeout:   formatDuration(ups.FailTimeout),
				UsePersistent: ups.UsePersistent,
				HealthCheck:   ups.HealthCheck,
			})
		}

		out.Domains = append(out.Domains, templates.EdgeDomain{
			Domain:        route.Domain,
			EnableTLS:     route.EnableTLS,
			AccountID:     route.ID,
			UpstreamName:  upstreamName,
			Sticky:        route.Metadata.Sticky,
			ProxyTimeout:  formatDuration(route.Metadata.TimeoutProxy),
			ReadTimeout:   formatDuration(route.Metadata.TimeoutRead),
			SendTimeout:   formatDuration(route.Metadata.TimeoutSend),
			EnablePersist: enablePersist,
			Upstreams:     upstreams,
		})
	}

	return out
}

func routeAssigned(assignments []string, nodeID string) bool {
	if len(assignments) == 0 {
		return true
	}
	for _, id := range assignments {
		if id == nodeID {
			return true
		}
	}
	return false
}

func makeIdentifier(prefix, id, fallback string) string {
	if id != "" {
		if ident := sanitizeID(id); ident != "" {
			return fmt.Sprintf("%s_%s", prefix, ident)
		}
	}
	return fmt.Sprintf("%s_%s", prefix, sanitizeID(fallback))
}

func sanitizeID(v string) string {
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return strings.ToLower(b.String())
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}
