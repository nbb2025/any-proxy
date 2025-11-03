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

// TunnelOptions controls how the tunnel agent behaves.
type TunnelOptions struct {
	ControlPlaneURL string
	NodeID          string
	OutputPath      string
	TemplatePath    string
	ReloadCommand   []string
	WatchTimeout    time.Duration
	RetryInterval   time.Duration
	Client          HTTPClient
	Logger          Logger
	DryRun          bool
}

// TunnelAgent consumes tunnel routes and renders stream configs.
type TunnelAgent struct {
	opts    TunnelOptions
	baseURL string
	client  HTTPClient
	logger  Logger
	version int64
}

// NewTunnelAgent builds a tunnel agent with sensible defaults.
func NewTunnelAgent(opts TunnelOptions) (*TunnelAgent, error) {
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

	return &TunnelAgent{
		opts:    opts,
		baseURL: baseURL,
		client:  client,
		logger:  logger,
	}, nil
}

// Run starts the watch loop for tunnel configs.
func (a *TunnelAgent) Run(ctx context.Context) error {
	a.logger.Printf("[tunnel] starting watch loop node=%s controlPlane=%s", a.opts.NodeID, a.baseURL)

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("[tunnel] context closed, stopping: %v", ctx.Err())
			return ctx.Err()
		default:
		}

		snap, changed, err := a.fetchSnapshot(ctx, a.version)
		if err != nil {
			a.logger.Printf("[tunnel] fetch snapshot error: %v", err)
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
			a.logger.Printf("[tunnel] apply snapshot error: %v", err)
			select {
			case <-time.After(a.opts.RetryInterval):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (a *TunnelAgent) fetchSnapshot(ctx context.Context, since int64) (configstore.ConfigSnapshot, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, a.opts.WatchTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/v1/config/snapshot?since=%d", a.baseURL, since)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return configstore.ConfigSnapshot{}, false, fmt.Errorf("build request: %w", err)
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

func (a *TunnelAgent) applySnapshot(ctx context.Context, snap configstore.ConfigSnapshot) error {
	data := transformTunnelSnapshot(snap, a.opts.NodeID)
	data.GeneratedAt = time.Now().UTC()
	data.NodeID = a.opts.NodeID
	data.Version = snap.Version

	if err := templates.RenderTunnel(data, a.opts.OutputPath, a.opts.TemplatePath); err != nil {
		return fmt.Errorf("render tunnel template: %w", err)
	}

	if a.opts.DryRun {
		a.logger.Printf("[tunnel] dry-run: skip reload")
		return nil
	}

	if len(a.opts.ReloadCommand) > 0 {
		if err := runCommand(ctx, a.opts.ReloadCommand, a.logger); err != nil {
			return fmt.Errorf("reload command failed: %w", err)
		}
		a.logger.Printf("[tunnel] reloaded via %s", strings.Join(a.opts.ReloadCommand, " "))
	}
	return nil
}

func transformTunnelSnapshot(snap configstore.ConfigSnapshot, nodeID string) templates.TunnelTemplateData {
	out := templates.TunnelTemplateData{
		NodeID: nodeID,
	}

	for _, route := range snap.Tunnels {
		if !routeAssigned(route.NodeIDs, nodeID) {
			continue
		}

		name := makeIdentifier("tunnel", route.ID, fmt.Sprintf("%s%d", route.BindHost, route.BindPort))
		listen := fmt.Sprintf("%s:%d", route.BindHost, route.BindPort)

		out.Routes = append(out.Routes, templates.TunnelRoute{
			Name:             name,
			Protocol:         route.Protocol,
			ListenAddress:    listen,
			IdleTimeout:      formatDuration(route.IdleTimeout),
			TargetAddress:    route.Target,
			EnableProxyProto: route.Metadata.EnableProxyProtocol,
		})
	}

	return out
}
