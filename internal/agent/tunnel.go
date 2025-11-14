package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"anyproxy.dev/any-proxy/internal/configstore"
	tclient "anyproxy.dev/any-proxy/internal/tunnel/client"
)

// TunnelOptions controls how the tunnel agent behaves.
type TunnelOptions struct {
	ControlPlaneURL string
	NodeID          string
	AgentKey        string
	AgentKeyPath    string
	GroupID         string
	EdgeCandidates  []string
	WatchTimeout    time.Duration
	RetryInterval   time.Duration
	Client          HTTPClient
	Logger          Logger
}

// TunnelAgent watches the control plane for tunnel-agent config and runs the client.
type TunnelAgent struct {
	opts    TunnelOptions
	baseURL string
	client  HTTPClient
	logger  Logger
	version int64
	key     string
	running context.CancelFunc
	current *tclient.Options
}

// NewTunnelAgent builds a tunnel agent with sensible defaults.
func NewTunnelAgent(opts TunnelOptions) (*TunnelAgent, error) {
	if strings.TrimSpace(opts.NodeID) == "" {
		return nil, fmt.Errorf("node id is required")
	}
	baseURL, err := normalizeBaseURL(opts.ControlPlaneURL)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(opts.AgentKey)
	if key == "" && strings.TrimSpace(opts.AgentKeyPath) != "" {
		loaded, loadErr := readSecretFile(opts.AgentKeyPath)
		if loadErr != nil {
			return nil, fmt.Errorf("read agent key: %w", loadErr)
		}
		key = loaded
	}
	if key == "" {
		return nil, fmt.Errorf("agent key is required")
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
	return &TunnelAgent{
		opts:    opts,
		baseURL: baseURL,
		client:  client,
		logger:  logger,
		key:     key,
	}, nil
}

// Run starts the watch loop for tunnel configs.
func (a *TunnelAgent) Run(ctx context.Context) error {
	a.logger.Printf("[tunnel] starting watch loop node=%s controlPlane=%s", a.opts.NodeID, a.baseURL)
	for {
		select {
		case <-ctx.Done():
			a.stopClient()
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
				a.stopClient()
				return ctx.Err()
			}
		}
		if !changed {
			continue
		}
		a.version = snap.Version
		if err := a.applySnapshot(ctx, snap); err != nil {
			a.logger.Printf("[tunnel] apply snapshot error: %v", err)
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
	cfg, err := a.buildClientOptions(snap)
	if err != nil {
		if errors.Is(err, errAgentNotFound) {
			a.logger.Printf("[tunnel] agent definition not found for node=%s", a.opts.NodeID)
			a.stopClient()
			return nil
		}
		return err
	}
	if cfg == nil {
		return nil
	}
	if a.current != nil && clientOptionsEqual(*cfg, *a.current) {
		return nil
	}
	if err := a.startClient(ctx, *cfg); err != nil {
		return fmt.Errorf("start client: %w", err)
	}
	return nil
}

func (a *TunnelAgent) startClient(ctx context.Context, cfg tclient.Options) error {
	cli, err := tclient.New(cfg)
	if err != nil {
		return err
	}
	a.stopClient()
	childCtx, cancel := context.WithCancel(ctx)
	a.running = cancel
	optionsCopy := cfg
	a.current = &optionsCopy
	go func() {
		if err := cli.Run(childCtx); err != nil && !errors.Is(err, context.Canceled) {
			a.logger.Printf("[tunnel] client stopped err=%v", err)
		}
	}()
	return nil
}

func (a *TunnelAgent) stopClient() {
	if a.running != nil {
		a.running()
		a.running = nil
	}
	a.current = nil
}

func (a *TunnelAgent) buildClientOptions(snap configstore.ConfigSnapshot) (*tclient.Options, error) {
	agent := findTunnelAgentByNodeID(snap, a.opts.NodeID)
	if agent == nil {
		return nil, errAgentNotFound
	}
	if !agent.Enabled {
		a.logger.Printf("[tunnel] agent id=%s disabled", agent.ID)
		a.stopClient()
		return nil, nil
	}
	groupID := strings.TrimSpace(a.opts.GroupID)
	if groupID == "" {
		groupID = strings.TrimSpace(agent.GroupID)
	}
	if groupID == "" {
		return nil, fmt.Errorf("group id missing for agent %s", agent.ID)
	}
	services := make([]tclient.ServiceConfig, 0, len(agent.Services))
	for _, svc := range agent.Services {
		services = append(services, tclient.ServiceConfig{
			ID:           svc.ID,
			Protocol:     svc.Protocol,
			LocalAddress: svc.LocalAddress,
			LocalPort:    svc.LocalPort,
		})
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("agent %s has no services", agent.ID)
	}
	edges := dedupeStrings(a.opts.EdgeCandidates)
	if len(edges) == 0 {
		derived, err := deriveEdgeCandidates(groupID, snap)
		if err != nil {
			return nil, err
		}
		edges = derived
	}
	if len(edges) == 0 {
		return nil, fmt.Errorf("no edge candidates available")
	}
	return &tclient.Options{
		NodeID:            a.opts.NodeID,
		Key:               a.key,
		GroupID:           groupID,
		EdgeCandidates:    edges,
		Services:          services,
		Logger:            a.logger,
		DialTimeout:       5 * time.Second,
		HeartbeatInterval: 15 * time.Second,
		ReconnectDelay:    a.opts.RetryInterval,
	}, nil
}

func clientOptionsEqual(a, b tclient.Options) bool {
	if a.GroupID != b.GroupID {
		return false
	}
	if len(a.EdgeCandidates) != len(b.EdgeCandidates) {
		return false
	}
	left := append([]string(nil), a.EdgeCandidates...)
	right := append([]string(nil), b.EdgeCandidates...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	if len(a.Services) != len(b.Services) {
		return false
	}
	serviceIndex := make(map[string]tclient.ServiceConfig, len(a.Services))
	for _, svc := range a.Services {
		serviceIndex[svc.ID] = svc
	}
	for _, svc := range b.Services {
		ref, ok := serviceIndex[svc.ID]
		if !ok {
			return false
		}
		if ref.LocalAddress != svc.LocalAddress || ref.LocalPort != svc.LocalPort || ref.Protocol != svc.Protocol {
			return false
		}
	}
	return true
}

func deriveEdgeCandidates(groupID string, snap configstore.ConfigSnapshot) ([]string, error) {
	group := findTunnelGroupByID(snap, groupID)
	if group == nil {
		return nil, fmt.Errorf("tunnel group %s not found", groupID)
	}
	listenAddr := strings.TrimSpace(group.ListenAddress)
	if listenAddr == "" {
		listenAddr = ":4433"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %s: %w", listenAddr, err)
	}
	var candidates []string
	if host != "" && host != "0.0.0.0" && host != "::" {
		candidates = append(candidates, fmt.Sprintf("%s:%s", host, port))
		return candidates, nil
	}
	for _, nodeID := range group.EdgeNodeIDs {
		node := findNodeByID(snap, nodeID)
		if node == nil {
			continue
		}
		for _, addr := range node.Addresses {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			candidates = append(candidates, fmt.Sprintf("%s:%s", addr, port))
		}
	}
	return dedupeStrings(candidates), nil
}

func findTunnelAgentByNodeID(snap configstore.ConfigSnapshot, nodeID string) *configstore.TunnelAgent {
	for i := range snap.TunnelAgents {
		if snap.TunnelAgents[i].NodeID == nodeID {
			return &snap.TunnelAgents[i]
		}
	}
	return nil
}

func findTunnelGroupByID(snap configstore.ConfigSnapshot, id string) *configstore.TunnelGroup {
	for i := range snap.TunnelGroups {
		if snap.TunnelGroups[i].ID == id {
			return &snap.TunnelGroups[i]
		}
	}
	return nil
}

func findNodeByID(snap configstore.ConfigSnapshot, id string) *configstore.EdgeNode {
	for i := range snap.Nodes {
		if snap.Nodes[i].ID == id {
			return &snap.Nodes[i]
		}
	}
	return nil
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

var errAgentNotFound = errors.New("tunnel agent not found")

func dedupeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		result = append(result, val)
	}
	return result
}
