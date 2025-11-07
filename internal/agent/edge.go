package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"anyproxy.dev/any-proxy/internal/configstore"
	tserver "anyproxy.dev/any-proxy/internal/tunnel/server"
	"anyproxy.dev/any-proxy/pkg/templates"
)

// EdgeOptions describes configuration for the edge agent.
type EdgeOptions struct {
	ControlPlaneURL      string
	NodeID               string
	OutputPath           string
	StreamOutputPath     string
	StreamTemplatePath   string
	CertificateDir       string
	ClientCADir          string
	TemplatePath         string
	HAProxyReloadCommand []string
	AuthToken            string
	GroupID              string
	NodeName             string
	NodeCategory         string
	ReloadCommand        []string
	WatchTimeout         time.Duration
	RetryInterval        time.Duration
	Client               HTTPClient
	Logger               Logger
	DryRun               bool
}

// EdgeAgent watches the control plane for domain updates and renders nginx config.
type EdgeAgent struct {
	opts         EdgeOptions
	baseURL      string
	client       HTTPClient
	logger       Logger
	version      int64
	groupID      string
	nodeName     string
	nodeCategory string
	lastReg      time.Time
	tunnelMgr    *tunnelServerManager
}

const edgeRegisterInterval = time.Minute

type nodeRegisterRequest struct {
	NodeID    string   `json:"nodeId"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name,omitempty"`
	Category  string   `json:"category,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Version   string   `json:"version,omitempty"`
	GroupID   string   `json:"groupId,omitempty"`
}

type nodeRegisterResponse struct {
	Node configstore.EdgeNode `json:"node"`
}

// NewEdgeAgent prepares an edge agent with sane defaults.
func NewEdgeAgent(opts EdgeOptions) (*EdgeAgent, error) {
	opts.NodeID = strings.TrimSpace(opts.NodeID)
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

	outputDir := filepath.Dir(opts.OutputPath)
	if err := templates.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("ensure output dir: %w", err)
	}
	if strings.TrimSpace(opts.CertificateDir) == "" {
		opts.CertificateDir = filepath.Join(outputDir, "certs")
	}
	if err := templates.EnsureDir(opts.CertificateDir); err != nil {
		return nil, fmt.Errorf("ensure certificate dir: %w", err)
	}
	if strings.TrimSpace(opts.ClientCADir) == "" {
		opts.ClientCADir = opts.CertificateDir
	}
	if err := templates.EnsureDir(opts.ClientCADir); err != nil {
		return nil, fmt.Errorf("ensure client CA dir: %w", err)
	}

	category := strings.ToLower(strings.TrimSpace(opts.NodeCategory))

	return &EdgeAgent{
		opts:         opts,
		baseURL:      baseURL,
		client:       client,
		logger:       logger,
		groupID:      strings.TrimSpace(opts.GroupID),
		nodeName:     strings.TrimSpace(opts.NodeName),
		nodeCategory: category,
		tunnelMgr:    newTunnelServerManager(logger),
	}, nil
}

// Run starts the watch loop.
func (a *EdgeAgent) Run(ctx context.Context) error {
	a.logger.Printf("[edge] starting watch loop node=%s controlPlane=%s", a.opts.NodeID, a.baseURL)

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("[edge] context closed, stopping: %v", ctx.Err())
			a.tunnelMgr.Stop()
			return ctx.Err()
		default:
		}

		if err := a.maybeRegister(ctx); err != nil {
			a.logger.Printf("[edge] node register failed: %v", err)
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
	certMaterials, clientCAPaths, err := a.materialiseCertificates(snap.Certificates)
	if err != nil {
		return fmt.Errorf("materialise certificates: %w", err)
	}

	data := transformEdgeSnapshot(snap, a.opts.NodeID, certMaterials, clientCAPaths)
	if len(data.Domains) == 0 {
		a.logger.Printf("[edge] no domains assigned to node %s, writing placeholder", a.opts.NodeID)
	}
	data.GeneratedAt = time.Now().UTC()
	data.NodeID = a.opts.NodeID
	data.Version = snap.Version
	if group := lookupNodeGroup(snap.Nodes, a.opts.NodeID); group != "" {
		a.groupID = group
	}

	if err := templates.RenderEdge(data, a.opts.OutputPath, a.opts.TemplatePath); err != nil {
		return fmt.Errorf("render edge template: %w", err)
	}

	var haproxyChanged bool
	if strings.TrimSpace(a.opts.StreamOutputPath) != "" {
		haproxyData := transformHAProxySnapshot(snap, a.opts.NodeID)
		haproxyData.GeneratedAt = time.Now().UTC()
		haproxyData.NodeID = a.opts.NodeID
		haproxyData.Version = snap.Version
		changed, err := templates.RenderHAProxy(haproxyData, a.opts.StreamOutputPath, a.opts.StreamTemplatePath)
		if err != nil {
			return fmt.Errorf("render haproxy template: %w", err)
		}
		haproxyChanged = changed
	}

	tunnelPlan := planTunnelServers(snap, a.opts.NodeID)
	if err := a.tunnelMgr.Update(ctx, tunnelPlan); err != nil {
		a.logger.Printf("[edge] tunnel server update error: %v", err)
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
	if haproxyChanged && len(a.opts.HAProxyReloadCommand) > 0 {
		if err := runCommand(ctx, a.opts.HAProxyReloadCommand, a.logger); err != nil {
			return fmt.Errorf("haproxy reload failed: %w", err)
		}
		a.logger.Printf("[edge] haproxy reloaded via %s", strings.Join(a.opts.HAProxyReloadCommand, " "))
	}
	return nil
}

func (a *EdgeAgent) materialiseCertificates(certs []configstore.Certificate) (map[string]templates.CertificateMaterial, map[string]string, error) {
	certMaterials := make(map[string]templates.CertificateMaterial)
	clientCAs := make(map[string]string)
	usedNames := make(map[string]int)

	for idx, cert := range certs {
		base := sanitizeID(cert.ID)
		if base == "default" || base == "" {
			base = sanitizeID(cert.Name)
		}
		if base == "default" || base == "" {
			base = fmt.Sprintf("cert%d", idx+1)
		}
		name := makeUniqueName(base, usedNames)

		pem := strings.TrimSpace(cert.PEM)
		key := strings.TrimSpace(cert.PrivateKey)

		if pem == "" && key == "" {
			continue
		}
		if pem == "" {
			a.logger.Printf("[edge] certificate id=%s name=%s missing PEM, skipping materialisation", cert.ID, cert.Name)
			continue
		}

		pemBytes := []byte(pem + "\n")

		certPath := filepath.Join(a.opts.CertificateDir, name+".crt")
		if err := writeFileIfChanged(certPath, pemBytes, 0o644); err != nil {
			return nil, nil, fmt.Errorf("write certificate %s: %w", cert.ID, err)
		}

		caPath := certPath
		if filepath.Clean(a.opts.ClientCADir) != filepath.Clean(a.opts.CertificateDir) {
			caPath = filepath.Join(a.opts.ClientCADir, name+".pem")
			if err := writeFileIfChanged(caPath, pemBytes, 0o644); err != nil {
				return nil, nil, fmt.Errorf("write client CA %s: %w", cert.ID, err)
			}
		}
		clientCAs[cert.ID] = caPath

		if key != "" {
			keyPath := filepath.Join(a.opts.CertificateDir, name+".key")
			if err := writeFileIfChanged(keyPath, []byte(key+"\n"), 0o600); err != nil {
				return nil, nil, fmt.Errorf("write private key %s: %w", cert.ID, err)
			}
			certMaterials[cert.ID] = templates.CertificateMaterial{
				CertificatePath: certPath,
				KeyPath:         keyPath,
			}
		} else {
			if !cert.Managed {
				a.logger.Printf("[edge] certificate id=%s name=%s missing private key, cannot be used for TLS termination", cert.ID, cert.Name)
			}
		}
	}

	return certMaterials, clientCAs, nil
}

func transformEdgeSnapshot(snap configstore.ConfigSnapshot, nodeID string, certMaterials map[string]templates.CertificateMaterial, clientCAs map[string]string) templates.EdgeTemplateData {
	out := templates.EdgeTemplateData{
		NodeID:       nodeID,
		Version:      snap.Version,
		Certificates: make(map[string]templates.CertificateMaterial),
	}

	domainIndex := make(map[string]configstore.DomainRoute)
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
		domainIndex[route.ID] = route
	}

	if len(domainIndex) == 0 {
		return out
	}

	for _, policy := range snap.SSLPolicies {
		tplPolicy := templates.SSLPolicy{
			ID:                    policy.ID,
			Name:                  policy.Name,
			Description:           policy.Description,
			Scope:                 toTemplateScope(policy.Scope),
			EnforceHTTPS:          policy.EnforceHTTPS,
			EnableHSTS:            policy.EnableHSTS,
			HSTSMaxAge:            policy.HSTSMaxAge,
			HSTSIncludeSubdomains: policy.HSTSIncludeSubdomains,
			HSTSPreload:           policy.HSTSPreload,
			MinTLSVersion:         policy.MinTLSVersion,
			EnableOCSPStapling:    policy.EnableOCSPStapling,
			ClientAuth:            policy.ClientAuth,
		}

		matched := false
		for domainID, route := range domainIndex {
			if tplPolicy.Scope.AppliesToDomain(domainID, route.Domain) {
				matched = true
				if policy.CertificateID != "" {
					if material, ok := certMaterials[policy.CertificateID]; ok {
						if _, exists := out.Certificates[domainID]; !exists {
							out.Certificates[domainID] = material
						}
					}
				}
			}
		}
		if !matched {
			continue
		}

		if len(policy.ClientCAIDs) > 0 {
			caPaths := make([]string, 0, len(policy.ClientCAIDs))
			for _, caID := range policy.ClientCAIDs {
				if caPath, ok := clientCAs[caID]; ok {
					caPaths = append(caPaths, caPath)
				}
			}
			tplPolicy.ClientCAPaths = caPaths
		}

		out.SSLPolicies = append(out.SSLPolicies, tplPolicy)
	}

	for _, policy := range snap.AccessPolicies {
		scope := toTemplateScope(policy.Scope)
		matched := false
		for domainID, route := range domainIndex {
			if scope.AppliesToDomain(domainID, route.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		access := templates.AccessPolicy{
			ID:           policy.ID,
			Name:         policy.Name,
			Description:  policy.Description,
			Scope:        scope,
			Action:       string(policy.Action),
			ResponseCode: policy.ResponseCode,
			RedirectURL:  policy.RedirectURL,
		}
		if strings.EqualFold(policy.Condition.Mode, "matchers") {
			access.Matchers = toTemplateMatchers(policy.Condition.Matchers)
		}
		out.AccessPolicies = append(out.AccessPolicies, access)
	}

	for _, rule := range snap.RewriteRules {
		scope := toTemplateScope(rule.Scope)
		matched := false
		for domainID, route := range domainIndex {
			if scope.AppliesToDomain(domainID, route.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		rewrite := templates.RewriteRule{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Scope:       scope,
			Actions:     toTemplateRewriteActions(rule.Actions),
			Priority:    rule.Priority,
		}
		if strings.EqualFold(rule.Condition.Mode, "matchers") {
			rewrite.Matchers = toTemplateMatchers(rule.Condition.Matchers)
		}
		out.RewriteRules = append(out.RewriteRules, rewrite)
	}

	return out
}

func transformHAProxySnapshot(snap configstore.ConfigSnapshot, nodeID string) templates.HAProxyTemplateData {
	data := templates.HAProxyTemplateData{
		NodeID: nodeID,
	}
	for _, route := range snap.Tunnels {
		if !routeAssigned(route.NodeIDs, nodeID) {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(route.Protocol))
		if mode != "udp" {
			mode = "tcp"
		}
		bindHost := route.BindHost
		if strings.TrimSpace(bindHost) == "" {
			bindHost = "0.0.0.0"
		}
		name := makeIdentifier("haproxy", route.ID, fmt.Sprintf("%s%d", bindHost, route.BindPort))
		data.Routes = append(data.Routes, templates.HAProxyRoute{
			Name:                name,
			Mode:                mode,
			BindAddress:         fmt.Sprintf("%s:%d", bindHost, route.BindPort),
			TargetAddress:       route.Target,
			IdleTimeout:         formatDuration(route.IdleTimeout),
			EnableProxyProtocol: route.Metadata.EnableProxyProtocol,
		})
	}
	return data
}

func planTunnelServers(snap configstore.ConfigSnapshot, nodeID string) map[string]map[string]tserver.SessionInfo {
	plan := make(map[string]map[string]tserver.SessionInfo)
	if nodeID == "" {
		return plan
	}
	for _, group := range snap.TunnelGroups {
		if !containsString(group.EdgeNodeIDs, nodeID) {
			continue
		}
		addr := strings.TrimSpace(group.ListenAddress)
		if addr == "" {
			addr = ":4433"
		}
		keyMap := plan[addr]
		if keyMap == nil {
			keyMap = make(map[string]tserver.SessionInfo)
			plan[addr] = keyMap
		}
		for _, agent := range snap.TunnelAgents {
			if agent.GroupID != group.ID || !agent.Enabled {
				continue
			}
			hash := strings.TrimSpace(agent.KeyHash)
			if hash == "" {
				continue
			}
			keyMap[hash] = tserver.SessionInfo{
				AgentID: agent.ID,
				NodeID:  agent.NodeID,
				GroupID: agent.GroupID,
			}
		}
	}
	return plan
}

func containsString(list []string, needle string) bool {
	for _, v := range list {
		if v == needle {
			return true
		}
	}
	return false
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

func lookupNodeGroup(nodes []configstore.EdgeNode, nodeID string) string {
	for _, node := range nodes {
		if node.ID == nodeID {
			return node.GroupID
		}
	}
	return ""
}

func (a *EdgeAgent) maybeRegister(ctx context.Context) error {
	if time.Since(a.lastReg) < edgeRegisterInterval {
		return nil
	}
	if err := a.registerNode(ctx); err != nil {
		return err
	}
	a.lastReg = time.Now()
	return nil
}

func (a *EdgeAgent) registerNode(ctx context.Context) error {
	hostname, _ := os.Hostname()
	ips := gatherLocalIPs()

	payload := nodeRegisterRequest{
		NodeID:    a.opts.NodeID,
		Kind:      "edge",
		Hostname:  hostname,
		Addresses: ips,
		Version:   runtime.Version(),
	}
	if grp := strings.TrimSpace(a.groupID); grp != "" {
		payload.GroupID = grp
	}
	if name := strings.TrimSpace(a.nodeName); name != "" {
		payload.Name = name
	}
	if cat := strings.TrimSpace(a.nodeCategory); cat != "" {
		payload.Category = strings.ToLower(cat)
	}
	if a.groupID != "" {
		payload.GroupID = a.groupID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal register payload: %w", err)
	}

	url := fmt.Sprintf("%s/v1/nodes/register", a.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(a.opts.AuthToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("register request status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out nodeRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}

	if out.Node.GroupID != "" {
		a.groupID = out.Node.GroupID
	}
	if strings.TrimSpace(out.Node.Name) != "" {
		a.nodeName = out.Node.Name
	}
	if cat := strings.TrimSpace(string(out.Node.Category)); cat != "" {
		a.nodeCategory = strings.ToLower(cat)
	}
	a.logger.Printf("[edge] registered node=%s group=%s addrs=%v", a.opts.NodeID, a.groupID, ips)
	return nil
}

func gatherLocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			ips = append(ips, ip.String())
		}
	}

	sort.Strings(ips)
	return uniqueStrings(ips)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func toTemplateScope(scope configstore.PolicyScope) templates.PolicyScope {
	return templates.PolicyScope{
		Mode:      scope.Mode,
		Resources: append([]string(nil), scope.Resources...),
		Tags:      append([]string(nil), scope.Tags...),
	}
}

func toTemplateMatchers(matchers []configstore.Matcher) []templates.Matcher {
	if len(matchers) == 0 {
		return nil
	}
	out := make([]templates.Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		out = append(out, templates.Matcher{
			Type:     matcher.Type,
			Key:      matcher.Key,
			Operator: matcher.Operator,
			Values:   append([]string(nil), matcher.Values...),
		})
	}
	return out
}

func toTemplateRewriteActions(actions configstore.RewriteActions) templates.RewriteActions {
	result := templates.RewriteActions{
		SNIOverride:  actions.SNIOverride,
		HostOverride: actions.HostOverride,
	}
	if actions.URL != (configstore.URLRewrite{}) {
		result.URL = templates.URLRewrite{
			Mode:  actions.URL.Mode,
			Path:  actions.URL.Path,
			Query: actions.URL.Query,
		}
	}
	if len(actions.Headers) > 0 {
		headers := make([]templates.HeaderMutation, 0, len(actions.Headers))
		for _, h := range actions.Headers {
			headers = append(headers, templates.HeaderMutation{
				Operation: h.Operation,
				Name:      h.Name,
				Value:     h.Value,
			})
		}
		result.Headers = headers
	}
	if actions.Upstream != nil {
		result.Upstream = &templates.UpstreamOverride{
			PassHostHeader: actions.Upstream.PassHostHeader,
			UpstreamHost:   actions.Upstream.UpstreamHost,
			Scheme:         actions.Upstream.Scheme,
			ConnectTimeout: actions.Upstream.ConnectTimeout,
			ReadTimeout:    actions.Upstream.ReadTimeout,
			SendTimeout:    actions.Upstream.SendTimeout,
		}
	}
	return result
}

func makeUniqueName(base string, used map[string]int) string {
	name := base
	if name == "" {
		name = "cert"
	}
	if count, ok := used[name]; ok {
		count++
		used[name] = count
		return fmt.Sprintf("%s_%d", name, count)
	}
	used[name] = 0
	return name
}

func writeFileIfChanged(path string, data []byte, perm fs.FileMode) error {
	existing, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(existing, data) {
			return os.Chmod(path, perm)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeFileAtomic(path, data, perm)
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}

	return os.Chmod(path, perm)
}
