package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
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
	CertificateDir  string
	ClientCADir     string
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
