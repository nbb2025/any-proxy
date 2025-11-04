package configstore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Store defines behaviours common to config backends.
type Store interface {
	Snapshot(ctx context.Context) (ConfigSnapshot, error)
	Watch(ctx context.Context, since int64) (ConfigSnapshot, error)
	UpsertDomain(route DomainRoute) (ConfigSnapshot, error)
	DeleteDomain(id string) (ConfigSnapshot, error)
	UpsertTunnel(route TunnelRoute) (ConfigSnapshot, error)
	DeleteTunnel(id string) (ConfigSnapshot, error)
	UpsertCertificate(cert Certificate) (ConfigSnapshot, error)
	DeleteCertificate(id string) (ConfigSnapshot, error)
	UpsertSSLPolicy(policy SSLPolicy) (ConfigSnapshot, error)
	DeleteSSLPolicy(id string) (ConfigSnapshot, error)
	UpsertAccessPolicy(policy AccessPolicy) (ConfigSnapshot, error)
	DeleteAccessPolicy(id string) (ConfigSnapshot, error)
	UpsertRewriteRule(rule RewriteRule) (ConfigSnapshot, error)
	DeleteRewriteRule(id string) (ConfigSnapshot, error)
}

// DomainRoute represents a domain level forwarding rule that an edge node should proxy.
type DomainRoute struct {
	ID        string     `json:"id"`
	Domain    string     `json:"domain"`
	Upstreams []Upstream `json:"upstreams"`
	EdgeNodes []string   `json:"edgeNodes"`
	EnableTLS bool       `json:"enableTls"`
	Metadata  RouteMeta  `json:"metadata,omitempty"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// Upstream defines a single upstream endpoint for an edge route.
type Upstream struct {
	Address       string        `json:"address"`
	Weight        int           `json:"weight"`
	MaxFails      int           `json:"maxFails,omitempty"`
	FailTimeout   time.Duration `json:"failTimeout,omitempty"`
	HealthCheck   string        `json:"healthCheck,omitempty"`
	UsePersistent bool          `json:"usePersistent,omitempty"`
}

// RouteMeta describes optional behaviours that edge templates might need.
type RouteMeta struct {
	Sticky       bool          `json:"sticky,omitempty"`
	TimeoutProxy time.Duration `json:"timeoutProxy,omitempty"`
	TimeoutRead  time.Duration `json:"timeoutRead,omitempty"`
	TimeoutSend  time.Duration `json:"timeoutSend,omitempty"`
}

// TunnelRoute configures an inbound tunnel that will be relayed to an internal service.
type TunnelRoute struct {
	ID          string        `json:"id"`
	Protocol    string        `json:"protocol"`
	BindHost    string        `json:"bindHost"`
	BindPort    int           `json:"bindPort"`
	Target      string        `json:"target"`
	NodeIDs     []string      `json:"nodeIds"`
	IdleTimeout time.Duration `json:"idleTimeout,omitempty"`
	UpdatedAt   time.Time     `json:"updatedAt"`
	Metadata    TunnelMeta    `json:"metadata,omitempty"`
}

// TunnelMeta carries optional extensions for tunnel behaviour.
type TunnelMeta struct {
	EnableProxyProtocol bool   `json:"enableProxyProtocol,omitempty"`
	Description         string `json:"description,omitempty"`
}

// Certificate represents TLS material managed by the control plane.
type Certificate struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Domains         []string  `json:"domains,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	NotBefore       time.Time `json:"notBefore,omitempty"`
	NotAfter        time.Time `json:"notAfter,omitempty"`
	Status          string    `json:"status,omitempty"`
	Managed         bool      `json:"managed"`
	ManagedProvider string    `json:"managedProvider,omitempty"`
	PEM             string    `json:"pem,omitempty"`
	PrivateKey      string    `json:"privateKey,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// PolicyScope restricts a policy to specific resources.
type PolicyScope struct {
	Mode      string   `json:"mode"` // any, resources, tags
	Resources []string `json:"resources,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// Condition describes request matching logic.
type Condition struct {
	Mode     string    `json:"mode"` // any, matchers
	Matchers []Matcher `json:"matchers,omitempty"`
}

// Matcher evaluates a single condition expression.
type Matcher struct {
	Type     string   `json:"type"`
	Key      string   `json:"key,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// SSLPolicy dictates TLS behaviour for a resource.
type SSLPolicy struct {
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	Description           string        `json:"description,omitempty"`
	Scope                 PolicyScope   `json:"scope"`
	Condition             Condition     `json:"condition"`
	CertificateID         string        `json:"certificateId,omitempty"`
	EnforceHTTPS          bool          `json:"enforceHttps"`
	EnableHSTS            bool          `json:"enableHsts"`
	HSTSMaxAge            time.Duration `json:"hstsMaxAge,omitempty"`
	HSTSIncludeSubdomains bool          `json:"hstsIncludeSubdomains,omitempty"`
	HSTSPreload           bool          `json:"hstsPreload,omitempty"`
	MinTLSVersion         string        `json:"minTlsVersion,omitempty"`
	EnableOCSPStapling    bool          `json:"enableOcspStapling"`
	ClientAuth            bool          `json:"clientAuth"`
	ClientCAIDs           []string      `json:"clientCaIds,omitempty"`
	CreatedAt             time.Time     `json:"createdAt"`
	UpdatedAt             time.Time     `json:"updatedAt"`
}

// AccessAction defines available decisions for access policy.
type AccessAction string

const (
	AccessActionAllow AccessAction = "allow"
	AccessActionDeny  AccessAction = "deny"
)

// AccessPolicy controls request admission.
type AccessPolicy struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	Scope        PolicyScope   `json:"scope"`
	Condition    Condition     `json:"condition"`
	Action       AccessAction  `json:"action"`
	ResponseCode int           `json:"responseCode,omitempty"`
	RedirectURL  string        `json:"redirectUrl,omitempty"`
	CreatedAt    time.Time     `json:"createdAt"`
	UpdatedAt    time.Time     `json:"updatedAt"`
}

// HeaderMutation represents a header modification.
type HeaderMutation struct {
	Operation string `json:"operation"` // set, add, delete
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
}

// URLRewrite describes path/query modifications.
type URLRewrite struct {
	Mode  string `json:"mode,omitempty"` // replace, append, regex
	Path  string `json:"path,omitempty"`
	Query string `json:"query,omitempty"`
}

// UpstreamOverride modifies upstream behaviour.
type UpstreamOverride struct {
	PassHostHeader bool          `json:"passHostHeader"`
	UpstreamHost   string        `json:"upstreamHost,omitempty"`
	Scheme         string        `json:"scheme,omitempty"`
	ConnectTimeout time.Duration `json:"connectTimeout,omitempty"`
	ReadTimeout    time.Duration `json:"readTimeout,omitempty"`
	SendTimeout    time.Duration `json:"sendTimeout,omitempty"`
}

// RewriteActions encapsulates supported rewrite mutations.
type RewriteActions struct {
	SNIOverride     string             `json:"sniOverride,omitempty"`
	HostOverride    string             `json:"hostOverride,omitempty"`
	URL             URLRewrite         `json:"url,omitempty"`
	Headers         []HeaderMutation   `json:"headers,omitempty"`
	Upstream        *UpstreamOverride  `json:"upstream,omitempty"`
}

// RewriteRule mutates outgoing origin requests.
type RewriteRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Scope       PolicyScope    `json:"scope"`
	Condition   Condition      `json:"condition"`
	Actions     RewriteActions `json:"actions"`
	Priority    int            `json:"priority"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

// ConfigSnapshot is the immutable configuration artefact that agents consume.
type ConfigSnapshot struct {
	Version     int64         `json:"version"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Domains     []DomainRoute `json:"domains"`
	Tunnels     []TunnelRoute `json:"tunnels"`
	Certificates []Certificate `json:"certificates"`
	SSLPolicies []SSLPolicy `json:"sslPolicies"`
	AccessPolicies []AccessPolicy `json:"accessPolicies"`
	RewriteRules []RewriteRule `json:"rewriteRules"`
}

// MemoryStore manages configuration in-memory.
type MemoryStore struct {
	mu            sync.RWMutex
	version       int64
	domains       map[string]DomainRoute
	tunnels       map[string]TunnelRoute
	certificates  map[string]Certificate
	sslPolicies   map[string]SSLPolicy
	accessPolicies map[string]AccessPolicy
	rewriteRules  map[string]RewriteRule
	watchers      map[int]chan ConfigSnapshot
	nextWatcherID int
}

var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("configstore: record not found")
)

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		domains:        make(map[string]DomainRoute),
		tunnels:        make(map[string]TunnelRoute),
		certificates:  make(map[string]Certificate),
		sslPolicies:   make(map[string]SSLPolicy),
		accessPolicies: make(map[string]AccessPolicy),
		rewriteRules:  make(map[string]RewriteRule),
		watchers:      make(map[int]chan ConfigSnapshot),
	}
}

var _ Store = (*MemoryStore)(nil)

// UpsertDomain inserts or replaces a domain route. Empty ID will be populated automatically.
func (s *MemoryStore) UpsertDomain(route DomainRoute) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if route.ID == "" {
		route.ID = uuid.NewString()
	}
	route.UpdatedAt = time.Now().UTC()
	s.domains[route.ID] = route
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteDomain removes a domain route.
func (s *MemoryStore) DeleteDomain(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.domains[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.domains, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertTunnel inserts or replaces a tunnel route.
func (s *MemoryStore) UpsertTunnel(route TunnelRoute) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if route.ID == "" {
		route.ID = uuid.NewString()
	}
	route.UpdatedAt = time.Now().UTC()
	s.tunnels[route.ID] = route
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteTunnel removes a tunnel route.
func (s *MemoryStore) DeleteTunnel(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tunnels[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.tunnels, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertCertificate inserts or updates certificate material.
func (s *MemoryStore) UpsertCertificate(cert Certificate) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cert.ID == "" {
		cert.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.certificates[cert.ID]; ok {
		if cert.CreatedAt.IsZero() {
			cert.CreatedAt = existing.CreatedAt
		}
	} else if cert.CreatedAt.IsZero() {
		cert.CreatedAt = now
	}
	cert.UpdatedAt = now
	s.certificates[cert.ID] = cert
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteCertificate removes a certificate entry.
func (s *MemoryStore) DeleteCertificate(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.certificates[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.certificates, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertSSLPolicy stores a TLS policy definition.
func (s *MemoryStore) UpsertSSLPolicy(policy SSLPolicy) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.sslPolicies[policy.ID]; ok {
		if policy.CreatedAt.IsZero() {
			policy.CreatedAt = existing.CreatedAt
		}
	} else if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	s.sslPolicies[policy.ID] = policy
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteSSLPolicy removes a TLS policy.
func (s *MemoryStore) DeleteSSLPolicy(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sslPolicies[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.sslPolicies, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertAccessPolicy stores an access-control rule.
func (s *MemoryStore) UpsertAccessPolicy(policy AccessPolicy) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.accessPolicies[policy.ID]; ok {
		if policy.CreatedAt.IsZero() {
			policy.CreatedAt = existing.CreatedAt
		}
	} else if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	s.accessPolicies[policy.ID] = policy
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteAccessPolicy removes an access policy.
func (s *MemoryStore) DeleteAccessPolicy(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.accessPolicies[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.accessPolicies, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertRewriteRule stores an origin rewrite rule.
func (s *MemoryStore) UpsertRewriteRule(rule RewriteRule) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.rewriteRules[rule.ID]; ok {
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = existing.CreatedAt
		}
	} else if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	s.rewriteRules[rule.ID] = rule
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// DeleteRewriteRule removes an origin rewrite rule.
func (s *MemoryStore) DeleteRewriteRule(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rewriteRules[id]; !ok {
		return ConfigSnapshot{}, ErrNotFound
	}
	delete(s.rewriteRules, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// Snapshot returns the latest configuration snapshot immediately.
func (s *MemoryStore) Snapshot(_ context.Context) (ConfigSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked(), nil
}

// Watch blocks until the store version exceeds the provided revision or the context ends.
func (s *MemoryStore) Watch(ctx context.Context, since int64) (ConfigSnapshot, error) {
	s.mu.Lock()
	if s.version > since {
		snap := s.snapshotLocked()
		s.mu.Unlock()
		return snap, nil
	}

	wID := s.nextWatcherID
	s.nextWatcherID++
	ch := make(chan ConfigSnapshot, 1)
	s.watchers[wID] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.watchers, wID)
		s.mu.Unlock()
	}()

	select {
	case snap := <-ch:
		return snap, nil
	case <-ctx.Done():
		return ConfigSnapshot{}, ctx.Err()
	}
}

// bumpLocked increments the store version and notifies listeners. Caller must hold s.mu.
func (s *MemoryStore) bumpLocked() {
	s.version++
	snap := s.snapshotLocked()
	for id, ch := range s.watchers {
		select {
		case ch <- snap:
		default:
			_ = id
		}
	}
}

func (s *MemoryStore) snapshotLocked() ConfigSnapshot {
	domainList := make([]DomainRoute, 0, len(s.domains))
	for _, v := range s.domains {
		domainList = append(domainList, v)
	}
	sort.Slice(domainList, func(i, j int) bool {
		if domainList[i].Domain == domainList[j].Domain {
			return domainList[i].ID < domainList[j].ID
		}
		return domainList[i].Domain < domainList[j].Domain
	})

	tunnelList := make([]TunnelRoute, 0, len(s.tunnels))
	for _, v := range s.tunnels {
		tunnelList = append(tunnelList, v)
	}
	sort.Slice(tunnelList, func(i, j int) bool {
		if tunnelList[i].BindHost == tunnelList[j].BindHost {
			if tunnelList[i].BindPort == tunnelList[j].BindPort {
				return tunnelList[i].ID < tunnelList[j].ID
			}
			return tunnelList[i].BindPort < tunnelList[j].BindPort
		}
		return tunnelList[i].BindHost < tunnelList[j].BindHost
	})

	certificateList := make([]Certificate, 0, len(s.certificates))
	for _, v := range s.certificates {
		certificateList = append(certificateList, v)
	}
	sort.Slice(certificateList, func(i, j int) bool {
		if certificateList[i].Name == certificateList[j].Name {
			return certificateList[i].ID < certificateList[j].ID
		}
		return certificateList[i].Name < certificateList[j].Name
	})

	sslPolicyList := make([]SSLPolicy, 0, len(s.sslPolicies))
	for _, v := range s.sslPolicies {
		sslPolicyList = append(sslPolicyList, v)
	}
	sort.Slice(sslPolicyList, func(i, j int) bool {
		if sslPolicyList[i].Name == sslPolicyList[j].Name {
			return sslPolicyList[i].ID < sslPolicyList[j].ID
		}
		return sslPolicyList[i].Name < sslPolicyList[j].Name
	})

	accessPolicyList := make([]AccessPolicy, 0, len(s.accessPolicies))
	for _, v := range s.accessPolicies {
		accessPolicyList = append(accessPolicyList, v)
	}
	sort.Slice(accessPolicyList, func(i, j int) bool {
		if accessPolicyList[i].Name == accessPolicyList[j].Name {
			return accessPolicyList[i].ID < accessPolicyList[j].ID
		}
		return accessPolicyList[i].Name < accessPolicyList[j].Name
	})

	rewriteList := make([]RewriteRule, 0, len(s.rewriteRules))
	for _, v := range s.rewriteRules {
		rewriteList = append(rewriteList, v)
	}
	sort.Slice(rewriteList, func(i, j int) bool {
		if rewriteList[i].Priority == rewriteList[j].Priority {
			if rewriteList[i].Name == rewriteList[j].Name {
				return rewriteList[i].ID < rewriteList[j].ID
			}
			return rewriteList[i].Name < rewriteList[j].Name
		}
		return rewriteList[i].Priority < rewriteList[j].Priority
	})

	return ConfigSnapshot{
		Version:     s.version,
		GeneratedAt: time.Now().UTC(),
		Domains:     domainList,
		Tunnels:     tunnelList,
		Certificates: certificateList,
		SSLPolicies:  sslPolicyList,
		AccessPolicies: accessPolicyList,
		RewriteRules:  rewriteList,
	}
}
