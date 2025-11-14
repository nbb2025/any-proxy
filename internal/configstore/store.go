package configstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"
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
	UpsertNodeGroup(group NodeGroup) (ConfigSnapshot, NodeGroup, error)
	DeleteNodeGroup(id string) (ConfigSnapshot, error)
	RegisterOrUpdateNode(reg NodeRegistration) (ConfigSnapshot, EdgeNode, error)
	UpdateNodeGroup(nodeID, groupID string) (ConfigSnapshot, EdgeNode, error)
	UpdateNode(nodeID string, update NodeUpdate) (ConfigSnapshot, EdgeNode, error)
	DeleteNode(id string) (ConfigSnapshot, error)
	UpsertTunnelGroup(group TunnelGroup) (ConfigSnapshot, TunnelGroup, error)
	DeleteTunnelGroup(id string) (ConfigSnapshot, error)
	UpsertTunnelAgent(agent TunnelAgent) (ConfigSnapshot, TunnelAgent, error)
	DeleteTunnelAgent(id string) (ConfigSnapshot, error)
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
	Sticky                 bool            `json:"sticky,omitempty"`
	TimeoutProxy           time.Duration   `json:"timeoutProxy,omitempty"`
	TimeoutRead            time.Duration   `json:"timeoutRead,omitempty"`
	TimeoutSend            time.Duration   `json:"timeoutSend,omitempty"`
	DisplayName            string          `json:"displayName,omitempty"`
	GroupName              string          `json:"groupName,omitempty"`
	Remark                 string          `json:"remark,omitempty"`
	ForwardMode            string          `json:"forwardMode,omitempty"`
	LoadBalancingAlgorithm string          `json:"loadBalancingAlgorithm,omitempty"`
	InboundListeners       []RouteListener `json:"inboundListeners,omitempty"`
	OutboundListeners      []RouteListener `json:"outboundListeners,omitempty"`
}

type RouteListener struct {
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// TunnelRoute configures an inbound tunnel that will be relayed to an internal service.
type TunnelRoute struct {
	ID          string        `json:"id"`
	GroupID     string        `json:"groupId"`
	Protocol    string        `json:"protocol"`
	BindHost    string        `json:"bindHost"`
	BindPort    int           `json:"bindPort"`
	BridgeBind  string        `json:"bridgeBind"`
	BridgePort  int           `json:"bridgePort"`
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

// TunnelGroup represents a logical ingress shared by tunnel agents and edge nodes.
type TunnelGroup struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	ListenAddress  string    `json:"listenAddress"`
	EdgeNodeIDs    []string  `json:"edgeNodeIds,omitempty"`
	Transports     []string  `json:"transports,omitempty"`
	EnableCompress bool      `json:"enableCompress,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// TunnelAgentService declares a local service that can be exposed via tunnel.
type TunnelAgentService struct {
	ID                string `json:"id"`
	Protocol          string `json:"protocol"`
	LocalAddress      string `json:"localAddress"`
	LocalPort         int    `json:"localPort"`
	RemotePort        int    `json:"remotePort"`
	EnableCompression bool   `json:"enableCompression,omitempty"`
	Description       string `json:"description,omitempty"`
}

// TunnelAgent describes a tunnel client instance living inside a private network.
type TunnelAgent struct {
	ID          string               `json:"id"`
	NodeID      string               `json:"nodeId"`
	GroupID     string               `json:"groupId"`
	Description string               `json:"description,omitempty"`
	KeyHash     string               `json:"keyHash"`
	KeyVersion  int                  `json:"keyVersion"`
	Enabled     bool                 `json:"enabled"`
	Services    []TunnelAgentService `json:"services,omitempty"`
	CreatedAt   time.Time            `json:"createdAt"`
	UpdatedAt   time.Time            `json:"updatedAt"`
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
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"`
	Scope        PolicyScope  `json:"scope"`
	Condition    Condition    `json:"condition"`
	Action       AccessAction `json:"action"`
	ResponseCode int          `json:"responseCode,omitempty"`
	RedirectURL  string       `json:"redirectUrl,omitempty"`
	CreatedAt    time.Time    `json:"createdAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
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
	SNIOverride  string            `json:"sniOverride,omitempty"`
	HostOverride string            `json:"hostOverride,omitempty"`
	URL          URLRewrite        `json:"url,omitempty"`
	Headers      []HeaderMutation  `json:"headers,omitempty"`
	Upstream     *UpstreamOverride `json:"upstream,omitempty"`
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

// NodeCategory classifies a node's high level capability.
type NodeCategory string

const (
	NodeCategoryWaiting NodeCategory = "waiting"
	NodeCategoryCDN     NodeCategory = "cdn"
	NodeCategoryTunnel  NodeCategory = "tunnel"
)

// NodeGroup represents a logical grouping under a category.
type NodeGroup struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Category    NodeCategory `json:"category"`
	Description string       `json:"description,omitempty"`
	System      bool         `json:"system,omitempty"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

// EdgeNode stores metadata reported by running agents.
type EdgeNode struct {
	ID                  string       `json:"id"`
	GroupID             string       `json:"groupId"`
	Category            NodeCategory `json:"category"`
	Kind                string       `json:"kind"`
	Name                string       `json:"name,omitempty"`
	Hostname            string       `json:"hostname,omitempty"`
	Addresses           []string     `json:"addresses,omitempty"`
	Version             string       `json:"version,omitempty"`
	AgentVersion        string       `json:"agentVersion,omitempty"`
	AgentDesiredVersion string       `json:"agentDesiredVersion,omitempty"`
	LastUpgradeAt       time.Time    `json:"lastUpgradeAt,omitempty"`
	NodeKeyHash         string       `json:"nodeKeyHash,omitempty"`
	NodeKeyVersion      int          `json:"nodeKeyVersion,omitempty"`
	LastSeen            time.Time    `json:"lastSeen"`
	CreatedAt           time.Time    `json:"createdAt"`
	UpdatedAt           time.Time    `json:"updatedAt"`
}

// NodeRegistration carries metadata supplied by agents on join/heartbeat.
type NodeRegistration struct {
	ID             string
	Kind           string
	GroupID        string
	Name           string
	Category       NodeCategory
	Hostname       string
	Addresses      []string
	Version        string
	AgentVersion   string
	NodeKeyHash    string
	NodeKeyVersion int
}

// NodeUpdate carries mutable node metadata for control-plane operations.
type NodeUpdate struct {
	GroupID             *string
	Name                *string
	Category            *NodeCategory
	AgentDesiredVersion *string
}

// ConfigSnapshot is the immutable configuration artefact that agents consume.
type ConfigSnapshot struct {
	Version        int64          `json:"version"`
	GeneratedAt    time.Time      `json:"generatedAt"`
	Domains        []DomainRoute  `json:"domains"`
	Tunnels        []TunnelRoute  `json:"tunnels"`
	TunnelGroups   []TunnelGroup  `json:"tunnelGroups"`
	TunnelAgents   []TunnelAgent  `json:"tunnelAgents"`
	Certificates   []Certificate  `json:"certificates"`
	SSLPolicies    []SSLPolicy    `json:"sslPolicies"`
	AccessPolicies []AccessPolicy `json:"accessPolicies"`
	RewriteRules   []RewriteRule  `json:"rewriteRules"`
	NodeGroups     []NodeGroup    `json:"nodeGroups"`
	Nodes          []EdgeNode     `json:"nodes"`
}

type MemoryStore struct {
	mu             sync.RWMutex
	version        int64
	domains        map[string]DomainRoute
	tunnels        map[string]TunnelRoute
	tunnelGroups   map[string]TunnelGroup
	tunnelAgents   map[string]TunnelAgent
	certificates   map[string]Certificate
	sslPolicies    map[string]SSLPolicy
	accessPolicies map[string]AccessPolicy
	rewriteRules   map[string]RewriteRule
	nodeGroups     map[string]NodeGroup
	nodes          map[string]EdgeNode
	watchers       map[int]chan ConfigSnapshot
	nextWatcherID  int
}

var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("configstore: record not found")
	// ErrInvalidGroup indicates the supplied node group is invalid.
	ErrInvalidGroup = errors.New("configstore: invalid node group")
	// ErrGroupNotFound indicates the referenced node group does not exist.
	ErrGroupNotFound = errors.New("configstore: node group not found")
	// ErrNodeNotFound indicates the referenced node is missing.
	ErrNodeNotFound = errors.New("configstore: node not found")
	// ErrProtectedGroup indicates a system group cannot be modified.
	ErrProtectedGroup = errors.New("configstore: protected node group")
	// ErrTunnelGroupNotFound indicates a tunnel group is missing.
	ErrTunnelGroupNotFound = errors.New("configstore: tunnel group not found")
	// ErrTunnelAgentNotFound indicates a tunnel agent is missing.
	ErrTunnelAgentNotFound = errors.New("configstore: tunnel agent not found")
	// ErrInvalidTunnelGroup indicates the supplied tunnel group definition is invalid.
	ErrInvalidTunnelGroup = errors.New("configstore: invalid tunnel group")
	// ErrInvalidTunnelAgent indicates the supplied tunnel agent definition is invalid.
	ErrInvalidTunnelAgent = errors.New("configstore: invalid tunnel agent")
	// ErrTunnelGroupInUse indicates the group cannot be removed due to active agents.
	ErrTunnelGroupInUse = errors.New("configstore: tunnel group in use")
)

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		domains:        make(map[string]DomainRoute),
		tunnels:        make(map[string]TunnelRoute),
		tunnelGroups:   make(map[string]TunnelGroup),
		tunnelAgents:   make(map[string]TunnelAgent),
		certificates:   make(map[string]Certificate),
		sslPolicies:    make(map[string]SSLPolicy),
		accessPolicies: make(map[string]AccessPolicy),
		rewriteRules:   make(map[string]RewriteRule),
		nodeGroups:     make(map[string]NodeGroup),
		nodes:          make(map[string]EdgeNode),
		watchers:       make(map[int]chan ConfigSnapshot),
	}
	now := time.Now().UTC()
	systemGroups := []NodeGroup{
		{
			ID:        defaultWaitingGroupID,
			Name:      "待分组",
			Category:  NodeCategoryWaiting,
			System:    true,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        defaultCDNGroupID,
			Name:      "默认 CDN 分组",
			Category:  NodeCategoryCDN,
			System:    true,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        defaultTunnelGroupID,
			Name:      "默认内网穿透分组",
			Category:  NodeCategoryTunnel,
			System:    true,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	for _, group := range systemGroups {
		store.nodeGroups[group.ID] = group
	}
	return store
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
	route.GroupID = strings.TrimSpace(route.GroupID)
	if route.GroupID == "" {
		return ConfigSnapshot{}, ErrInvalidTunnelGroup
	}
	route.Protocol = strings.ToLower(strings.TrimSpace(route.Protocol))
	if route.Protocol == "" {
		route.Protocol = "tcp"
	}
	route.BindHost = strings.TrimSpace(route.BindHost)
	if route.BindHost == "" {
		route.BindHost = "0.0.0.0"
	}
	if route.BindPort <= 0 || route.BindPort > 65535 {
		return ConfigSnapshot{}, fmt.Errorf("bind port must be between 1 and 65535")
	}
	route.Target = strings.TrimSpace(route.Target)
	route.BridgeBind = strings.TrimSpace(route.BridgeBind)
	if route.BridgeBind == "" {
		route.BridgeBind = "127.0.0.1"
	}
	if route.BridgePort < 0 || route.BridgePort > 65535 {
		return ConfigSnapshot{}, fmt.Errorf("bridge port must be between 0 and 65535")
	}
	route.NodeIDs = dedupeStrings(route.NodeIDs)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tunnelGroups[route.GroupID]; !ok {
		return ConfigSnapshot{}, ErrTunnelGroupNotFound
	}

	if route.ID == "" {
		route.ID = uuid.NewString()
	}

	if route.BridgePort == 0 {
		port, err := s.allocateBridgePortLocked(route.ID, route.BridgeBind)
		if err != nil {
			return ConfigSnapshot{}, err
		}
		route.BridgePort = port
	} else if s.bridgeAddrInUseLocked(route.ID, route.BridgeBind, route.BridgePort) {
		return ConfigSnapshot{}, fmt.Errorf("bridge address %s:%d already in use", route.BridgeBind, route.BridgePort)
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

// UpsertNodeGroup creates or updates a logical node group.
func (s *MemoryStore) UpsertNodeGroup(group NodeGroup) (ConfigSnapshot, NodeGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(group.Name) == "" {
		return ConfigSnapshot{}, NodeGroup{}, ErrInvalidGroup
	}
	switch group.Category {
	case NodeCategoryWaiting, NodeCategoryCDN, NodeCategoryTunnel:
	default:
		return ConfigSnapshot{}, NodeGroup{}, ErrInvalidGroup
	}

	now := time.Now().UTC()
	if group.ID == "" {
		group.ID = uuid.NewString()
		group.CreatedAt = now
		group.UpdatedAt = now
	} else {
		existing, ok := s.nodeGroups[group.ID]
		if ok {
			if existing.System && existing.Category != group.Category {
				return ConfigSnapshot{}, NodeGroup{}, ErrProtectedGroup
			}
			if group.CreatedAt.IsZero() {
				group.CreatedAt = existing.CreatedAt
			}
			if group.System != existing.System {
				group.System = existing.System
			}
		} else if group.CreatedAt.IsZero() {
			group.CreatedAt = now
		}
		group.UpdatedAt = now
	}
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.UpdatedAt = now
	if existing, ok := s.nodeGroups[group.ID]; ok {
		if existing.System {
			group.System = true
		}
	}
	s.nodeGroups[group.ID] = group
	s.bumpLocked()
	return s.snapshotLocked(), group, nil
}

// DeleteNodeGroup removes a node group and reassigns members to the waiting pool.
func (s *MemoryStore) DeleteNodeGroup(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	group, ok := s.nodeGroups[id]
	if !ok {
		return ConfigSnapshot{}, ErrGroupNotFound
	}
	if group.System {
		return ConfigSnapshot{}, ErrProtectedGroup
	}

	waiting := s.ensureSystemGroupLocked(NodeCategoryWaiting)

	now := time.Now().UTC()
	for nodeID, node := range s.nodes {
		if node.GroupID == id {
			node.GroupID = waiting.ID
			node.Category = waiting.Category
			node.UpdatedAt = now
			s.nodes[nodeID] = node
		}
	}

	delete(s.nodeGroups, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// RegisterOrUpdateNode persists node metadata reported by agents.
func (s *MemoryStore) RegisterOrUpdateNode(reg NodeRegistration) (ConfigSnapshot, EdgeNode, error) {
	if strings.TrimSpace(reg.ID) == "" {
		return ConfigSnapshot{}, EdgeNode{}, ErrNodeNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var group NodeGroup
	if id := strings.TrimSpace(reg.GroupID); id != "" {
		group = s.nodeGroups[id]
		if group.ID == "" {
			group = s.ensureSystemGroupLocked(reg.Category)
		}
	} else if reg.Category != "" {
		group = s.ensureSystemGroupLocked(reg.Category)
	} else {
		group = s.ensureSystemGroupLocked(NodeCategoryWaiting)
	}

	now := time.Now().UTC()
	addresses := uniqueStrings(reg.Addresses)

	node, exists := s.nodes[reg.ID]
	if !exists {
		node = EdgeNode{
			ID:        reg.ID,
			CreatedAt: now,
		}
	}

	changed := !exists

	if node.GroupID != group.ID {
		node.GroupID = group.ID
		node.Category = group.Category
		changed = true
	}

	if name := strings.TrimSpace(reg.Name); name != "" && name != node.Name {
		node.Name = name
		changed = true
	}

	if kind := strings.TrimSpace(reg.Kind); kind != "" && kind != node.Kind {
		node.Kind = kind
		changed = true
	} else if node.Kind == "" {
		node.Kind = "edge"
		changed = true
	}

	if host := strings.TrimSpace(reg.Hostname); host != "" && host != node.Hostname {
		node.Hostname = host
		changed = true
	}

	if len(addresses) > 0 && !equalStringSlices(node.Addresses, addresses) {
		node.Addresses = addresses
		changed = true
	}

	if ver := strings.TrimSpace(reg.Version); ver != "" && ver != node.Version {
		node.Version = ver
		changed = true
	}
	if agentVer := strings.TrimSpace(reg.AgentVersion); agentVer != "" && agentVer != node.AgentVersion {
		node.AgentVersion = agentVer
		changed = true
	}

	if hash := strings.TrimSpace(reg.NodeKeyHash); hash != "" {
		keyChanged := false
		if hash != node.NodeKeyHash {
			node.NodeKeyHash = hash
			keyChanged = true
			changed = true
		}
		if reg.NodeKeyVersion > 0 && reg.NodeKeyVersion != node.NodeKeyVersion {
			node.NodeKeyVersion = reg.NodeKeyVersion
			changed = true
		} else if node.NodeKeyVersion == 0 && keyChanged {
			node.NodeKeyVersion = 1
			changed = true
		}
	}

	node.LastSeen = now
	node.UpdatedAt = now
	if node.AgentDesiredVersion != "" && node.AgentVersion != "" && node.AgentDesiredVersion == node.AgentVersion {
		node.AgentDesiredVersion = ""
		node.LastUpgradeAt = now
		changed = true
	}

	s.nodes[node.ID] = node
	if changed {
		s.bumpLocked()
	}
	return s.snapshotLocked(), node, nil
}

// UpdateNodeGroup moves a node to the specified group.
func (s *MemoryStore) UpdateNodeGroup(nodeID, groupID string) (ConfigSnapshot, EdgeNode, error) {
	gid := groupID
	return s.UpdateNode(nodeID, NodeUpdate{GroupID: &gid})
}

// UpdateNode mutates node metadata such as group membership or display name.
func (s *MemoryStore) UpdateNode(nodeID string, update NodeUpdate) (ConfigSnapshot, EdgeNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return ConfigSnapshot{}, EdgeNode{}, ErrNodeNotFound
	}

	changed := false
	if update.GroupID != nil {
		targetID := strings.TrimSpace(*update.GroupID)
		var group NodeGroup
		if targetID == "" {
			group = s.ensureSystemGroupLocked(NodeCategoryWaiting)
		} else {
			group = s.nodeGroups[targetID]
			if group.ID == "" {
				return ConfigSnapshot{}, EdgeNode{}, ErrGroupNotFound
			}
		}
		if node.GroupID != group.ID {
			node.GroupID = group.ID
			node.Category = group.Category
			changed = true
		}
	}
	if update.Name != nil {
		name := strings.TrimSpace(*update.Name)
		if node.Name != name {
			node.Name = name
			changed = true
		}
	}
	if update.Category != nil {
		category := *update.Category
		group := s.ensureSystemGroupLocked(category)
		if node.Category != category || node.GroupID != group.ID {
			node.Category = category
			node.GroupID = group.ID
			changed = true
		}
	}
	if update.AgentDesiredVersion != nil {
		desired := strings.TrimSpace(*update.AgentDesiredVersion)
		if node.AgentDesiredVersion != desired {
			node.AgentDesiredVersion = desired
			changed = true
		}
	}

	if changed {
		node.UpdatedAt = time.Now().UTC()
		s.nodes[nodeID] = node
		s.bumpLocked()
	}

	return s.snapshotLocked(), node, nil
}

// UpsertTunnelGroup creates or updates a tunnel ingress group.
func (s *MemoryStore) UpsertTunnelGroup(group TunnelGroup) (ConfigSnapshot, TunnelGroup, error) {
	if strings.TrimSpace(group.Name) == "" {
		return ConfigSnapshot{}, TunnelGroup{}, ErrInvalidTunnelGroup
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if group.ID == "" {
		group.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.tunnelGroups[group.ID]; ok {
		if group.CreatedAt.IsZero() {
			group.CreatedAt = existing.CreatedAt
		}
	} else if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.ListenAddress = strings.TrimSpace(group.ListenAddress)
	if group.ListenAddress == "" {
		group.ListenAddress = ":4433"
	}
	group.EdgeNodeIDs = dedupeStrings(group.EdgeNodeIDs)
	group.Transports = normalizeTransports(group.Transports)
	group.UpdatedAt = now
	s.tunnelGroups[group.ID] = group
	s.bumpLocked()
	return s.snapshotLocked(), group, nil
}

// DeleteTunnelGroup removes the specified tunnel group.
func (s *MemoryStore) DeleteTunnelGroup(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tunnelGroups[id]; !ok {
		return ConfigSnapshot{}, ErrTunnelGroupNotFound
	}
	for _, agent := range s.tunnelAgents {
		if agent.GroupID == id {
			return ConfigSnapshot{}, ErrTunnelGroupInUse
		}
	}
	delete(s.tunnelGroups, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

// UpsertTunnelAgent creates or updates a tunnel client definition.
func (s *MemoryStore) UpsertTunnelAgent(agent TunnelAgent) (ConfigSnapshot, TunnelAgent, error) {
	agent.NodeID = strings.TrimSpace(agent.NodeID)
	agent.GroupID = strings.TrimSpace(agent.GroupID)
	agent.KeyHash = strings.TrimSpace(agent.KeyHash)
	if agent.NodeID == "" || agent.GroupID == "" || agent.KeyHash == "" {
		return ConfigSnapshot{}, TunnelAgent{}, ErrInvalidTunnelAgent
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tunnelGroups[agent.GroupID]; !ok {
		return ConfigSnapshot{}, TunnelAgent{}, ErrTunnelGroupNotFound
	}
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if existing, ok := s.tunnelAgents[agent.ID]; ok {
		if agent.CreatedAt.IsZero() {
			agent.CreatedAt = existing.CreatedAt
		}
		if agent.KeyVersion == 0 {
			agent.KeyVersion = existing.KeyVersion
		}
		if agent.KeyHash == "" {
			agent.KeyHash = existing.KeyHash
		}
	} else {
		if agent.CreatedAt.IsZero() {
			agent.CreatedAt = now
		}
		if agent.KeyVersion == 0 {
			agent.KeyVersion = 1
		}
	}
	agent.Services = normalizeServices(agent.Services)
	agent.UpdatedAt = now
	s.tunnelAgents[agent.ID] = agent
	s.bumpLocked()
	return s.snapshotLocked(), agent, nil
}

// DeleteTunnelAgent removes a tunnel agent definition.
func (s *MemoryStore) DeleteTunnelAgent(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tunnelAgents[id]; !ok {
		return ConfigSnapshot{}, ErrTunnelAgentNotFound
	}
	delete(s.tunnelAgents, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

func (s *MemoryStore) bridgeAddrInUseLocked(routeID, bind string, port int) bool {
	bind = strings.TrimSpace(bind)
	for id, route := range s.tunnels {
		if id == routeID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(route.BridgeBind), bind) && route.BridgePort == port {
			return true
		}
	}
	return false
}

func (s *MemoryStore) allocateBridgePortLocked(routeID, bind string) (int, error) {
	if existing, ok := s.tunnels[routeID]; ok {
		if existing.BridgeBind == bind && existing.BridgePort > 0 {
			if !s.bridgeAddrInUseLocked(routeID, bind, existing.BridgePort) {
				return existing.BridgePort, nil
			}
		}
	}
	base := 40000
	if routeID != "" {
		sum := crc32.ChecksumIEEE([]byte(routeID))
		base = 40000 + int(sum%20000)
	}
	if base < 1024 {
		base = 40000
	}
	port := base
	for attempts := 0; attempts < 20000; attempts++ {
		candidate := port + attempts
		if candidate > 65535 {
			candidate = 1024 + (candidate-1024)%64511
		}
		if !s.bridgeAddrInUseLocked(routeID, bind, candidate) {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("no bridge ports available for %s", bind)
}

// DeleteNode removes the specified edge node from the inventory.
func (s *MemoryStore) DeleteNode(id string) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nodes[id]; !ok {
		return ConfigSnapshot{}, ErrNodeNotFound
	}
	delete(s.nodes, id)
	s.bumpLocked()
	return s.snapshotLocked(), nil
}

func uniqueStrings(values []string) []string {
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

func (s *MemoryStore) ensureSystemGroupLocked(category NodeCategory) NodeGroup {
	id, name := defaultSystemGroupMeta(category)
	if existing, ok := s.nodeGroups[id]; ok {
		return existing
	}
	now := time.Now().UTC()
	group := NodeGroup{
		ID:        id,
		Name:      name,
		Category:  category,
		System:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.nodeGroups[id] = group
	return group
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeTransports(values []string) []string {
	if len(values) == 0 {
		return []string{"quic"}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		switch v {
		case "quic", "websocket":
		default:
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeServices(services []TunnelAgentService) []TunnelAgentService {
	seen := make(map[string]struct{}, len(services))
	for i := range services {
		svc := &services[i]
		if svc.ID == "" {
			svc.ID = fmt.Sprintf("svc-%d", i+1)
		}
		if _, ok := seen[svc.ID]; ok {
			svc.ID = fmt.Sprintf("svc-%d", len(seen)+1)
		}
		seen[svc.ID] = struct{}{}
		svc.Protocol = strings.ToLower(strings.TrimSpace(svc.Protocol))
		if svc.Protocol == "" {
			svc.Protocol = "tcp"
		}
		svc.LocalAddress = strings.TrimSpace(svc.LocalAddress)
		if svc.LocalAddress == "" {
			svc.LocalAddress = "127.0.0.1"
		}
		if svc.LocalPort == 0 {
			svc.LocalPort = svc.RemotePort
		}
	}
	return services
}

// GenerateTunnelAgentKey returns a base64 encoded secret and its SHA256 hash.
func GenerateTunnelAgentKey() (secret string, hashed string, err error) {
	return generateSecretKey()
}

// HashTunnelAgentKey derives the stored hash for a tunnel-agent secret.
func HashTunnelAgentKey(secret string) string {
	return hashSecret(secret)
}

// GenerateNodeKey returns a base64 encoded secret tied to an edge node.
func GenerateNodeKey() (secret string, hashed string, err error) {
	return generateSecretKey()
}

// HashNodeKey derives the stored hash for a node secret.
func HashNodeKey(secret string) string {
	return hashSecret(secret)
}

func generateSecretKey() (secret string, hashed string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	secret = base64.RawStdEncoding.EncodeToString(buf)
	hashBytes := sha256.Sum256([]byte(secret))
	hashed = hex.EncodeToString(hashBytes[:])
	return secret, hashed, nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
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

	tunnelGroupList := make([]TunnelGroup, 0, len(s.tunnelGroups))
	for _, v := range s.tunnelGroups {
		tunnelGroupList = append(tunnelGroupList, v)
	}
	sort.Slice(tunnelGroupList, func(i, j int) bool {
		if tunnelGroupList[i].Name == tunnelGroupList[j].Name {
			return tunnelGroupList[i].ID < tunnelGroupList[j].ID
		}
		return tunnelGroupList[i].Name < tunnelGroupList[j].Name
	})

	tunnelAgentList := make([]TunnelAgent, 0, len(s.tunnelAgents))
	for _, v := range s.tunnelAgents {
		tunnelAgentList = append(tunnelAgentList, v)
	}
	sort.Slice(tunnelAgentList, func(i, j int) bool {
		if tunnelAgentList[i].GroupID == tunnelAgentList[j].GroupID {
			return tunnelAgentList[i].NodeID < tunnelAgentList[j].NodeID
		}
		return tunnelAgentList[i].GroupID < tunnelAgentList[j].GroupID
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

	groupList := make([]NodeGroup, 0, len(s.nodeGroups))
	for _, v := range s.nodeGroups {
		groupList = append(groupList, v)
	}
	sort.Slice(groupList, func(i, j int) bool {
		if groupList[i].Category == groupList[j].Category {
			if groupList[i].Name == groupList[j].Name {
				return groupList[i].ID < groupList[j].ID
			}
			return groupList[i].Name < groupList[j].Name
		}
		return groupList[i].Category < groupList[j].Category
	})

	nodeList := make([]EdgeNode, 0, len(s.nodes))
	for _, v := range s.nodes {
		nodeList = append(nodeList, v)
	}
	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].ID < nodeList[j].ID
	})

	return ConfigSnapshot{
		Version:        s.version,
		GeneratedAt:    time.Now().UTC(),
		Domains:        domainList,
		Tunnels:        tunnelList,
		TunnelGroups:   tunnelGroupList,
		TunnelAgents:   tunnelAgentList,
		Certificates:   certificateList,
		SSLPolicies:    sslPolicyList,
		AccessPolicies: accessPolicyList,
		RewriteRules:   rewriteList,
		NodeGroups:     groupList,
		Nodes:          nodeList,
	}
}
