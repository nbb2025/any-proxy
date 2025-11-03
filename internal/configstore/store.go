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

// ConfigSnapshot is the immutable configuration artefact that agents consume.
type ConfigSnapshot struct {
	Version     int64         `json:"version"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Domains     []DomainRoute `json:"domains"`
	Tunnels     []TunnelRoute `json:"tunnels"`
}

// MemoryStore manages configuration in-memory.
type MemoryStore struct {
	mu            sync.RWMutex
	version       int64
	domains       map[string]DomainRoute
	tunnels       map[string]TunnelRoute
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
		domains:  make(map[string]DomainRoute),
		tunnels:  make(map[string]TunnelRoute),
		watchers: make(map[int]chan ConfigSnapshot),
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

	return ConfigSnapshot{
		Version:     s.version,
		GeneratedAt: time.Now().UTC(),
		Domains:     domainList,
		Tunnels:     tunnelList,
	}
}
