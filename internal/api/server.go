package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"anyproxy.dev/any-proxy/internal/configstore"
)

const (
	defaultWatchTimeout = 55 * time.Second
)

// Server exposes HTTP endpoints for managing configuration and serving agent requests.
type Server struct {
	store  configstore.Store
	logger Logger
	health func(context.Context) error
}

// Logger abstracts the logging dependency to simplify unit testing.
type Logger interface {
	Printf(format string, v ...any)
}

// Option applies configuration to the Server.
type Option func(*Server)

// WithLogger overrides the logger.
func WithLogger(l Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}

// WithHealthCheck registers a dependency health probe executed by /healthz.
func WithHealthCheck(fn func(context.Context) error) Option {
	return func(s *Server) {
		s.health = fn
	}
}

// NewServer builds a Server with the provided configuration store.
func NewServer(store configstore.Store, opts ...Option) *Server {
	s := &Server{
		store:  store,
		logger: stdLogger{},
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Register attaches handlers to the supplied mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/config/snapshot", s.handleSnapshot)
	mux.HandleFunc("/v1/domains", s.handleDomains)
	mux.HandleFunc("/v1/domains/", s.handleDomainsByID)
	mux.HandleFunc("/v1/tunnels", s.handleTunnels)
	mux.HandleFunc("/v1/tunnels/", s.handleTunnelsByID)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.health != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.health(ctx); err != nil {
			http.Error(w, fmt.Sprintf("dependency unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		val, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid since parameter", http.StatusBadRequest)
			return
		}
		since = val
	}

	ctx, cancel := context.WithTimeout(r.Context(), defaultWatchTimeout)
	defer cancel()

	snap, err := s.store.Watch(ctx, since)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.Error(w, fmt.Sprintf("watch error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.Domains)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertDomain(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDomainsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/domains/")
	if id == "" {
		http.Error(w, "missing domain id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteDomain(id); err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, fmt.Sprintf("delete failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpsertDomain(w http.ResponseWriter, r *http.Request) {
	var payload DomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if err := payload.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}

	route, err := payload.ToDomainRoute()
	if err != nil {
		http.Error(w, fmt.Sprintf("payload error: %v", err), http.StatusBadRequest)
		return
	}

	snap, err := s.store.UpsertDomain(route)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.Tunnels)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertTunnel(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTunnelsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/tunnels/")
	if id == "" {
		http.Error(w, "missing tunnel id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteTunnel(id); err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, fmt.Sprintf("delete failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpsertTunnel(w http.ResponseWriter, r *http.Request) {
	var payload TunnelPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if err := payload.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}

	route, err := payload.ToTunnelRoute()
	if err != nil {
		http.Error(w, fmt.Sprintf("payload error: %v", err), http.StatusBadRequest)
		return
	}

	snap, err := s.store.UpsertTunnel(route)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type stdLogger struct{}

func (stdLogger) Printf(format string, v ...any) {
	fmt.Printf(format+"\n", v...)
}

// DomainPayload describes the REST payload for domain routes.
type DomainPayload struct {
	ID        string             `json:"id,omitempty"`
	Domain    string             `json:"domain"`
	EnableTLS bool               `json:"enableTls"`
	Upstreams []UpstreamPayload  `json:"upstreams"`
	EdgeNodes []string           `json:"edgeNodes"`
	Metadata  RouteMetadataInput `json:"metadata,omitempty"`
}

// Validate performs light schema checks.
func (p DomainPayload) Validate() error {
	if p.Domain == "" {
		return errors.New("domain is required")
	}
	if len(p.Upstreams) == 0 {
		return errors.New("at least one upstream is required")
	}
	for i, ups := range p.Upstreams {
		if err := ups.Validate(); err != nil {
			return fmt.Errorf("upstream[%d]: %w", i, err)
		}
	}
	return nil
}

// ToDomainRoute converts the payload into a configstore struct.
func (p DomainPayload) ToDomainRoute() (configstore.DomainRoute, error) {
	upstreams := make([]configstore.Upstream, 0, len(p.Upstreams))
	for _, ups := range p.Upstreams {
		cfg, err := ups.toUpstream()
		if err != nil {
			return configstore.DomainRoute{}, err
		}
		upstreams = append(upstreams, cfg)
	}

	meta, err := p.Metadata.toRouteMeta()
	if err != nil {
		return configstore.DomainRoute{}, err
	}

	return configstore.DomainRoute{
		ID:        p.ID,
		Domain:    p.Domain,
		EnableTLS: p.EnableTLS,
		Upstreams: upstreams,
		EdgeNodes: append([]string(nil), p.EdgeNodes...),
		Metadata:  meta,
	}, nil
}

// UpstreamPayload represents the JSON schema for upstream entries.
type UpstreamPayload struct {
	Address       string `json:"address"`
	Weight        int    `json:"weight,omitempty"`
	MaxFails      int    `json:"maxFails,omitempty"`
	FailTimeout   string `json:"failTimeout,omitempty"`
	HealthCheck   string `json:"healthCheck,omitempty"`
	UsePersistent bool   `json:"usePersistent,omitempty"`
}

func (p UpstreamPayload) Validate() error {
	if p.Address == "" {
		return errors.New("address is required")
	}
	return nil
}

func (p UpstreamPayload) toUpstream() (configstore.Upstream, error) {
	var failTO time.Duration
	var err error
	if p.FailTimeout != "" {
		failTO, err = time.ParseDuration(p.FailTimeout)
		if err != nil {
			return configstore.Upstream{}, fmt.Errorf("invalid failTimeout: %w", err)
		}
	}

	return configstore.Upstream{
		Address:       p.Address,
		Weight:        p.Weight,
		MaxFails:      p.MaxFails,
		FailTimeout:   failTO,
		HealthCheck:   p.HealthCheck,
		UsePersistent: p.UsePersistent,
	}, nil
}

// RouteMetadataInput allows parsing duration strings from JSON.
type RouteMetadataInput struct {
	Sticky       bool   `json:"sticky,omitempty"`
	TimeoutProxy string `json:"timeoutProxy,omitempty"`
	TimeoutRead  string `json:"timeoutRead,omitempty"`
	TimeoutSend  string `json:"timeoutSend,omitempty"`
}

func (r RouteMetadataInput) toRouteMeta() (configstore.RouteMeta, error) {
	parse := func(raw string) (time.Duration, error) {
		if raw == "" {
			return 0, nil
		}
		return time.ParseDuration(raw)
	}

	var err error
	meta := configstore.RouteMeta{
		Sticky: r.Sticky,
	}
	if meta.TimeoutProxy, err = parse(r.TimeoutProxy); err != nil {
		return configstore.RouteMeta{}, fmt.Errorf("timeoutProxy: %w", err)
	}
	if meta.TimeoutRead, err = parse(r.TimeoutRead); err != nil {
		return configstore.RouteMeta{}, fmt.Errorf("timeoutRead: %w", err)
	}
	if meta.TimeoutSend, err = parse(r.TimeoutSend); err != nil {
		return configstore.RouteMeta{}, fmt.Errorf("timeoutSend: %w", err)
	}

	return meta, nil
}

// TunnelPayload describes the REST payload for tunnel definitions.
type TunnelPayload struct {
	ID          string              `json:"id,omitempty"`
	Protocol    string              `json:"protocol"`
	BindHost    string              `json:"bindHost"`
	BindPort    int                 `json:"bindPort"`
	Target      string              `json:"target"`
	NodeIDs     []string            `json:"nodeIds"`
	IdleTimeout string              `json:"idleTimeout,omitempty"`
	Metadata    TunnelMetadataInput `json:"metadata,omitempty"`
}

// Validate checks the tunnel input.
func (p TunnelPayload) Validate() error {
	if p.Protocol == "" {
		return errors.New("protocol is required")
	}
	if p.BindHost == "" {
		return errors.New("bindHost is required")
	}
	if p.BindPort == 0 {
		return errors.New("bindPort is required")
	}
	if p.Target == "" {
		return errors.New("target is required")
	}
	return nil
}

// ToTunnelRoute converts payload to store model.
func (p TunnelPayload) ToTunnelRoute() (configstore.TunnelRoute, error) {
	var idle time.Duration
	var err error
	if p.IdleTimeout != "" {
		idle, err = time.ParseDuration(p.IdleTimeout)
		if err != nil {
			return configstore.TunnelRoute{}, fmt.Errorf("idleTimeout: %w", err)
		}
	}

	meta := configstore.TunnelMeta{
		EnableProxyProtocol: p.Metadata.EnableProxyProtocol,
		Description:         p.Metadata.Description,
	}

	return configstore.TunnelRoute{
		ID:          p.ID,
		Protocol:    strings.ToLower(p.Protocol),
		BindHost:    p.BindHost,
		BindPort:    p.BindPort,
		Target:      p.Target,
		NodeIDs:     append([]string(nil), p.NodeIDs...),
		IdleTimeout: idle,
		Metadata:    meta,
	}, nil
}

// TunnelMetadataInput captures optional tunnel fields.
type TunnelMetadataInput struct {
	EnableProxyProtocol bool   `json:"enableProxyProtocol,omitempty"`
	Description         string `json:"description,omitempty"`
}
