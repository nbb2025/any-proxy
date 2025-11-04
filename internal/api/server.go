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
	mux.HandleFunc("/v1/certificates", s.handleCertificates)
	mux.HandleFunc("/v1/certificates/", s.handleCertificatesByID)
	mux.HandleFunc("/v1/ssl-policies", s.handleSSLPolicies)
	mux.HandleFunc("/v1/ssl-policies/", s.handleSSLPoliciesByID)
	mux.HandleFunc("/v1/access-policies", s.handleAccessPolicies)
	mux.HandleFunc("/v1/access-policies/", s.handleAccessPoliciesByID)
	mux.HandleFunc("/v1/rewrite-rules", s.handleRewriteRules)
	mux.HandleFunc("/v1/rewrite-rules/", s.handleRewriteRulesByID)
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

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.Certificates)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertCertificate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificatesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/certificates/")
	if id == "" {
		http.Error(w, "missing certificate id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteCertificate(id); err != nil {
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

func (s *Server) handleSSLPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.SSLPolicies)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertSSLPolicy(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSLPoliciesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ssl-policies/")
	if id == "" {
		http.Error(w, "missing policy id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteSSLPolicy(id); err != nil {
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

func (s *Server) handleAccessPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.AccessPolicies)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertAccessPolicy(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAccessPoliciesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/access-policies/")
	if id == "" {
		http.Error(w, "missing policy id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteAccessPolicy(id); err != nil {
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

func (s *Server) handleRewriteRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap.RewriteRules)
	case http.MethodPost, http.MethodPut:
		s.handleUpsertRewriteRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRewriteRulesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/rewrite-rules/")
	if id == "" {
		http.Error(w, "missing rule id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.store.DeleteRewriteRule(id); err != nil {
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

func (s *Server) handleUpsertCertificate(w http.ResponseWriter, r *http.Request) {
	var payload CertificatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	cert, err := payload.toCertificate()
	if err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}
	snap, err := s.store.UpsertCertificate(cert)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func (s *Server) handleUpsertSSLPolicy(w http.ResponseWriter, r *http.Request) {
	var payload SSLPolicyPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	policy, err := payload.toSSLPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}
	snap, err := s.store.UpsertSSLPolicy(policy)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func (s *Server) handleUpsertAccessPolicy(w http.ResponseWriter, r *http.Request) {
	var payload AccessPolicyPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	policy, err := payload.toAccessPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}
	snap, err := s.store.UpsertAccessPolicy(policy)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func (s *Server) handleUpsertRewriteRule(w http.ResponseWriter, r *http.Request) {
	var payload RewriteRulePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	rule, err := payload.toRewriteRule()
	if err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}
	snap, err := s.store.UpsertRewriteRule(rule)
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

// CertificatePayload describes REST payload for certificates.
type CertificatePayload struct {
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Domains         []string `json:"domains,omitempty"`
	Issuer          string   `json:"issuer,omitempty"`
	NotBefore       string   `json:"notBefore,omitempty"`
	NotAfter        string   `json:"notAfter,omitempty"`
	Status          string   `json:"status,omitempty"`
	Managed         bool     `json:"managed,omitempty"`
	ManagedProvider string   `json:"managedProvider,omitempty"`
	PEM             string   `json:"pem,omitempty"`
	PrivateKey      string   `json:"privateKey,omitempty"`
}

func (p CertificatePayload) toCertificate() (configstore.Certificate, error) {
	if strings.TrimSpace(p.Name) == "" {
		return configstore.Certificate{}, errors.New("name is required")
	}
	if !p.Managed {
		if strings.TrimSpace(p.PEM) == "" || strings.TrimSpace(p.PrivateKey) == "" {
			return configstore.Certificate{}, errors.New("pem and privateKey are required for unmanaged certificates")
		}
	}

	var notBefore, notAfter time.Time
	var err error
	if strings.TrimSpace(p.NotBefore) != "" {
		notBefore, err = time.Parse(time.RFC3339, p.NotBefore)
		if err != nil {
			return configstore.Certificate{}, fmt.Errorf("invalid notBefore: %w", err)
		}
	}
	if strings.TrimSpace(p.NotAfter) != "" {
		notAfter, err = time.Parse(time.RFC3339, p.NotAfter)
		if err != nil {
			return configstore.Certificate{}, fmt.Errorf("invalid notAfter: %w", err)
		}
	}

	return configstore.Certificate{
		ID:              p.ID,
		Name:            strings.TrimSpace(p.Name),
		Description:     strings.TrimSpace(p.Description),
		Domains:         copyStringSlice(p.Domains),
		Issuer:          strings.TrimSpace(p.Issuer),
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		Status:          strings.TrimSpace(p.Status),
		Managed:         p.Managed,
		ManagedProvider: strings.TrimSpace(p.ManagedProvider),
		PEM:             p.PEM,
		PrivateKey:      p.PrivateKey,
	}, nil
}

// SSLPolicyPayload models TLS policy JSON schema.
type SSLPolicyPayload struct {
	ID                    string           `json:"id,omitempty"`
	Name                  string           `json:"name"`
	Description           string           `json:"description,omitempty"`
	Scope                 ScopePayload     `json:"scope"`
	Condition             ConditionPayload `json:"condition"`
	CertificateID         string           `json:"certificateId,omitempty"`
	EnforceHTTPS          bool             `json:"enforceHttps"`
	EnableHSTS            bool             `json:"enableHsts"`
	HSTSMaxAge            string           `json:"hstsMaxAge,omitempty"`
	HSTSIncludeSubdomains bool             `json:"hstsIncludeSubdomains,omitempty"`
	HSTSPreload           bool             `json:"hstsPreload,omitempty"`
	MinTLSVersion         string           `json:"minTlsVersion,omitempty"`
	EnableOCSPStapling    bool             `json:"enableOcspStapling"`
	ClientAuth            bool             `json:"clientAuth"`
	ClientCAIDs           []string         `json:"clientCaIds,omitempty"`
}

func (p SSLPolicyPayload) toSSLPolicy() (configstore.SSLPolicy, error) {
	scope, err := p.Scope.toScope()
	if err != nil {
		return configstore.SSLPolicy{}, fmt.Errorf("scope: %w", err)
	}
	cond, err := p.Condition.toCondition()
	if err != nil {
		return configstore.SSLPolicy{}, fmt.Errorf("condition: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return configstore.SSLPolicy{}, errors.New("name is required")
	}
	var hstsAge time.Duration
	if strings.TrimSpace(p.HSTSMaxAge) != "" {
		hstsAge, err = time.ParseDuration(p.HSTSMaxAge)
		if err != nil {
			return configstore.SSLPolicy{}, fmt.Errorf("invalid hstsMaxAge: %w", err)
		}
	}
	return configstore.SSLPolicy{
		ID:                    p.ID,
		Name:                  strings.TrimSpace(p.Name),
		Description:           strings.TrimSpace(p.Description),
		Scope:                 scope,
		Condition:             cond,
		CertificateID:         strings.TrimSpace(p.CertificateID),
		EnforceHTTPS:          p.EnforceHTTPS,
		EnableHSTS:            p.EnableHSTS,
		HSTSMaxAge:            hstsAge,
		HSTSIncludeSubdomains: p.HSTSIncludeSubdomains,
		HSTSPreload:           p.HSTSPreload,
		MinTLSVersion:         strings.TrimSpace(p.MinTLSVersion),
		EnableOCSPStapling:    p.EnableOCSPStapling,
		ClientAuth:            p.ClientAuth,
		ClientCAIDs:           copyStringSlice(p.ClientCAIDs),
	}, nil
}

// AccessPolicyPayload models access control JSON schema.
type AccessPolicyPayload struct {
	ID           string           `json:"id,omitempty"`
	Name         string           `json:"name"`
	Description  string           `json:"description,omitempty"`
	Scope        ScopePayload     `json:"scope"`
	Condition    ConditionPayload `json:"condition"`
	Action       string           `json:"action"`
	ResponseCode int              `json:"responseCode,omitempty"`
	RedirectURL  string           `json:"redirectUrl,omitempty"`
}

func (p AccessPolicyPayload) toAccessPolicy() (configstore.AccessPolicy, error) {
	scope, err := p.Scope.toScope()
	if err != nil {
		return configstore.AccessPolicy{}, fmt.Errorf("scope: %w", err)
	}
	cond, err := p.Condition.toCondition()
	if err != nil {
		return configstore.AccessPolicy{}, fmt.Errorf("condition: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(p.Action))
	var mapped configstore.AccessAction
	switch action {
	case "allow", "allowed":
		mapped = configstore.AccessActionAllow
	case "deny", "blocked", "block":
		mapped = configstore.AccessActionDeny
	default:
		return configstore.AccessPolicy{}, errors.New("action must be allow or deny")
	}
	if strings.TrimSpace(p.Name) == "" {
		return configstore.AccessPolicy{}, errors.New("name is required")
	}
	return configstore.AccessPolicy{
		ID:           p.ID,
		Name:         strings.TrimSpace(p.Name),
		Description:  strings.TrimSpace(p.Description),
		Scope:        scope,
		Condition:    cond,
		Action:       mapped,
		ResponseCode: p.ResponseCode,
		RedirectURL:  strings.TrimSpace(p.RedirectURL),
	}, nil
}

// RewriteRulePayload models origin rewrite JSON schema.
type RewriteRulePayload struct {
	ID          string                `json:"id,omitempty"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Scope       ScopePayload          `json:"scope"`
	Condition   ConditionPayload      `json:"condition"`
	Actions     RewriteActionsPayload `json:"actions"`
	Priority    int                   `json:"priority,omitempty"`
}

func (p RewriteRulePayload) toRewriteRule() (configstore.RewriteRule, error) {
	scope, err := p.Scope.toScope()
	if err != nil {
		return configstore.RewriteRule{}, fmt.Errorf("scope: %w", err)
	}
	cond, err := p.Condition.toCondition()
	if err != nil {
		return configstore.RewriteRule{}, fmt.Errorf("condition: %w", err)
	}
	actions, err := p.Actions.toActions()
	if err != nil {
		return configstore.RewriteRule{}, fmt.Errorf("actions: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return configstore.RewriteRule{}, errors.New("name is required")
	}
	return configstore.RewriteRule{
		ID:          p.ID,
		Name:        strings.TrimSpace(p.Name),
		Description: strings.TrimSpace(p.Description),
		Scope:       scope,
		Condition:   cond,
		Actions:     actions,
		Priority:    p.Priority,
	}, nil
}

// ScopePayload mirrors configstore.PolicyScope.
type ScopePayload struct {
	Mode      string   `json:"mode,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// ConditionPayload mirrors configstore.Condition.
type ConditionPayload struct {
	Mode     string           `json:"mode,omitempty"`
	Matchers []MatcherPayload `json:"matchers,omitempty"`
}

// MatcherPayload mirrors configstore.Matcher.
type MatcherPayload struct {
	Type     string   `json:"type"`
	Key      string   `json:"key,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// RewriteActionsPayload mirrors configstore.RewriteActions.
type RewriteActionsPayload struct {
	SNIOverride  string                   `json:"sniOverride,omitempty"`
	HostOverride string                   `json:"hostOverride,omitempty"`
	URL          URLRewritePayload        `json:"url,omitempty"`
	Headers      []HeaderMutationPayload  `json:"headers,omitempty"`
	Upstream     *UpstreamOverridePayload `json:"upstream,omitempty"`
}

// URLRewritePayload mirrors configstore.URLRewrite.
type URLRewritePayload struct {
	Mode  string `json:"mode,omitempty"`
	Path  string `json:"path,omitempty"`
	Query string `json:"query,omitempty"`
}

// HeaderMutationPayload mirrors configstore.HeaderMutation.
type HeaderMutationPayload struct {
	Operation string `json:"operation"`
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
}

// UpstreamOverridePayload mirrors configstore.UpstreamOverride.
type UpstreamOverridePayload struct {
	PassHostHeader bool   `json:"passHostHeader"`
	UpstreamHost   string `json:"upstreamHost,omitempty"`
	Scheme         string `json:"scheme,omitempty"`
	ConnectTimeout string `json:"connectTimeout,omitempty"`
	ReadTimeout    string `json:"readTimeout,omitempty"`
	SendTimeout    string `json:"sendTimeout,omitempty"`
}

func (p ScopePayload) toScope() (configstore.PolicyScope, error) {
	mode := strings.TrimSpace(strings.ToLower(p.Mode))
	switch mode {
	case "", "any":
		return configstore.PolicyScope{Mode: "any"}, nil
	case "resources":
		if len(p.Resources) == 0 {
			return configstore.PolicyScope{}, errors.New("resources cannot be empty when mode=resources")
		}
		return configstore.PolicyScope{Mode: "resources", Resources: copyStringSlice(p.Resources)}, nil
	case "tags":
		if len(p.Tags) == 0 {
			return configstore.PolicyScope{}, errors.New("tags cannot be empty when mode=tags")
		}
		return configstore.PolicyScope{Mode: "tags", Tags: copyStringSlice(p.Tags)}, nil
	default:
		return configstore.PolicyScope{}, fmt.Errorf("unsupported scope mode %s", mode)
	}
}

func (p ConditionPayload) toCondition() (configstore.Condition, error) {
	mode := strings.TrimSpace(strings.ToLower(p.Mode))
	if mode == "" || mode == "any" {
		return configstore.Condition{Mode: "any"}, nil
	}
	if mode != "matchers" {
		return configstore.Condition{}, fmt.Errorf("unsupported condition mode %s", mode)
	}
	if len(p.Matchers) == 0 {
		return configstore.Condition{}, errors.New("matchers cannot be empty when mode=matchers")
	}
	matchers := make([]configstore.Matcher, 0, len(p.Matchers))
	for i, m := range p.Matchers {
		matcher, err := m.toMatcher()
		if err != nil {
			return configstore.Condition{}, fmt.Errorf("matcher[%d]: %w", i, err)
		}
		matchers = append(matchers, matcher)
	}
	return configstore.Condition{Mode: "matchers", Matchers: matchers}, nil
}

func (p MatcherPayload) toMatcher() (configstore.Matcher, error) {
	if strings.TrimSpace(p.Type) == "" {
		return configstore.Matcher{}, errors.New("matcher type is required")
	}
	return configstore.Matcher{
		Type:     strings.TrimSpace(p.Type),
		Key:      strings.TrimSpace(p.Key),
		Operator: strings.TrimSpace(p.Operator),
		Values:   copyStringSlice(p.Values),
	}, nil
}

func (p RewriteActionsPayload) toActions() (configstore.RewriteActions, error) {
	var actions configstore.RewriteActions
	hasAction := false
	if strings.TrimSpace(p.SNIOverride) != "" {
		actions.SNIOverride = strings.TrimSpace(p.SNIOverride)
		hasAction = true
	}
	if strings.TrimSpace(p.HostOverride) != "" {
		actions.HostOverride = strings.TrimSpace(p.HostOverride)
		hasAction = true
	}
	if p.URL != (URLRewritePayload{}) {
		actions.URL = configstore.URLRewrite{
			Mode:  strings.TrimSpace(p.URL.Mode),
			Path:  strings.TrimSpace(p.URL.Path),
			Query: strings.TrimSpace(p.URL.Query),
		}
		hasAction = true
	}
	if len(p.Headers) > 0 {
		headers := make([]configstore.HeaderMutation, 0, len(p.Headers))
		for i, h := range p.Headers {
			mutation, err := h.toMutation()
			if err != nil {
				return configstore.RewriteActions{}, fmt.Errorf("headers[%d]: %w", i, err)
			}
			headers = append(headers, mutation)
		}
		actions.Headers = headers
		hasAction = true
	}
	if p.Upstream != nil {
		override, err := p.Upstream.toOverride()
		if err != nil {
			return configstore.RewriteActions{}, fmt.Errorf("upstream: %w", err)
		}
		actions.Upstream = &override
		hasAction = true
	}
	if !hasAction {
		return configstore.RewriteActions{}, errors.New("at least one rewrite action must be specified")
	}
	return actions, nil
}

func (p HeaderMutationPayload) toMutation() (configstore.HeaderMutation, error) {
	op := strings.TrimSpace(strings.ToLower(p.Operation))
	switch op {
	case "set", "add", "delete":
	default:
		return configstore.HeaderMutation{}, fmt.Errorf("unsupported header operation %s", p.Operation)
	}
	if strings.TrimSpace(p.Name) == "" {
		return configstore.HeaderMutation{}, errors.New("header name is required")
	}
	return configstore.HeaderMutation{
		Operation: op,
		Name:      strings.TrimSpace(p.Name),
		Value:     p.Value,
	}, nil
}

func (p UpstreamOverridePayload) toOverride() (configstore.UpstreamOverride, error) {
	var connect, read, send time.Duration
	var err error
	if strings.TrimSpace(p.ConnectTimeout) != "" {
		connect, err = time.ParseDuration(p.ConnectTimeout)
		if err != nil {
			return configstore.UpstreamOverride{}, fmt.Errorf("connectTimeout: %w", err)
		}
	}
	if strings.TrimSpace(p.ReadTimeout) != "" {
		read, err = time.ParseDuration(p.ReadTimeout)
		if err != nil {
			return configstore.UpstreamOverride{}, fmt.Errorf("readTimeout: %w", err)
		}
	}
	if strings.TrimSpace(p.SendTimeout) != "" {
		send, err = time.ParseDuration(p.SendTimeout)
		if err != nil {
			return configstore.UpstreamOverride{}, fmt.Errorf("sendTimeout: %w", err)
		}
	}
	return configstore.UpstreamOverride{
		PassHostHeader: p.PassHostHeader,
		UpstreamHost:   strings.TrimSpace(p.UpstreamHost),
		Scheme:         strings.TrimSpace(p.Scheme),
		ConnectTimeout: connect,
		ReadTimeout:    read,
		SendTimeout:    send,
	}, nil
}

func copyStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	dst := make([]string, len(src))
	for i, v := range src {
		dst[i] = strings.TrimSpace(v)
	}
	return dst
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
