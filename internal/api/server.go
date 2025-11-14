package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"anyproxy.dev/any-proxy/internal/auth"
	"anyproxy.dev/any-proxy/internal/configstore"
)

const (
	defaultWatchTimeout = 55 * time.Second
)

// Server exposes HTTP endpoints for managing configuration and serving agent requests.
type Server struct {
	store         configstore.Store
	logger        Logger
	health        func(context.Context) error
	versionLister AgentVersionLister
}

// Logger abstracts the logging dependency to simplify unit testing.
type Logger interface {
	Printf(format string, v ...any)
}

// Option applies configuration to the Server.
type Option func(*Server)

// AgentVersionLister enumerates available agent versions.
type AgentVersionLister func(context.Context) (AgentVersionListing, error)

type AgentVersionListing struct {
	Versions       []string
	LatestResolved string
}

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

// WithAgentVersionLister injects the version provider used by /v1/agent-versions.
func WithAgentVersionLister(lister AgentVersionLister) Option {
	return func(s *Server) {
		s.versionLister = lister
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
	mux.HandleFunc("/v1/nodes/register", s.handleNodeRegister)
	mux.HandleFunc("/v1/nodes", s.handleNodes)
	mux.HandleFunc("/v1/nodes/desired-version", s.handleNodeDesiredVersionBatch)
	mux.HandleFunc("/v1/nodes/", s.handleNodesByID)
	mux.HandleFunc("/v1/node-groups", s.handleNodeGroups)
	mux.HandleFunc("/v1/node-groups/", s.handleNodeGroupsByID)
	mux.HandleFunc("/v1/tunnel-groups", s.handleTunnelGroups)
	mux.HandleFunc("/v1/tunnel-groups/", s.handleTunnelGroupsByID)
	mux.HandleFunc("/v1/domains", s.handleDomains)
	mux.HandleFunc("/v1/domains/", s.handleDomainsByID)
	mux.HandleFunc("/v1/tunnels", s.handleTunnels)
	mux.HandleFunc("/v1/tunnels/", s.handleTunnelsByID)
	mux.HandleFunc("/v1/tunnel-agents", s.handleTunnelAgents)
	mux.HandleFunc("/v1/tunnel-agents/", s.handleTunnelAgentsByID)
	mux.HandleFunc("/v1/certificates", s.handleCertificates)
	mux.HandleFunc("/v1/certificates/", s.handleCertificatesByID)
	mux.HandleFunc("/v1/ssl-policies", s.handleSSLPolicies)
	mux.HandleFunc("/v1/ssl-policies/", s.handleSSLPoliciesByID)
	mux.HandleFunc("/v1/access-policies", s.handleAccessPolicies)
	mux.HandleFunc("/v1/access-policies/", s.handleAccessPoliciesByID)
	mux.HandleFunc("/v1/rewrite-rules", s.handleRewriteRules)
	mux.HandleFunc("/v1/rewrite-rules/", s.handleRewriteRulesByID)
	mux.HandleFunc("/v1/agent-versions", s.handleAgentVersions)
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

func (s *Server) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload NodeRegisterPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	nodeID := strings.TrimSpace(payload.NodeID)
	if nodeID == "" {
		http.Error(w, "nodeId is required", http.StatusBadRequest)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	shouldProvisionKey := false
	switch principal.Type {
	case auth.PrincipalTypeUser:
		shouldProvisionKey = true
	case auth.PrincipalTypeNode:
		if strings.TrimSpace(principal.NodeID) == "" || principal.NodeID != nodeID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	addresses := append([]string(nil), payload.Addresses...)
	if remote := extractRemoteIP(r.RemoteAddr); remote != "" {
		addresses = appendUnique(addresses, remote)
	}

	category := configstore.NodeCategoryWaiting
	if payload.Category != "" {
		if parsed, err := parseNodeCategory(payload.Category); err == nil {
			category = parsed
		}
	}

	reg := configstore.NodeRegistration{
		ID:           nodeID,
		Kind:         strings.TrimSpace(payload.Kind),
		GroupID:      strings.TrimSpace(payload.GroupID),
		Name:         strings.TrimSpace(payload.Name),
		Category:     category,
		Hostname:     strings.TrimSpace(payload.Hostname),
		Addresses:    addresses,
		Version:      strings.TrimSpace(payload.Version),
		AgentVersion: strings.TrimSpace(payload.AgentVersion),
	}

	snap, node, err := s.store.RegisterOrUpdateNode(reg)
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrInvalidGroup):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		}
		return
	}

	var issuedKey string
	if shouldProvisionKey && strings.TrimSpace(node.NodeKeyHash) == "" {
		secret, hash, err := configstore.GenerateNodeKey()
		if err != nil {
			http.Error(w, fmt.Sprintf("key generation error: %v", err), http.StatusInternalServerError)
			return
		}
		reg.NodeKeyHash = hash
		nextVersion := node.NodeKeyVersion
		if nextVersion <= 0 {
			nextVersion = 1
		} else {
			nextVersion++
		}
		reg.NodeKeyVersion = nextVersion

		snap, node, err = s.store.RegisterOrUpdateNode(reg)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrInvalidGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}
		issuedKey = secret
	}

	resp := map[string]any{
		"node":    node,
		"version": snap.Version,
	}
	if issuedKey != "" {
		resp["nodeKey"] = issuedKey
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes":   snap.Nodes,
			"groups":  snap.NodeGroups,
			"version": snap.Version,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/nodes/")
	if id == "" {
		http.Error(w, "missing node id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var payload NodeUpdatePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
			return
		}

		update := configstore.NodeUpdate{}
		hasChange := false

		if payload.GroupID != nil {
			groupVal := strings.TrimSpace(*payload.GroupID)
			update.GroupID = &groupVal
			hasChange = true
		}
		if payload.Name != nil {
			nameVal := strings.TrimSpace(*payload.Name)
			update.Name = &nameVal
			hasChange = true
		}
		if payload.Category != nil {
			cat, err := parseNodeCategory(*payload.Category)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid category: %v", err), http.StatusBadRequest)
				return
			}
			update.Category = &cat
			hasChange = true
		}
		if payload.AgentDesiredVersion != nil {
			desired := strings.TrimSpace(*payload.AgentDesiredVersion)
			update.AgentDesiredVersion = &desired
			hasChange = true
		}
		if !hasChange {
			http.Error(w, "no changes requested", http.StatusBadRequest)
			return
		}

		snap, node, err := s.store.UpdateNode(id, update)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrNodeNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			case errors.Is(err, configstore.ErrGroupNotFound):
				http.Error(w, "group not found", http.StatusNotFound)
			case errors.Is(err, configstore.ErrInvalidGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"node":    node,
			"version": snap.Version,
		})
	case http.MethodDelete:
		snap, err := s.store.DeleteNode(id)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrNodeNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": snap.Version,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodeDesiredVersionBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload NodeDesiredVersionBatchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if len(payload.NodeIDs) == 0 {
		http.Error(w, "nodeIds required", http.StatusBadRequest)
		return
	}
	if payload.AgentDesiredVersion == nil {
		http.Error(w, "agentDesiredVersion required", http.StatusBadRequest)
		return
	}

	desired := strings.TrimSpace(*payload.AgentDesiredVersion)
	update := configstore.NodeUpdate{AgentDesiredVersion: &desired}

	updated := make([]configstore.EdgeNode, 0, len(payload.NodeIDs))
	var version int64
	for _, rawID := range payload.NodeIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			http.Error(w, "node id cannot be empty", http.StatusBadRequest)
			return
		}
		snap, node, err := s.store.UpdateNode(id, update)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrNodeNotFound):
				http.Error(w, fmt.Sprintf("node %s not found", id), http.StatusNotFound)
			case errors.Is(err, configstore.ErrGroupNotFound):
				http.Error(w, fmt.Sprintf("group for node %s not found", id), http.StatusNotFound)
			default:
				http.Error(w, fmt.Sprintf("update node %s failed: %v", id, err), http.StatusInternalServerError)
			}
			return
		}
		version = snap.Version
		updated = append(updated, node)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":   updated,
		"version": version,
		"updated": len(updated),
	})
}

func (s *Server) handleNodeGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"groups":  snap.NodeGroups,
			"version": snap.Version,
		})
	case http.MethodPost:
		var payload NodeGroupPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
			return
		}

		group, err := payload.toNodeGroup(nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
			return
		}

		snap, stored, err := s.store.UpsertNodeGroup(group)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrInvalidGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			case errors.Is(err, configstore.ErrProtectedGroup):
				http.Error(w, err.Error(), http.StatusForbidden)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"group":   stored,
			"version": snap.Version,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodeGroupsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/node-groups/")
	if id == "" {
		http.Error(w, "missing group id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var payload NodeGroupPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
			return
		}
		payload.ID = id

		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		var existing *configstore.NodeGroup
		for i := range snap.NodeGroups {
			if snap.NodeGroups[i].ID == id {
				existing = &snap.NodeGroups[i]
				break
			}
		}
		if existing == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		group, err := payload.toNodeGroup(existing)
		if err != nil {
			http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
			return
		}
		group.ID = id

		snap, stored, err := s.store.UpsertNodeGroup(group)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrInvalidGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			case errors.Is(err, configstore.ErrProtectedGroup):
				http.Error(w, err.Error(), http.StatusForbidden)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"group":   stored,
			"version": snap.Version,
		})
	case http.MethodDelete:
		snap, err := s.store.DeleteNodeGroup(id)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrGroupNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			case errors.Is(err, configstore.ErrProtectedGroup):
				http.Error(w, err.Error(), http.StatusForbidden)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"version": snap.Version,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTunnelGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"groups":  snap.TunnelGroups,
			"version": snap.Version,
		})
	case http.MethodPost:
		var payload TunnelGroupPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
			return
		}
		group, err := payload.toTunnelGroup(nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
			return
		}
		snap, stored, err := s.store.UpsertTunnelGroup(group)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrInvalidTunnelGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"group":   stored,
			"version": snap.Version,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTunnelGroupsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/tunnel-groups/")
	if id == "" {
		http.Error(w, "missing group id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var payload TunnelGroupPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
			return
		}
		payload.ID = id

		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		existing := findTunnelGroupByID(snap, id)
		if existing == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		group, err := payload.toTunnelGroup(existing)
		if err != nil {
			http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
			return
		}
		group.ID = id

		snap, stored, err := s.store.UpsertTunnelGroup(group)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrInvalidTunnelGroup):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"group":   stored,
			"version": snap.Version,
		})
	case http.MethodDelete:
		snap, err := s.store.DeleteTunnelGroup(id)
		if err != nil {
			switch {
			case errors.Is(err, configstore.ErrTunnelGroupNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			case errors.Is(err, configstore.ErrTunnelGroupInUse):
				http.Error(w, err.Error(), http.StatusConflict)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"version": snap.Version})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

func (s *Server) handleTunnelAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"agents":  snap.TunnelAgents,
			"version": snap.Version,
		})
	case http.MethodPost:
		s.handleUpsertTunnelAgent(w, r, "")
	case http.MethodPut:
		s.handleUpsertTunnelAgent(w, r, "")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTunnelAgentsByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/tunnel-agents/")
	if path == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}
	parts := strings.Split(path, "/")
	id := parts[0]
	if id == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}

	if len(parts) == 2 && parts[1] == "refresh-key" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleTunnelAgentRefreshKey(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		s.handleUpsertTunnelAgent(w, r, id)
	case http.MethodDelete:
		if _, err := s.store.DeleteTunnelAgent(id); err != nil {
			switch {
			case errors.Is(err, configstore.ErrTunnelAgentNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			default:
				http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
			}
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

func (s *Server) handleAgentVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	listing := AgentVersionListing{Versions: []string{"latest"}}
	if s.versionLister != nil {
		result, err := s.versionLister(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("list versions failed: %v", err), http.StatusInternalServerError)
			return
		}
		if len(result.Versions) > 0 {
			listing = result
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"versions": listing.Versions,
		"latest":   listing.LatestResolved,
	})
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

func (s *Server) handleUpsertTunnelAgent(w http.ResponseWriter, r *http.Request, forcedID string) {
	var payload TunnelAgentPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if forcedID != "" {
		payload.ID = forcedID
	}

	var existing *configstore.TunnelAgent
	if payload.ID != "" {
		snap, err := s.store.Snapshot(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
			return
		}
		existing = findTunnelAgentByID(snap, payload.ID)
		if existing == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}

	agent, rotateKey, err := payload.toTunnelAgent(existing)
	if err != nil {
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}

	var secret string
	if existing == nil || rotateKey || strings.TrimSpace(agent.KeyHash) == "" {
		sec, hash, err := configstore.GenerateTunnelAgentKey()
		if err != nil {
			http.Error(w, fmt.Sprintf("key generation error: %v", err), http.StatusInternalServerError)
			return
		}
		secret = sec
		agent.KeyHash = hash
		if existing != nil {
			agent.KeyVersion = existing.KeyVersion + 1
		} else if agent.KeyVersion == 0 {
			agent.KeyVersion = 1
		}
	}

	snap, stored, err := s.store.UpsertTunnelAgent(agent)
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrInvalidTunnelAgent):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, configstore.ErrTunnelGroupNotFound):
			http.Error(w, "tunnel group not found", http.StatusBadRequest)
		default:
			http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		}
		return
	}

	resp := map[string]any{
		"agent":   stored,
		"version": snap.Version,
	}
	if secret != "" {
		resp["agentKey"] = secret
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleTunnelAgentRefreshKey(w http.ResponseWriter, r *http.Request, id string) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("snapshot error: %v", err), http.StatusInternalServerError)
		return
	}
	existing := findTunnelAgentByID(snap, id)
	if existing == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	agent := *existing
	secret, hash, err := configstore.GenerateTunnelAgentKey()
	if err != nil {
		http.Error(w, fmt.Sprintf("key generation error: %v", err), http.StatusInternalServerError)
		return
	}
	agent.KeyHash = hash
	agent.KeyVersion++

	newSnap, stored, err := s.store.UpsertTunnelAgent(agent)
	if err != nil {
		http.Error(w, fmt.Sprintf("store error: %v", err), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"agent":    stored,
		"version":  newSnap.Version,
		"agentKey": secret,
	}
	writeJSON(w, http.StatusOK, resp)
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

type NodeGroupPayload struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
}

func (p NodeGroupPayload) toNodeGroup(existing *configstore.NodeGroup) (configstore.NodeGroup, error) {
	var group configstore.NodeGroup
	if existing != nil {
		group = *existing
	}

	if id := strings.TrimSpace(p.ID); id != "" {
		group.ID = id
	} else if existing == nil {
		group.ID = ""
	}

	if name := strings.TrimSpace(p.Name); name != "" {
		group.Name = name
	} else if existing == nil || strings.TrimSpace(group.Name) == "" {
		return configstore.NodeGroup{}, errors.New("name is required")
	}

	if desc := strings.TrimSpace(p.Description); desc != "" || existing == nil {
		group.Description = desc
	}

	if catRaw := strings.TrimSpace(p.Category); catRaw != "" {
		category, err := parseNodeCategory(catRaw)
		if err != nil {
			return configstore.NodeGroup{}, err
		}
		group.Category = category
	} else if existing == nil {
		return configstore.NodeGroup{}, errors.New("category is required")
	}

	return group, nil
}

type TunnelGroupPayload struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	ListenAddress  string   `json:"listenAddress,omitempty"`
	EdgeNodeIDs    []string `json:"edgeNodeIds,omitempty"`
	Transports     []string `json:"transports,omitempty"`
	EnableCompress *bool    `json:"enableCompress,omitempty"`
}

func (p TunnelGroupPayload) toTunnelGroup(existing *configstore.TunnelGroup) (configstore.TunnelGroup, error) {
	var group configstore.TunnelGroup
	if existing != nil {
		group = *existing
	}

	if id := strings.TrimSpace(p.ID); id != "" {
		group.ID = id
	} else if existing == nil {
		group.ID = ""
	}

	if name := strings.TrimSpace(p.Name); name != "" {
		group.Name = name
	} else if existing == nil {
		return configstore.TunnelGroup{}, fmt.Errorf("name is required")
	}

	if desc := strings.TrimSpace(p.Description); desc != "" || p.Description == "" {
		group.Description = strings.TrimSpace(p.Description)
	}

	if addr := strings.TrimSpace(p.ListenAddress); addr != "" {
		group.ListenAddress = addr
	}

	if len(p.EdgeNodeIDs) > 0 {
		group.EdgeNodeIDs = append([]string(nil), p.EdgeNodeIDs...)
	}
	if len(p.Transports) > 0 {
		group.Transports = append([]string(nil), p.Transports...)
	}
	if p.EnableCompress != nil {
		group.EnableCompress = *p.EnableCompress
	}
	return group, nil
}

type TunnelAgentPayload struct {
	ID          string                      `json:"id,omitempty"`
	NodeID      string                      `json:"nodeId"`
	GroupID     string                      `json:"groupId"`
	Description string                      `json:"description,omitempty"`
	Enabled     *bool                       `json:"enabled,omitempty"`
	RotateKey   bool                        `json:"rotateKey,omitempty"`
	Services    []TunnelAgentServicePayload `json:"services,omitempty"`
}

type TunnelAgentServicePayload struct {
	ID                string `json:"id,omitempty"`
	Protocol          string `json:"protocol"`
	LocalAddress      string `json:"localAddress"`
	LocalPort         int    `json:"localPort"`
	RemotePort        int    `json:"remotePort"`
	EnableCompression *bool  `json:"enableCompression,omitempty"`
	Description       string `json:"description,omitempty"`
}

func (p TunnelAgentPayload) toTunnelAgent(existing *configstore.TunnelAgent) (configstore.TunnelAgent, bool, error) {
	var agent configstore.TunnelAgent
	if existing != nil {
		agent = *existing
	} else {
		agent.Enabled = true
	}

	if id := strings.TrimSpace(p.ID); id != "" {
		agent.ID = id
	}

	if nodeID := strings.TrimSpace(p.NodeID); nodeID != "" || existing == nil {
		if nodeID == "" {
			return configstore.TunnelAgent{}, false, fmt.Errorf("nodeId is required")
		}
		agent.NodeID = nodeID
	}

	if groupID := strings.TrimSpace(p.GroupID); groupID != "" || existing == nil {
		if groupID == "" {
			return configstore.TunnelAgent{}, false, fmt.Errorf("groupId is required")
		}
		agent.GroupID = groupID
	}

	if desc := strings.TrimSpace(p.Description); desc != "" || p.Description == "" {
		agent.Description = strings.TrimSpace(p.Description)
	}

	if p.Enabled != nil {
		agent.Enabled = *p.Enabled
	}

	if p.Services != nil {
		services := make([]configstore.TunnelAgentService, len(p.Services))
		for i := range p.Services {
			svc, err := p.Services[i].toService()
			if err != nil {
				return configstore.TunnelAgent{}, false, err
			}
			services[i] = svc
		}
		agent.Services = services
	}

	return agent, p.RotateKey, nil
}

func (p TunnelAgentServicePayload) toService() (configstore.TunnelAgentService, error) {
	if p.RemotePort <= 0 {
		return configstore.TunnelAgentService{}, fmt.Errorf("remotePort must be > 0")
	}
	svc := configstore.TunnelAgentService{
		ID:           strings.TrimSpace(p.ID),
		Protocol:     strings.TrimSpace(p.Protocol),
		LocalAddress: strings.TrimSpace(p.LocalAddress),
		LocalPort:    p.LocalPort,
		RemotePort:   p.RemotePort,
		Description:  strings.TrimSpace(p.Description),
	}
	if svc.Protocol == "" {
		svc.Protocol = "tcp"
	}
	if svc.LocalAddress == "" {
		svc.LocalAddress = "127.0.0.1"
	}
	if svc.LocalPort == 0 {
		svc.LocalPort = svc.RemotePort
	}
	if p.EnableCompression != nil {
		svc.EnableCompression = *p.EnableCompression
	}
	return svc, nil
}

func findTunnelGroupByID(snap configstore.ConfigSnapshot, id string) *configstore.TunnelGroup {
	for i := range snap.TunnelGroups {
		if snap.TunnelGroups[i].ID == id {
			return &snap.TunnelGroups[i]
		}
	}
	return nil
}

func findTunnelAgentByID(snap configstore.ConfigSnapshot, id string) *configstore.TunnelAgent {
	for i := range snap.TunnelAgents {
		if snap.TunnelAgents[i].ID == id {
			return &snap.TunnelAgents[i]
		}
	}
	return nil
}

type NodeRegisterPayload struct {
	NodeID       string   `json:"nodeId"`
	Kind         string   `json:"kind,omitempty"`
	Name         string   `json:"name,omitempty"`
	Category     string   `json:"category,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
	Version      string   `json:"version,omitempty"`
	AgentVersion string   `json:"agentVersion,omitempty"`
	GroupID      string   `json:"groupId,omitempty"`
}

type NodeUpdatePayload struct {
	GroupID             *string `json:"groupId,omitempty"`
	Name                *string `json:"name,omitempty"`
	Category            *string `json:"category,omitempty"`
	AgentDesiredVersion *string `json:"agentDesiredVersion,omitempty"`
}

type NodeDesiredVersionBatchPayload struct {
	NodeIDs             []string `json:"nodeIds"`
	AgentDesiredVersion *string  `json:"agentDesiredVersion"`
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
	Sticky                 bool                 `json:"sticky,omitempty"`
	TimeoutProxy           string               `json:"timeoutProxy,omitempty"`
	TimeoutRead            string               `json:"timeoutRead,omitempty"`
	TimeoutSend            string               `json:"timeoutSend,omitempty"`
	DisplayName            string               `json:"displayName,omitempty"`
	GroupName              string               `json:"groupName,omitempty"`
	Remark                 string               `json:"remark,omitempty"`
	ForwardMode            string               `json:"forwardMode,omitempty"`
	LoadBalancingAlgorithm string               `json:"loadBalancingAlgorithm,omitempty"`
	InboundListeners       []routeListenerInput `json:"inboundListeners,omitempty"`
	OutboundListeners      []routeListenerInput `json:"outboundListeners,omitempty"`
}

type routeListenerInput struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func (r RouteMetadataInput) toRouteMeta() (configstore.RouteMeta, error) {
	parse := func(raw string) (time.Duration, error) {
		if raw == "" {
			return 0, nil
		}
		return time.ParseDuration(raw)
	}

	var err error
	parseListeners := func(inputs []routeListenerInput) ([]configstore.RouteListener, error) {
		if len(inputs) == 0 {
			return nil, nil
		}
		listeners := make([]configstore.RouteListener, 0, len(inputs))
		for idx, listener := range inputs {
			protocol := strings.ToUpper(strings.TrimSpace(listener.Protocol))
			if protocol != "HTTP" && protocol != "HTTPS" {
				return nil, fmt.Errorf("listener[%d]: protocol must be HTTP or HTTPS", idx)
			}
			if listener.Port <= 0 || listener.Port > 65535 {
				return nil, fmt.Errorf("listener[%d]: port must be between 1-65535", idx)
			}
			listeners = append(listeners, configstore.RouteListener{
				Protocol: protocol,
				Port:     listener.Port,
			})
		}
		return listeners, nil
	}

	meta := configstore.RouteMeta{
		Sticky:                 r.Sticky,
		DisplayName:            strings.TrimSpace(r.DisplayName),
		GroupName:              strings.TrimSpace(r.GroupName),
		Remark:                 strings.TrimSpace(r.Remark),
		ForwardMode:            strings.TrimSpace(strings.ToLower(r.ForwardMode)),
		LoadBalancingAlgorithm: strings.TrimSpace(strings.ToLower(r.LoadBalancingAlgorithm)),
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
	if meta.InboundListeners, err = parseListeners(r.InboundListeners); err != nil {
		return configstore.RouteMeta{}, fmt.Errorf("inboundListeners: %w", err)
	}
	if meta.OutboundListeners, err = parseListeners(r.OutboundListeners); err != nil {
		return configstore.RouteMeta{}, fmt.Errorf("outboundListeners: %w", err)
	}

	return meta, nil
}

// TunnelPayload describes the REST payload for tunnel definitions.
type TunnelPayload struct {
	ID          string              `json:"id,omitempty"`
	GroupID     string              `json:"groupId"`
	Protocol    string              `json:"protocol"`
	BindHost    string              `json:"bindHost"`
	BindPort    int                 `json:"bindPort"`
	BridgeBind  string              `json:"bridgeBind,omitempty"`
	BridgePort  int                 `json:"bridgePort,omitempty"`
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

func parseNodeCategory(raw string) (configstore.NodeCategory, error) {
	switch val := strings.ToLower(strings.TrimSpace(raw)); val {
	case "waiting", "pending", "unassigned", "待分组":
		return configstore.NodeCategoryWaiting, nil
	case "cdn":
		return configstore.NodeCategoryCDN, nil
	case "tunnel", "penetration", "intranet", "内网穿透":
		return configstore.NodeCategoryTunnel, nil
	default:
		return "", fmt.Errorf("invalid node category: %s", raw)
	}
}

func appendUnique(items []string, value string) []string {
	val := strings.TrimSpace(value)
	if val == "" {
		return items
	}
	for _, item := range items {
		if item == val {
			return items
		}
	}
	return append(items, val)
}

func extractRemoteIP(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return strings.TrimSpace(host)
}

// Validate checks the tunnel input.
func (p TunnelPayload) Validate() error {
	if strings.TrimSpace(p.GroupID) == "" {
		return errors.New("groupId is required")
	}
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
	if p.BridgePort < 0 || p.BridgePort > 65535 {
		return errors.New("bridgePort must be between 0 and 65535")
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
		GroupID:     p.GroupID,
		Protocol:    strings.ToLower(p.Protocol),
		BindHost:    p.BindHost,
		BindPort:    p.BindPort,
		BridgeBind:  p.BridgeBind,
		BridgePort:  p.BridgePort,
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
