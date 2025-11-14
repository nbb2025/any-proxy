package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// LoginHandler handles POST /auth/login.
func LoginHandler(mgr *Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		tokens, err := mgr.Login(strings.TrimSpace(payload.Username), payload.Password)
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	})
}

// RefreshHandler handles POST /auth/refresh.
func RefreshHandler(mgr *Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			RefreshToken string `json:"refreshToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.RefreshToken) == "" {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		tokens, err := mgr.Refresh(payload.RefreshToken)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	})
}

const (
	bearerPrefix = "bearer "
	edgePrefix   = "edge "
)

// Middleware wraps an http.Handler enforcing access token validation.
func Middleware(next http.Handler, mgr *Manager, opts ...MiddlewareOption) http.Handler {
	config := middlewareConfig{
		skipped:      map[string]struct{}{},
		nodeKeyPaths: map[string]struct{}{},
	}
	for _, opt := range opts {
		opt(&config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.isSkipped(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if header == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		lower := strings.ToLower(header)
		switch {
		case strings.HasPrefix(lower, bearerPrefix):
			token := strings.TrimSpace(header[len(bearerPrefix):])
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := mgr.ValidateAccess(token)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := ContextWithPrincipal(r.Context(), Principal{
				Type:    PrincipalTypeUser,
				Subject: claims.Subject,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		case strings.HasPrefix(lower, edgePrefix):
			if config.nodeKeyValidator == nil || !config.allowNodeKey(r.Method, r.URL.Path) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			nodeID, secret, ok := parseEdgeCredential(header[len(edgePrefix):])
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := config.nodeKeyValidator.ValidateNodeKey(r.Context(), nodeID, secret); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := ContextWithPrincipal(r.Context(), Principal{
				Type:   PrincipalTypeNode,
				NodeID: nodeID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

type middlewareConfig struct {
	skipped          map[string]struct{}
	nodeKeyPaths     map[string]struct{}
	nodeKeyValidator NodeKeyValidator
}

func (c *middlewareConfig) isSkipped(method, path string) bool {
	if _, ok := c.skipped["* "+path]; ok {
		return true
	}
	if _, ok := c.skipped[strings.ToUpper(method)+" "+path]; ok {
		return true
	}
	if path == "/" {
		return false
	}
	for key := range c.skipped {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		kMethod, kPath := parts[0], parts[1]
		if !strings.HasSuffix(kPath, "*") {
			continue
		}
		prefix := strings.TrimSuffix(kPath, "*")
		if strings.HasPrefix(path, prefix) && (kMethod == "*" || strings.EqualFold(kMethod, method)) {
			return true
		}
	}
	return false
}

func (c *middlewareConfig) allowNodeKey(method, path string) bool {
	if c.nodeKeyValidator == nil || len(c.nodeKeyPaths) == 0 {
		return false
	}
	if _, ok := c.nodeKeyPaths["* "+path]; ok {
		return true
	}
	if _, ok := c.nodeKeyPaths[strings.ToUpper(method)+" "+path]; ok {
		return true
	}
	if path == "/" {
		return false
	}
	for key := range c.nodeKeyPaths {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		kMethod, kPath := parts[0], parts[1]
		if !strings.HasSuffix(kPath, "*") {
			continue
		}
		prefix := strings.TrimSuffix(kPath, "*")
		if strings.HasPrefix(path, prefix) && (kMethod == "*" || strings.EqualFold(kMethod, method)) {
			return true
		}
	}
	return false
}

// MiddlewareOption customises middleware behaviour.
type MiddlewareOption func(*middlewareConfig)

// WithSkip adds routes exempted from authentication (method prefix wildcard supported).
// method accepts "*" for all methods.
func WithSkip(method, path string) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		if cfg.skipped == nil {
			cfg.skipped = make(map[string]struct{})
		}
		cfg.skipped[strings.ToUpper(method)+" "+path] = struct{}{}
	}
}

// WithNodeKeyValidator enables node-key based authentication on the provided routes.
// Routes should follow the "METHOD /path" format and support "*" wildcards similar to WithSkip.
func WithNodeKeyValidator(validator NodeKeyValidator, routes ...string) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.nodeKeyValidator = validator
		if cfg.nodeKeyPaths == nil {
			cfg.nodeKeyPaths = make(map[string]struct{})
		}
		for _, route := range routes {
			spec := strings.TrimSpace(route)
			if spec == "" {
				continue
			}
			parts := strings.SplitN(spec, " ", 2)
			if len(parts) != 2 {
				cfg.nodeKeyPaths["* "+spec] = struct{}{}
				continue
			}
			method := strings.TrimSpace(parts[0])
			path := strings.TrimSpace(parts[1])
			if method == "" {
				method = "*"
			}
			cfg.nodeKeyPaths[strings.ToUpper(method)+" "+path] = struct{}{}
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseEdgeCredential(raw string) (string, string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	nodeID := strings.TrimSpace(parts[0])
	secret := strings.TrimSpace(parts[1])
	if nodeID == "" || secret == "" {
		return "", "", false
	}
	return nodeID, secret, true
}
