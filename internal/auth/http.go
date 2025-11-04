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

// Middleware wraps an http.Handler enforcing access token validation.
func Middleware(next http.Handler, mgr *Manager, opts ...MiddlewareOption) http.Handler {
	config := middlewareConfig{
		skipped: map[string]struct{}{},
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
		if header == "" || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(header[7:])
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := mgr.ValidateAccess(token); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type middlewareConfig struct {
	skipped map[string]struct{}
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

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

