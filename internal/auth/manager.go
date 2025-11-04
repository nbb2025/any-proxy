package auth

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidCredentials indicates login credentials mismatch.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrInvalidToken indicates token parsing or validation failure.
	ErrInvalidToken = errors.New("auth: invalid token")
)

// Config captures authentication parameters sourced from environment.
type Config struct {
	Username       string
	Password       string
	JWTSecret      []byte
	AccessTokenTTL time.Duration
	RefreshTokenTTL time.Duration
	Issuer         string
}

// LoadConfigFromEnv initialises Config using environment variables.
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		Username:  strings.TrimSpace(os.Getenv("AUTH_USERNAME")),
		Password:  strings.TrimSpace(os.Getenv("AUTH_PASSWORD")),
		Issuer:    strings.TrimSpace(os.Getenv("AUTH_ISSUER")),
	}

	if cfg.Issuer == "" {
		cfg.Issuer = "any-proxy-control-plane"
	}

	secret := strings.TrimSpace(os.Getenv("AUTH_JWT_SECRET"))
	if secret == "" {
		return Config{}, errors.New("AUTH_JWT_SECRET must be provided")
	}
	cfg.JWTSecret = []byte(secret)

	if cfg.Username == "" || cfg.Password == "" {
		return Config{}, errors.New("AUTH_USERNAME and AUTH_PASSWORD must be provided")
	}

	accessTTL, err := parseTTL(os.Getenv("AUTH_ACCESS_TOKEN_TTL"), 24*time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("invalid AUTH_ACCESS_TOKEN_TTL: %w", err)
	}
	refreshTTL, err := parseTTL(os.Getenv("AUTH_REFRESH_TOKEN_TTL"), 14*24*time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("invalid AUTH_REFRESH_TOKEN_TTL: %w", err)
	}

	cfg.AccessTokenTTL = accessTTL
	cfg.RefreshTokenTTL = refreshTTL
	return cfg, nil
}

func parseTTL(raw string, fallback time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(raw)
}

// Manager handles credential verification and token lifecycle.
type Manager struct {
	cfg Config
}

// NewManager constructs a Manager using cfg.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.AccessTokenTTL <= 0 {
		return nil, errors.New("access token TTL must be positive")
	}
	if cfg.RefreshTokenTTL <= 0 {
		return nil, errors.New("refresh token TTL must be positive")
	}
	return &Manager{cfg: cfg}, nil
}

type tokenType string

const (
	typeAccess  tokenType = "access"
	typeRefresh tokenType = "refresh"
)

// Login verifies credentials and returns token pair.
func (m *Manager) Login(username, password string) (TokenPair, error) {
	if username != m.cfg.Username || password != m.cfg.Password {
		return TokenPair{}, ErrInvalidCredentials
	}
	return m.issuePair(username)
}

// Refresh issues a new token pair using a refresh token.
func (m *Manager) Refresh(token string) (TokenPair, error) {
	claims, err := m.parseToken(token, typeRefresh)
	if err != nil {
		return TokenPair{}, err
	}
	return m.issuePair(claims.Subject)
}

// ValidateAccess parses an access token and returns claims.
func (m *Manager) ValidateAccess(token string) (*Claims, error) {
	return m.parseToken(token, typeAccess)
}

func (m *Manager) issuePair(subject string) (TokenPair, error) {
	now := time.Now().UTC()
	access, err := m.signToken(subject, typeAccess, now, m.cfg.AccessTokenTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := m.signToken(subject, typeRefresh, now, m.cfg.RefreshTokenTTL)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    now.Add(m.cfg.AccessTokenTTL),
	}, nil
}

func (m *Manager) signToken(subject string, t tokenType, issuedAt time.Time, ttl time.Duration) (string, error) {
	claims := Claims{
		TokenType: string(t),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.cfg.JWTSecret)
}

func (m *Manager) parseToken(raw string, expected tokenType) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	token, err := parser.ParseWithClaims(strings.TrimSpace(raw), &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return m.cfg.JWTSecret, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if claims.TokenType != string(expected) {
		return nil, ErrInvalidToken
	}
	if err := jwt.NewValidator().Validate(claims); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// Claims represents JWT claims used by the control plane.
type Claims struct {
	TokenType string `json:"type"`
	jwt.RegisteredClaims
}

// TokenPair groups access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}
