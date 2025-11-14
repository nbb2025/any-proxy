package auth

import "context"

// PrincipalType represents the origin of an authenticated request.
type PrincipalType string

const (
	// PrincipalTypeUser indicates the request used a control-plane user token.
	PrincipalTypeUser PrincipalType = "user"
	// PrincipalTypeNode indicates the request used a node-specific key.
	PrincipalTypeNode PrincipalType = "node"
)

// Principal captures authentication data attached to a request context.
type Principal struct {
	Type    PrincipalType
	Subject string
	NodeID  string
}

type principalContextKey struct{}

// ContextWithPrincipal stores the authenticated principal inside ctx.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext extracts the authenticated principal if present.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// NodeKeyValidator checks whether a node secret is valid for the supplied node.
type NodeKeyValidator interface {
	ValidateNodeKey(ctx context.Context, nodeID, secret string) error
}

// ErrInvalidNodeKey indicates a secret mismatch or missing node key.
var ErrInvalidNodeKey = ErrInvalidToken
