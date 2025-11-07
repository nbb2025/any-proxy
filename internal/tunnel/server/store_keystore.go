package server

import (
	"context"
	"errors"
	"fmt"

	"anyproxy.dev/any-proxy/internal/configstore"
)

// ErrInvalidKey indicates the supplied tunnel key is unknown or disabled.
var ErrInvalidKey = errors.New("tunnel key invalid")

// StoreKeyStore implements KeyStore using the shared config store snapshot.
type StoreKeyStore struct {
	store configstore.Store
}

// NewStoreKeyStore wraps a config store for tunnel key lookups.
func NewStoreKeyStore(store configstore.Store) *StoreKeyStore {
	return &StoreKeyStore{store: store}
}

// ValidateKey verifies the provided key against tunnel-agent definitions.
func (s *StoreKeyStore) ValidateKey(ctx context.Context, nodeID, key string) (SessionInfo, error) {
	if s.store == nil {
		return SessionInfo{}, fmt.Errorf("keystore not configured")
	}

	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		return SessionInfo{}, fmt.Errorf("snapshot error: %w", err)
	}

	hash := configstore.HashTunnelAgentKey(key)
	for _, agent := range snap.TunnelAgents {
		if !agent.Enabled {
			continue
		}
		if agent.NodeID != "" && agent.NodeID != nodeID {
			continue
		}
		if agent.KeyHash == hash {
			return SessionInfo{
				AgentID: agent.ID,
				NodeID:  agent.NodeID,
				GroupID: agent.GroupID,
			}, nil
		}
	}

	return SessionInfo{}, ErrInvalidKey
}
