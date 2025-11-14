package agent

import (
	"context"
	"errors"
	"sync"

	"anyproxy.dev/any-proxy/internal/configstore"
	tserver "anyproxy.dev/any-proxy/internal/tunnel/server"
)

type tunnelServerManager struct {
	logger  Logger
	mu      sync.Mutex
	servers map[string]*tunnelServerInstance
}

type tunnelServerInstance struct {
	cancel   context.CancelFunc
	keystore *snapshotKeyStore
	server   *tserver.Server
	groupID  string
}

type tunnelServerPlan struct {
	ingressAddr string
	groupID     string
	routes      []tserver.RouteConfig
	sessions    map[string]tserver.SessionInfo
}

func newTunnelServerManager(logger Logger) *tunnelServerManager {
	if logger == nil {
		logger = noopLogger{}
	}
	return &tunnelServerManager{
		logger:  logger,
		servers: make(map[string]*tunnelServerInstance),
	}
}

func (m *tunnelServerManager) Update(ctx context.Context, plans map[string]tunnelServerPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// stop servers no longer needed
	for addr, inst := range m.servers {
		if _, ok := plans[addr]; !ok {
			inst.cancel()
			delete(m.servers, addr)
		}
	}

	// start or update required servers
	for addr, plan := range plans {
		if inst, ok := m.servers[addr]; ok {
			inst.keystore.Update(plan.sessions)
			if err := inst.server.UpdateConfig(tserver.Config{GroupID: plan.groupID, Routes: plan.routes}); err != nil {
				m.logger.Printf("[edge] tunnel server config update failed addr=%s err=%v", addr, err)
			}
			continue
		}
		ks := newSnapshotKeyStore()
		ks.Update(plan.sessions)
		srv, err := tserver.New(tserver.Options{
			ListenAddr: addr,
			GroupID:    plan.groupID,
			Logger:     m.logger,
			KeyStore:   ks,
		})
		if err != nil {
			m.logger.Printf("[edge] start tunnel server failed addr=%s err=%v", addr, err)
			continue
		}
		if err := srv.UpdateConfig(tserver.Config{GroupID: plan.groupID, Routes: plan.routes}); err != nil {
			m.logger.Printf("[edge] tunnel server initial config failed addr=%s err=%v", addr, err)
			continue
		}
		srvCtx, cancel := context.WithCancel(ctx)
		m.servers[addr] = &tunnelServerInstance{
			cancel:   cancel,
			keystore: ks,
			server:   srv,
			groupID:  plan.groupID,
		}
		go func(addr string) {
			if err := srv.Serve(srvCtx); err != nil && !errors.Is(err, context.Canceled) {
				m.logger.Printf("[edge] tunnel server stopped addr=%s err=%v", addr, err)
			}
		}(addr)
	}
	return nil
}

func (m *tunnelServerManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr, inst := range m.servers {
		inst.cancel()
		delete(m.servers, addr)
	}
}

type snapshotKeyStore struct {
	mu      sync.RWMutex
	allowed map[string]tserver.SessionInfo
}

func newSnapshotKeyStore() *snapshotKeyStore {
	return &snapshotKeyStore{
		allowed: make(map[string]tserver.SessionInfo),
	}
}

func (s *snapshotKeyStore) Update(keys map[string]tserver.SessionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowed = make(map[string]tserver.SessionInfo, len(keys))
	for hash, info := range keys {
		s.allowed[hash] = info
	}
}

func (s *snapshotKeyStore) ValidateKey(ctx context.Context, nodeID, key string) (tserver.SessionInfo, error) {
	hash := configstore.HashTunnelAgentKey(key)
	s.mu.RLock()
	info, ok := s.allowed[hash]
	s.mu.RUnlock()
	if !ok {
		return tserver.SessionInfo{}, tserver.ErrInvalidKey
	}
	if info.NodeID != "" && nodeID != "" && info.NodeID != nodeID {
		return tserver.SessionInfo{}, tserver.ErrInvalidKey
	}
	return info, nil
}
