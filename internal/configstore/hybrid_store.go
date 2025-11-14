package configstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// HybridStore keeps configuration snapshots in etcd while persisting management data in Postgres.
type HybridStore struct {
	config *EtcdStore
	mgmt   *PGStore
}

var _ Store = (*HybridStore)(nil)

// NewHybridStore composes etcd + Postgres stores and removes legacy management keys from etcd.
func NewHybridStore(config *EtcdStore, mgmt *PGStore) (*HybridStore, error) {
	if config == nil {
		return nil, errors.New("hybridstore: etcd store is nil")
	}
	if mgmt == nil {
		return nil, errors.New("hybridstore: pg store is nil")
	}
	store := &HybridStore{
		config: config,
		mgmt:   mgmt,
	}
	if err := store.purgeManagementKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("purge etcd management keys: %w", err)
	}
	return store, nil
}

// Snapshot reads config from etcd and overlays management data from Postgres.
func (h *HybridStore) Snapshot(ctx context.Context) (ConfigSnapshot, error) {
	base, err := h.config.Snapshot(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return h.overlayManagement(ctx, base)
}

// Watch delegates to etcd for revision semantics, then overlays management data.
func (h *HybridStore) Watch(ctx context.Context, since int64) (ConfigSnapshot, error) {
	base, err := h.config.Watch(ctx, since)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return h.overlayManagement(ctx, base)
}

func (h *HybridStore) UpsertDomain(route DomainRoute) (ConfigSnapshot, error) {
	return h.config.UpsertDomain(route)
}

func (h *HybridStore) DeleteDomain(id string) (ConfigSnapshot, error) {
	return h.config.DeleteDomain(id)
}

func (h *HybridStore) UpsertTunnel(route TunnelRoute) (ConfigSnapshot, error) {
	return h.config.UpsertTunnel(route)
}

func (h *HybridStore) DeleteTunnel(id string) (ConfigSnapshot, error) {
	return h.config.DeleteTunnel(id)
}

func (h *HybridStore) UpsertCertificate(cert Certificate) (ConfigSnapshot, error) {
	return h.config.UpsertCertificate(cert)
}

func (h *HybridStore) DeleteCertificate(id string) (ConfigSnapshot, error) {
	return h.config.DeleteCertificate(id)
}

func (h *HybridStore) UpsertSSLPolicy(policy SSLPolicy) (ConfigSnapshot, error) {
	return h.config.UpsertSSLPolicy(policy)
}

func (h *HybridStore) DeleteSSLPolicy(id string) (ConfigSnapshot, error) {
	return h.config.DeleteSSLPolicy(id)
}

func (h *HybridStore) UpsertAccessPolicy(policy AccessPolicy) (ConfigSnapshot, error) {
	return h.config.UpsertAccessPolicy(policy)
}

func (h *HybridStore) DeleteAccessPolicy(id string) (ConfigSnapshot, error) {
	return h.config.DeleteAccessPolicy(id)
}

func (h *HybridStore) UpsertRewriteRule(rule RewriteRule) (ConfigSnapshot, error) {
	return h.config.UpsertRewriteRule(rule)
}

func (h *HybridStore) DeleteRewriteRule(id string) (ConfigSnapshot, error) {
	return h.config.DeleteRewriteRule(id)
}

func (h *HybridStore) UpsertNodeGroup(group NodeGroup) (ConfigSnapshot, NodeGroup, error) {
	persisted, err := h.mgmt.UpsertNodeGroup(group)
	if err != nil {
		return ConfigSnapshot{}, NodeGroup{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, NodeGroup{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, NodeGroup{}, err
	}
	return snap, persisted, nil
}

func (h *HybridStore) DeleteNodeGroup(id string) (ConfigSnapshot, error) {
	if _, err := h.mgmt.DeleteNodeGroup(id); err != nil {
		return ConfigSnapshot{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (h *HybridStore) RegisterOrUpdateNode(reg NodeRegistration) (ConfigSnapshot, EdgeNode, error) {
	node, changed, err := h.mgmt.RegisterOrUpdateNode(reg)
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	if changed {
		if err := h.bumpManagementVersion(); err != nil {
			return ConfigSnapshot{}, EdgeNode{}, err
		}
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	return snap, node, nil
}

func (h *HybridStore) UpdateNodeGroup(nodeID, groupID string) (ConfigSnapshot, EdgeNode, error) {
	gid := groupID
	return h.UpdateNode(nodeID, NodeUpdate{GroupID: &gid})
}

func (h *HybridStore) UpdateNode(nodeID string, update NodeUpdate) (ConfigSnapshot, EdgeNode, error) {
	node, err := h.mgmt.UpdateNode(nodeID, update)
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	return snap, node, nil
}

func (h *HybridStore) DeleteNode(id string) (ConfigSnapshot, error) {
	if err := h.mgmt.DeleteNode(id); err != nil {
		return ConfigSnapshot{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (h *HybridStore) UpsertTunnelGroup(group TunnelGroup) (ConfigSnapshot, TunnelGroup, error) {
	persisted, err := h.mgmt.UpsertTunnelGroup(group)
	if err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, err
	}
	return snap, persisted, nil
}

func (h *HybridStore) DeleteTunnelGroup(id string) (ConfigSnapshot, error) {
	if err := h.mgmt.DeleteTunnelGroup(id); err != nil {
		return ConfigSnapshot{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (h *HybridStore) UpsertTunnelAgent(agent TunnelAgent) (ConfigSnapshot, TunnelAgent, error) {
	persisted, err := h.mgmt.UpsertTunnelAgent(agent)
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, err
	}
	return snap, persisted, nil
}

func (h *HybridStore) DeleteTunnelAgent(id string) (ConfigSnapshot, error) {
	if err := h.mgmt.DeleteTunnelAgent(id); err != nil {
		return ConfigSnapshot{}, err
	}
	if err := h.bumpManagementVersion(); err != nil {
		return ConfigSnapshot{}, err
	}
	snap, err := h.composeSnapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (h *HybridStore) composeSnapshot(ctx context.Context) (ConfigSnapshot, error) {
	base, err := h.config.Snapshot(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return h.overlayManagement(ctx, base)
}

func (h *HybridStore) overlayManagement(ctx context.Context, snap ConfigSnapshot) (ConfigSnapshot, error) {
	state, err := h.mgmt.ExportState(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	snap.NodeGroups = state.NodeGroups
	snap.Nodes = state.Nodes
	snap.TunnelGroups = state.TunnelGroups
	snap.TunnelAgents = state.TunnelAgents
	return snap, nil
}

func (h *HybridStore) bumpManagementVersion() error {
	ctx, cancel := h.config.withCtx(context.Background())
	defer cancel()
	value := strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err := h.config.client.Put(ctx, h.config.managementVersionKey(), value)
	return err
}

func (h *HybridStore) purgeManagementKeys(ctx context.Context) error {
	prefixes := []string{
		h.config.nodeGroupsPrefix(),
		h.config.nodesPrefix(),
		h.config.tunnelGroupsPrefix(),
		h.config.tunnelAgentsPrefix(),
	}
	for _, prefix := range prefixes {
		if err := h.deletePrefix(prefix); err != nil {
			return err
		}
	}
	return nil
}

func (h *HybridStore) deletePrefix(prefix string) error {
	ctx, cancel := h.config.withCtx(context.Background())
	defer cancel()
	_, err := h.config.client.Delete(ctx, prefix, clientv3.WithPrefix())
	return err
}
