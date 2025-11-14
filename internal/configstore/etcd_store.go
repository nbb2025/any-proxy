package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/google/uuid"
)

const (
	defaultEtcdPrefix = "/any-proxy/"
	domainsDir        = "domains/"
	tunnelsDir        = "tunnels/"
	tunnelGroupsDir   = "tunnel_groups/"
	tunnelAgentsDir   = "tunnel_agents/"
	certificatesDir   = "certificates/"
	sslPoliciesDir    = "ssl_policies/"
	accessPoliciesDir = "access_policies/"
	rewriteRulesDir   = "rewrite_rules/"
	nodeGroupsDir     = "node_groups/"
	nodesDir          = "nodes/"
	metaDir           = "meta/"
)

// EtcdOptions configures EtcdStore behaviour.
type EtcdOptions struct {
	Prefix  string
	Timeout time.Duration
}

// EtcdStore persists configuration in etcd.
type EtcdStore struct {
	client  *clientv3.Client
	prefix  string
	timeout time.Duration
}

var _ Store = (*EtcdStore)(nil)

// NewEtcdStore wraps an etcd client.
func NewEtcdStore(client *clientv3.Client, opts EtcdOptions) (*EtcdStore, error) {
	if client == nil {
		return nil, errors.New("configstore: etcd client is nil")
	}

	prefix := opts.Prefix
	if prefix == "" {
		prefix = defaultEtcdPrefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	store := &EtcdStore{
		client:  client,
		prefix:  prefix,
		timeout: timeout,
	}

	if _, err := store.ensureSystemGroup(NodeCategoryWaiting); err != nil {
		return nil, err
	}
	if _, err := store.ensureSystemGroup(NodeCategoryCDN); err != nil {
		return nil, err
	}
	if _, err := store.ensureSystemGroup(NodeCategoryTunnel); err != nil {
		return nil, err
	}

	return store, nil
}

// UpsertDomain inserts or updates a domain definition in etcd.
func (e *EtcdStore) UpsertDomain(route DomainRoute) (ConfigSnapshot, error) {
	if route.ID == "" {
		route.ID = uuid.NewString()
	}
	route.UpdatedAt = time.Now().UTC()

	payload, err := json.Marshal(route)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal domain: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.domainKey(route.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put domain: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteDomain removes a domain from etcd.
func (e *EtcdStore) DeleteDomain(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.domainKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete domain: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}

	return e.Snapshot(context.Background())
}

// UpsertTunnel inserts or updates a tunnel definition in etcd.
func (e *EtcdStore) UpsertTunnel(route TunnelRoute) (ConfigSnapshot, error) {
	if route.ID == "" {
		route.ID = uuid.NewString()
	}
	route.UpdatedAt = time.Now().UTC()

	payload, err := json.Marshal(route)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal tunnel: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.tunnelKey(route.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put tunnel: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteTunnel removes a tunnel from etcd.
func (e *EtcdStore) DeleteTunnel(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.tunnelKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete tunnel: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}

	return e.Snapshot(context.Background())
}

// UpsertCertificate inserts or updates certificate material.
func (e *EtcdStore) UpsertCertificate(cert Certificate) (ConfigSnapshot, error) {
	if cert.ID == "" {
		cert.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if cert.CreatedAt.IsZero() {
		cert.CreatedAt = now
	}
	cert.UpdatedAt = now

	payload, err := json.Marshal(cert)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal certificate: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.certificateKey(cert.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put certificate: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteCertificate removes certificate data.
func (e *EtcdStore) DeleteCertificate(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.certificateKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete certificate: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}
	return e.Snapshot(context.Background())
}

// UpsertSSLPolicy stores TLS policies.
func (e *EtcdStore) UpsertSSLPolicy(policy SSLPolicy) (ConfigSnapshot, error) {
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	payload, err := json.Marshal(policy)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal ssl policy: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.sslPolicyKey(policy.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put ssl policy: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteSSLPolicy removes TLS policy.
func (e *EtcdStore) DeleteSSLPolicy(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.sslPolicyKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete ssl policy: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}
	return e.Snapshot(context.Background())
}

// UpsertAccessPolicy stores access decisions.
func (e *EtcdStore) UpsertAccessPolicy(policy AccessPolicy) (ConfigSnapshot, error) {
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	payload, err := json.Marshal(policy)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal access policy: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.accessPolicyKey(policy.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put access policy: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteAccessPolicy removes an access policy.
func (e *EtcdStore) DeleteAccessPolicy(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.accessPolicyKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete access policy: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}
	return e.Snapshot(context.Background())
}

// UpsertRewriteRule stores origin rewrite definition.
func (e *EtcdStore) UpsertRewriteRule(rule RewriteRule) (ConfigSnapshot, error) {
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now

	payload, err := json.Marshal(rule)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal rewrite rule: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.rewriteRuleKey(rule.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("put rewrite rule: %w", err)
	}

	return e.Snapshot(context.Background())
}

// DeleteRewriteRule removes rewrite entry.
func (e *EtcdStore) DeleteRewriteRule(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.rewriteRuleKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete rewrite rule: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNotFound
	}
	return e.Snapshot(context.Background())
}

// UpsertNodeGroup stores or updates node group metadata.
func (e *EtcdStore) UpsertNodeGroup(group NodeGroup) (ConfigSnapshot, NodeGroup, error) {
	if strings.TrimSpace(group.Name) == "" {
		return ConfigSnapshot{}, NodeGroup{}, ErrInvalidGroup
	}
	switch group.Category {
	case NodeCategoryWaiting, NodeCategoryCDN, NodeCategoryTunnel:
	default:
		return ConfigSnapshot{}, NodeGroup{}, ErrInvalidGroup
	}

	now := time.Now().UTC()
	if group.ID == "" {
		group.ID = uuid.NewString()
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	existing, err := e.getNodeGroup(ctx, group.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return ConfigSnapshot{}, NodeGroup{}, err
	}
	if existing.ID != "" {
		group.CreatedAt = existing.CreatedAt
		if existing.System && existing.Category != group.Category {
			return ConfigSnapshot{}, NodeGroup{}, ErrProtectedGroup
		}
		if existing.System {
			group.System = true
		}
		if group.Description == "" {
			group.Description = existing.Description
		}
	} else if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.ID == defaultWaitingGroupID {
		group.System = true
		group.Category = NodeCategoryWaiting
		if group.Name == "" {
			group.Name = "待分组"
		}
	}
	group.UpdatedAt = now

	payload, err := json.Marshal(group)
	if err != nil {
		return ConfigSnapshot{}, NodeGroup{}, fmt.Errorf("marshal node group: %w", err)
	}

	if _, err = e.client.Put(ctx, e.nodeGroupKey(group.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, NodeGroup{}, fmt.Errorf("put node group: %w", err)
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, NodeGroup{}, err
	}
	return snap, group, nil
}

// DeleteNodeGroup removes a node group and reassigns members to waiting pool.
func (e *EtcdStore) DeleteNodeGroup(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	group, err := e.getNodeGroup(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ConfigSnapshot{}, ErrGroupNotFound
		}
		return ConfigSnapshot{}, err
	}
	if group.System {
		return ConfigSnapshot{}, ErrProtectedGroup
	}

	waitingGroup, err := e.ensureSystemGroup(NodeCategoryWaiting)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("ensure waiting group: %w", err)
	}

	nodesResp, err := e.client.Get(ctx, e.nodesPrefix(), clientv3.WithPrefix())
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("list nodes: %w", err)
	}

	now := time.Now().UTC()
	for _, kv := range nodesResp.Kvs {
		var node EdgeNode
		if err := json.Unmarshal(kv.Value, &node); err != nil {
			return ConfigSnapshot{}, fmt.Errorf("decode node %s: %w", string(kv.Key), err)
		}
		if node.GroupID != id {
			continue
		}
		node.GroupID = waitingGroup.ID
		node.Category = waitingGroup.Category
		node.UpdatedAt = now
		payload, err := json.Marshal(node)
		if err != nil {
			return ConfigSnapshot{}, fmt.Errorf("marshal reassigned node: %w", err)
		}
		if _, err = e.client.Put(ctx, string(kv.Key), string(payload)); err != nil {
			return ConfigSnapshot{}, fmt.Errorf("update node %s: %w", node.ID, err)
		}
	}

	if _, err = e.client.Delete(ctx, e.nodeGroupKey(id)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete node group: %w", err)
	}

	return e.Snapshot(context.Background())
}

// RegisterOrUpdateNode persists node metadata reported by agents.
func (e *EtcdStore) RegisterOrUpdateNode(reg NodeRegistration) (ConfigSnapshot, EdgeNode, error) {
	nodeID := strings.TrimSpace(reg.ID)
	if nodeID == "" {
		return ConfigSnapshot{}, EdgeNode{}, ErrNodeNotFound
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	var group NodeGroup
	var err error
	if id := strings.TrimSpace(reg.GroupID); id != "" {
		group, err = e.getNodeGroup(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				group, err = e.ensureSystemGroup(reg.Category)
				if err != nil {
					return ConfigSnapshot{}, EdgeNode{}, err
				}
			} else {
				return ConfigSnapshot{}, EdgeNode{}, err
			}
		}
	} else if reg.Category != "" {
		group, err = e.ensureSystemGroup(reg.Category)
		if err != nil {
			return ConfigSnapshot{}, EdgeNode{}, err
		}
	} else {
		group, err = e.ensureSystemGroup(NodeCategoryWaiting)
		if err != nil {
			return ConfigSnapshot{}, EdgeNode{}, err
		}
	}

	existing, err := e.getNode(ctx, nodeID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return ConfigSnapshot{}, EdgeNode{}, err
	}

	now := time.Now().UTC()
	addresses := uniqueStrings(reg.Addresses)
	if len(addresses) == 0 && strings.TrimSpace(reg.Hostname) == "" {
		// keep addresses empty; hostname optional
	}

	node := existing
	if node.ID == "" {
		node.ID = nodeID
		node.CreatedAt = now
	}

	node.GroupID = group.ID
	node.Category = group.Category
	if name := strings.TrimSpace(reg.Name); name != "" {
		node.Name = name
	}
	if kind := strings.TrimSpace(reg.Kind); kind != "" {
		node.Kind = kind
	} else if node.Kind == "" {
		node.Kind = "edge"
	}

	if host := strings.TrimSpace(reg.Hostname); host != "" {
		node.Hostname = host
	}
	if len(addresses) > 0 {
		node.Addresses = addresses
	}
	if ver := strings.TrimSpace(reg.Version); ver != "" {
		node.Version = ver
	}
	if agentVer := strings.TrimSpace(reg.AgentVersion); agentVer != "" {
		node.AgentVersion = agentVer
	}
	if hash := strings.TrimSpace(reg.NodeKeyHash); hash != "" {
		keyChanged := false
		if hash != node.NodeKeyHash {
			node.NodeKeyHash = hash
			keyChanged = true
		}
		if reg.NodeKeyVersion > 0 {
			if reg.NodeKeyVersion != node.NodeKeyVersion {
				node.NodeKeyVersion = reg.NodeKeyVersion
			}
		} else if node.NodeKeyVersion == 0 && keyChanged {
			node.NodeKeyVersion = 1
		}
	}
	node.LastSeen = now
	node.UpdatedAt = now
	if node.AgentDesiredVersion != "" && node.AgentVersion != "" && node.AgentDesiredVersion == node.AgentVersion {
		node.AgentDesiredVersion = ""
		node.LastUpgradeAt = now
	}

	payload, err := json.Marshal(node)
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, fmt.Errorf("marshal node: %w", err)
	}

	if _, err = e.client.Put(ctx, e.nodeKey(node.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, EdgeNode{}, fmt.Errorf("put node: %w", err)
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	return snap, node, nil
}

// UpdateNodeGroup moves a node into another group.
func (e *EtcdStore) UpdateNodeGroup(nodeID, groupID string) (ConfigSnapshot, EdgeNode, error) {
	gid := groupID
	update := NodeUpdate{GroupID: &gid}
	return e.UpdateNode(nodeID, update)
}

// UpdateNode mutates persisted node metadata.
func (e *EtcdStore) UpdateNode(nodeID string, update NodeUpdate) (ConfigSnapshot, EdgeNode, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	node, err := e.getNode(ctx, nodeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ConfigSnapshot{}, EdgeNode{}, ErrNodeNotFound
		}
		return ConfigSnapshot{}, EdgeNode{}, err
	}

	changed := false
	if update.GroupID != nil {
		targetID := strings.TrimSpace(*update.GroupID)
		var group NodeGroup
		if targetID == "" {
			group, err = e.ensureSystemGroup(NodeCategoryWaiting)
		} else {
			group, err = e.getNodeGroup(ctx, targetID)
		}
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ConfigSnapshot{}, EdgeNode{}, ErrGroupNotFound
			}
			return ConfigSnapshot{}, EdgeNode{}, err
		}
		if node.GroupID != group.ID {
			node.GroupID = group.ID
			node.Category = group.Category
			changed = true
		}
	}
	if update.Name != nil {
		name := strings.TrimSpace(*update.Name)
		if node.Name != name {
			node.Name = name
			changed = true
		}
	}
	if update.Category != nil {
		category := *update.Category
		var group NodeGroup
		group, err = e.ensureSystemGroup(category)
		if err != nil {
			return ConfigSnapshot{}, EdgeNode{}, err
		}
		if node.Category != category || node.GroupID != group.ID {
			node.Category = category
			node.GroupID = group.ID
			changed = true
		}
	}
	if update.AgentDesiredVersion != nil {
		desired := strings.TrimSpace(*update.AgentDesiredVersion)
		if node.AgentDesiredVersion != desired {
			node.AgentDesiredVersion = desired
			changed = true
		}
	}

	if changed {
		node.UpdatedAt = time.Now().UTC()
		payload, err := json.Marshal(node)
		if err != nil {
			return ConfigSnapshot{}, EdgeNode{}, fmt.Errorf("marshal node: %w", err)
		}
		if _, err = e.client.Put(ctx, e.nodeKey(node.ID), string(payload)); err != nil {
			return ConfigSnapshot{}, EdgeNode{}, fmt.Errorf("put node: %w", err)
		}
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, EdgeNode{}, err
	}
	return snap, node, nil
}

// DeleteNode removes a node definition and invalidates its key.
func (e *EtcdStore) DeleteNode(nodeID string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.nodeKey(nodeID))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete node: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrNodeNotFound
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

// Snapshot reads all configuration entries from etcd.
func (e *EtcdStore) Snapshot(ctx context.Context) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(ctx)
	defer cancel()

	resp, err := e.client.Get(ctx, e.prefix, clientv3.WithPrefix())
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("get snapshot: %w", err)
	}

	domains := make([]DomainRoute, 0)
	tunnels := make([]TunnelRoute, 0)
	tunnelGroups := make([]TunnelGroup, 0)
	tunnelAgents := make([]TunnelAgent, 0)
	certificates := make([]Certificate, 0)
	sslPolicies := make([]SSLPolicy, 0)
	accessPolicies := make([]AccessPolicy, 0)
	rewriteRules := make([]RewriteRule, 0)
	nodeGroups := make([]NodeGroup, 0)
	nodes := make([]EdgeNode, 0)

	for _, kv := range resp.Kvs {
		key := strings.TrimPrefix(string(kv.Key), e.prefix)
		switch {
		case strings.HasPrefix(key, domainsDir):
			var route DomainRoute
			if err := json.Unmarshal(kv.Value, &route); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode domain %s: %w", key, err)
			}
			domains = append(domains, route)
		case strings.HasPrefix(key, tunnelsDir):
			var route TunnelRoute
			if err := json.Unmarshal(kv.Value, &route); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode tunnel %s: %w", key, err)
			}
			tunnels = append(tunnels, route)
		case strings.HasPrefix(key, tunnelGroupsDir):
			var group TunnelGroup
			if err := json.Unmarshal(kv.Value, &group); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode tunnel group %s: %w", key, err)
			}
			tunnelGroups = append(tunnelGroups, group)
		case strings.HasPrefix(key, tunnelAgentsDir):
			var agent TunnelAgent
			if err := json.Unmarshal(kv.Value, &agent); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode tunnel agent %s: %w", key, err)
			}
			tunnelAgents = append(tunnelAgents, agent)
		case strings.HasPrefix(key, certificatesDir):
			var cert Certificate
			if err := json.Unmarshal(kv.Value, &cert); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode certificate %s: %w", key, err)
			}
			certificates = append(certificates, cert)
		case strings.HasPrefix(key, sslPoliciesDir):
			var policy SSLPolicy
			if err := json.Unmarshal(kv.Value, &policy); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode ssl policy %s: %w", key, err)
			}
			sslPolicies = append(sslPolicies, policy)
		case strings.HasPrefix(key, accessPoliciesDir):
			var policy AccessPolicy
			if err := json.Unmarshal(kv.Value, &policy); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode access policy %s: %w", key, err)
			}
			accessPolicies = append(accessPolicies, policy)
		case strings.HasPrefix(key, rewriteRulesDir):
			var rule RewriteRule
			if err := json.Unmarshal(kv.Value, &rule); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode rewrite rule %s: %w", key, err)
			}
			rewriteRules = append(rewriteRules, rule)
		case strings.HasPrefix(key, nodeGroupsDir):
			var group NodeGroup
			if err := json.Unmarshal(kv.Value, &group); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode node group %s: %w", key, err)
			}
			nodeGroups = append(nodeGroups, group)
		case strings.HasPrefix(key, nodesDir):
			var node EdgeNode
			if err := json.Unmarshal(kv.Value, &node); err != nil {
				return ConfigSnapshot{}, fmt.Errorf("decode node %s: %w", key, err)
			}
			nodes = append(nodes, node)
		}
	}

	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Domain == domains[j].Domain {
			return domains[i].ID < domains[j].ID
		}
		return domains[i].Domain < domains[j].Domain
	})

	sort.Slice(tunnels, func(i, j int) bool {
		if tunnels[i].BindHost == tunnels[j].BindHost {
			if tunnels[i].BindPort == tunnels[j].BindPort {
				return tunnels[i].ID < tunnels[j].ID
			}
			return tunnels[i].BindPort < tunnels[j].BindPort
		}
		return tunnels[i].BindHost < tunnels[j].BindHost
	})

	sort.Slice(tunnelGroups, func(i, j int) bool {
		if tunnelGroups[i].Name == tunnelGroups[j].Name {
			return tunnelGroups[i].ID < tunnelGroups[j].ID
		}
		return tunnelGroups[i].Name < tunnelGroups[j].Name
	})

	sort.Slice(tunnelAgents, func(i, j int) bool {
		if tunnelAgents[i].GroupID == tunnelAgents[j].GroupID {
			return tunnelAgents[i].NodeID < tunnelAgents[j].NodeID
		}
		return tunnelAgents[i].GroupID < tunnelAgents[j].GroupID
	})

	sort.Slice(certificates, func(i, j int) bool {
		if certificates[i].Name == certificates[j].Name {
			return certificates[i].ID < certificates[j].ID
		}
		return certificates[i].Name < certificates[j].Name
	})

	sort.Slice(sslPolicies, func(i, j int) bool {
		if sslPolicies[i].Name == sslPolicies[j].Name {
			return sslPolicies[i].ID < sslPolicies[j].ID
		}
		return sslPolicies[i].Name < sslPolicies[j].Name
	})

	sort.Slice(accessPolicies, func(i, j int) bool {
		if accessPolicies[i].Name == accessPolicies[j].Name {
			return accessPolicies[i].ID < accessPolicies[j].ID
		}
		return accessPolicies[i].Name < accessPolicies[j].Name
	})

	sort.Slice(rewriteRules, func(i, j int) bool {
		if rewriteRules[i].Priority == rewriteRules[j].Priority {
			if rewriteRules[i].Name == rewriteRules[j].Name {
				return rewriteRules[i].ID < rewriteRules[j].ID
			}
			return rewriteRules[i].Name < rewriteRules[j].Name
		}
		return rewriteRules[i].Priority < rewriteRules[j].Priority
	})

	sort.Slice(nodeGroups, func(i, j int) bool {
		if nodeGroups[i].Category == nodeGroups[j].Category {
			if nodeGroups[i].Name == nodeGroups[j].Name {
				return nodeGroups[i].ID < nodeGroups[j].ID
			}
			return nodeGroups[i].Name < nodeGroups[j].Name
		}
		return nodeGroups[i].Category < nodeGroups[j].Category
	})

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	return ConfigSnapshot{
		Version:        resp.Header.Revision,
		GeneratedAt:    time.Now().UTC(),
		Domains:        domains,
		Tunnels:        tunnels,
		TunnelGroups:   tunnelGroups,
		TunnelAgents:   tunnelAgents,
		Certificates:   certificates,
		SSLPolicies:    sslPolicies,
		AccessPolicies: accessPolicies,
		RewriteRules:   rewriteRules,
		NodeGroups:     nodeGroups,
		Nodes:          nodes,
	}, nil
}

// Watch blocks until etcd reports a revision newer than `since`.
func (e *EtcdStore) Watch(ctx context.Context, since int64) (ConfigSnapshot, error) {
	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, err
	}
	if snap.Version > since {
		return snap, nil
	}

	watchOpts := []clientv3.OpOption{clientv3.WithPrefix()}
	if since > 0 {
		watchOpts = append(watchOpts, clientv3.WithRev(since+1))
	}

	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	watchCh := e.client.Watch(watchCtx, e.prefix, watchOpts...)
	for {
		select {
		case <-ctx.Done():
			return ConfigSnapshot{}, ctx.Err()
		case resp, ok := <-watchCh:
			if !ok {
				return ConfigSnapshot{}, context.Canceled
			}
			if err := resp.Err(); err != nil {
				if errors.Is(err, rpctypes.ErrCompacted) {
					// revision compacted, fetch latest snapshot directly
					return e.Snapshot(context.Background())
				}
				return ConfigSnapshot{}, err
			}
			if resp.Canceled {
				if resp.Err() != nil {
					return ConfigSnapshot{}, resp.Err()
				}
				return ConfigSnapshot{}, context.Canceled
			}
			return e.Snapshot(context.Background())
		}
	}
}

// UpsertTunnelGroup stores tunnel group metadata.
func (e *EtcdStore) UpsertTunnelGroup(group TunnelGroup) (ConfigSnapshot, TunnelGroup, error) {
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		return ConfigSnapshot{}, TunnelGroup{}, ErrInvalidTunnelGroup
	}
	if group.ID == "" {
		group.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.ListenAddress = strings.TrimSpace(group.ListenAddress)
	if group.ListenAddress == "" {
		group.ListenAddress = ":4433"
	}
	group.EdgeNodeIDs = dedupeStrings(group.EdgeNodeIDs)
	group.Transports = normalizeTransports(group.Transports)
	group.UpdatedAt = now

	payload, err := json.Marshal(group)
	if err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, fmt.Errorf("marshal tunnel group: %w", err)
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	if _, err = e.client.Put(ctx, e.tunnelGroupKey(group.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, fmt.Errorf("put tunnel group: %w", err)
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, TunnelGroup{}, err
	}
	return snap, group, nil
}

// DeleteTunnelGroup removes a tunnel ingress definition.
func (e *EtcdStore) DeleteTunnelGroup(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Get(ctx, e.tunnelGroupKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("get tunnel group: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return ConfigSnapshot{}, ErrTunnelGroupNotFound
	}

	agentResp, err := e.client.Get(ctx, e.tunnelAgentsPrefix(), clientv3.WithPrefix())
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("list tunnel agents: %w", err)
	}
	for _, kv := range agentResp.Kvs {
		var agent TunnelAgent
		if err := json.Unmarshal(kv.Value, &agent); err != nil {
			return ConfigSnapshot{}, fmt.Errorf("decode tunnel agent %s: %w", string(kv.Key), err)
		}
		if agent.GroupID == id {
			return ConfigSnapshot{}, ErrTunnelGroupInUse
		}
	}

	if _, err := e.client.Delete(ctx, e.tunnelGroupKey(id)); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete tunnel group: %w", err)
	}

	return e.Snapshot(context.Background())
}

// UpsertTunnelAgent stores tunnel client metadata.
func (e *EtcdStore) UpsertTunnelAgent(agent TunnelAgent) (ConfigSnapshot, TunnelAgent, error) {
	agent.NodeID = strings.TrimSpace(agent.NodeID)
	agent.GroupID = strings.TrimSpace(agent.GroupID)
	agent.KeyHash = strings.TrimSpace(agent.KeyHash)
	if agent.NodeID == "" || agent.GroupID == "" || agent.KeyHash == "" {
		return ConfigSnapshot{}, TunnelAgent{}, ErrInvalidTunnelAgent
	}
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}

	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	groupResp, err := e.client.Get(ctx, e.tunnelGroupKey(agent.GroupID))
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, fmt.Errorf("get tunnel group: %w", err)
	}
	if len(groupResp.Kvs) == 0 {
		return ConfigSnapshot{}, TunnelAgent{}, ErrTunnelGroupNotFound
	}

	now := time.Now().UTC()
	resp, err := e.client.Get(ctx, e.tunnelAgentKey(agent.ID))
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, fmt.Errorf("get tunnel agent: %w", err)
	}
	if len(resp.Kvs) > 0 {
		var existing TunnelAgent
		if err := json.Unmarshal(resp.Kvs[0].Value, &existing); err != nil {
			return ConfigSnapshot{}, TunnelAgent{}, fmt.Errorf("decode tunnel agent: %w", err)
		}
		if agent.CreatedAt.IsZero() {
			agent.CreatedAt = existing.CreatedAt
		}
		if agent.KeyVersion == 0 {
			agent.KeyVersion = existing.KeyVersion
		}
		if agent.KeyHash == "" {
			agent.KeyHash = existing.KeyHash
		}
	} else {
		if agent.CreatedAt.IsZero() {
			agent.CreatedAt = now
		}
		if agent.KeyVersion == 0 {
			agent.KeyVersion = 1
		}
	}

	agent.Services = normalizeServices(agent.Services)
	agent.UpdatedAt = now

	payload, err := json.Marshal(agent)
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, fmt.Errorf("marshal tunnel agent: %w", err)
	}

	if _, err := e.client.Put(ctx, e.tunnelAgentKey(agent.ID), string(payload)); err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, fmt.Errorf("put tunnel agent: %w", err)
	}

	snap, err := e.Snapshot(context.Background())
	if err != nil {
		return ConfigSnapshot{}, TunnelAgent{}, err
	}
	return snap, agent, nil
}

// DeleteTunnelAgent removes a tunnel agent definition.
func (e *EtcdStore) DeleteTunnelAgent(id string) (ConfigSnapshot, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	resp, err := e.client.Delete(ctx, e.tunnelAgentKey(id))
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("delete tunnel agent: %w", err)
	}
	if resp.Deleted == 0 {
		return ConfigSnapshot{}, ErrTunnelAgentNotFound
	}
	return e.Snapshot(context.Background())
}

func (e *EtcdStore) domainKey(id string) string {
	return e.prefix + domainsDir + id
}

func (e *EtcdStore) tunnelKey(id string) string {
	return e.prefix + tunnelsDir + id
}

func (e *EtcdStore) certificateKey(id string) string {
	return e.prefix + certificatesDir + id
}

func (e *EtcdStore) sslPolicyKey(id string) string {
	return e.prefix + sslPoliciesDir + id
}

func (e *EtcdStore) accessPolicyKey(id string) string {
	return e.prefix + accessPoliciesDir + id
}

func (e *EtcdStore) rewriteRuleKey(id string) string {
	return e.prefix + rewriteRulesDir + id
}

func (e *EtcdStore) tunnelGroupKey(id string) string {
	return e.prefix + tunnelGroupsDir + id
}

func (e *EtcdStore) tunnelAgentKey(id string) string {
	return e.prefix + tunnelAgentsDir + id
}

func (e *EtcdStore) nodeGroupKey(id string) string {
	return e.prefix + nodeGroupsDir + id
}

func (e *EtcdStore) nodeKey(id string) string {
	return e.prefix + nodesDir + id
}

func (e *EtcdStore) managementVersionKey() string {
	return e.prefix + metaDir + "management_version"
}

func (e *EtcdStore) nodeGroupsPrefix() string {
	return e.prefix + nodeGroupsDir
}

func (e *EtcdStore) nodesPrefix() string {
	return e.prefix + nodesDir
}

func (e *EtcdStore) tunnelGroupsPrefix() string {
	return e.prefix + tunnelGroupsDir
}

func (e *EtcdStore) tunnelAgentsPrefix() string {
	return e.prefix + tunnelAgentsDir
}

func (e *EtcdStore) withCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), e.timeout)
	}
	return context.WithTimeout(parent, e.timeout)
}

func (e *EtcdStore) ensureSystemGroup(category NodeCategory) (NodeGroup, error) {
	ctx, cancel := e.withCtx(context.Background())
	defer cancel()

	id, name := defaultSystemGroupMeta(category)
	group, err := e.getNodeGroup(ctx, id)
	if err == nil {
		return group, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return NodeGroup{}, err
	}

	now := time.Now().UTC()
	group = NodeGroup{
		ID:        id,
		Name:      name,
		Category:  category,
		System:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	payload, err := json.Marshal(group)
	if err != nil {
		return NodeGroup{}, fmt.Errorf("marshal system node group: %w", err)
	}
	if _, err = e.client.Put(ctx, e.nodeGroupKey(group.ID), string(payload)); err != nil {
		return NodeGroup{}, fmt.Errorf("put system node group: %w", err)
	}
	return group, nil
}

func (e *EtcdStore) getNodeGroup(ctx context.Context, id string) (NodeGroup, error) {
	resp, err := e.client.Get(ctx, e.nodeGroupKey(id))
	if err != nil {
		return NodeGroup{}, fmt.Errorf("get node group: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return NodeGroup{}, ErrNotFound
	}
	var group NodeGroup
	if err := json.Unmarshal(resp.Kvs[0].Value, &group); err != nil {
		return NodeGroup{}, fmt.Errorf("decode node group: %w", err)
	}
	return group, nil
}

func (e *EtcdStore) getNode(ctx context.Context, id string) (EdgeNode, error) {
	resp, err := e.client.Get(ctx, e.nodeKey(id))
	if err != nil {
		return EdgeNode{}, fmt.Errorf("get node: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return EdgeNode{}, ErrNotFound
	}
	var node EdgeNode
	if err := json.Unmarshal(resp.Kvs[0].Value, &node); err != nil {
		return EdgeNode{}, fmt.Errorf("decode node: %w", err)
	}
	return node, nil
}
