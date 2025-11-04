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
	certificatesDir   = "certificates/"
	sslPoliciesDir    = "ssl_policies/"
	accessPoliciesDir = "access_policies/"
	rewriteRulesDir   = "rewrite_rules/"
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

	return &EtcdStore{
		client:  client,
		prefix:  prefix,
		timeout: timeout,
	}, nil
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
	certificates := make([]Certificate, 0)
	sslPolicies := make([]SSLPolicy, 0)
	accessPolicies := make([]AccessPolicy, 0)
	rewriteRules := make([]RewriteRule, 0)

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

	return ConfigSnapshot{
		Version:     resp.Header.Revision,
		GeneratedAt: time.Now().UTC(),
		Domains:     domains,
		Tunnels:     tunnels,
		Certificates: certificates,
		SSLPolicies:  sslPolicies,
		AccessPolicies: accessPolicies,
		RewriteRules:  rewriteRules,
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

func (e *EtcdStore) withCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), e.timeout)
	}
	return context.WithTimeout(parent, e.timeout)
}
