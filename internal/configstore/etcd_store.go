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

	return ConfigSnapshot{
		Version:     resp.Header.Revision,
		GeneratedAt: time.Now().UTC(),
		Domains:     domains,
		Tunnels:     tunnels,
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

func (e *EtcdStore) withCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), e.timeout)
	}
	return context.WithTimeout(parent, e.timeout)
}
