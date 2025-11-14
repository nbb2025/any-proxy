package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"anyproxy.dev/any-proxy/internal/tunnel/protocol"
)

// Options controls tunnel-agent client behaviour.
type Options struct {
	NodeID            string
	Key               string
	GroupID           string
	EdgeCandidates    []string
	Services          []ServiceConfig
	Logger            Logger
	DialTimeout       time.Duration
	HeartbeatInterval time.Duration
	ReconnectDelay    time.Duration
}

// ServiceConfig declares a local service exposed through the tunnel.
type ServiceConfig struct {
	ID           string
	Protocol     string
	LocalAddress string
	LocalPort    int
}

// Logger represents minimal logging operations.
type Logger interface {
	Printf(string, ...interface{})
}

// Client maintains control/data connections towards an edge gateway.
type Client struct {
	opts     Options
	services map[string]ServiceConfig
	logger   Logger
}

// New constructs a client.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.NodeID) == "" || strings.TrimSpace(opts.Key) == "" {
		return nil, errors.New("node id and key required")
	}
	if len(opts.EdgeCandidates) == 0 {
		return nil, errors.New("edge candidate list required")
	}
	if len(opts.Services) == 0 {
		return nil, errors.New("at least one service is required")
	}
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 15 * time.Second
	}
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = 3 * time.Second
	}
	serviceIndex := make(map[string]ServiceConfig, len(opts.Services))
	for _, svc := range opts.Services {
		id := strings.TrimSpace(svc.ID)
		if id == "" {
			return nil, fmt.Errorf("service id required")
		}
		if svc.LocalAddress == "" {
			svc.LocalAddress = "127.0.0.1"
		}
		if svc.LocalPort == 0 {
			return nil, fmt.Errorf("service %s localPort required", id)
		}
		svc.Protocol = strings.ToLower(strings.TrimSpace(svc.Protocol))
		if svc.Protocol == "" {
			svc.Protocol = "tcp"
		}
		serviceIndex[id] = svc
	}
	return &Client{
		opts:     opts,
		services: serviceIndex,
		logger:   opts.Logger,
	}, nil
}

// Run keeps the tunnel connection alive until context cancellation.
func (c *Client) Run(ctx context.Context) error {
	for {
		if err := c.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Printf("[tunnel-client] control session error: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.opts.ReconnectDelay):
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	edges := shuffled(c.opts.EdgeCandidates)
	var lastErr error
	for _, addr := range edges {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := c.dialEdge(addr)
		if err != nil {
			lastErr = err
			c.logger.Printf("[tunnel-client] dial edge=%s err=%v", addr, err)
			continue
		}
		err = c.handleControlSession(ctx, conn, addr)
		if err == nil || errors.Is(err, context.Canceled) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func (c *Client) dialEdge(addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.opts.DialTimeout}
	return dialer.Dial("tcp", addr)
}

func (c *Client) handleControlSession(ctx context.Context, conn net.Conn, edgeAddr string) error {
	defer conn.Close()
	services := make([]protocol.ServiceAdvertisement, 0, len(c.services))
	for _, svc := range c.services {
		services = append(services, protocol.ServiceAdvertisement{ID: svc.ID, Protocol: svc.Protocol})
	}
	shake := protocol.Envelope{
		Type: protocol.MessageTypeHandshake,
		Handshake: &protocol.HandshakeMessage{
			NodeID:              c.opts.NodeID,
			Key:                 c.opts.Key,
			GroupID:             c.opts.GroupID,
			Version:             protocol.Version,
			Role:                "control",
			Services:            services,
			PreferredTransports: []string{"tcp"},
			Capabilities: protocol.Capabilities{
				SupportsUDP:         false,
				SupportsCompression: false,
			},
		},
	}
	if err := protocol.WriteEnvelope(conn, shake); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}
	sessCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.controlReadLoop(sessCtx, cancel, conn, edgeAddr)
	}()
	go func() {
		defer wg.Done()
		c.sendHeartbeats(sessCtx, conn, cancel)
	}()
	<-sessCtx.Done()
	conn.Close()
	wg.Wait()
	return sessCtx.Err()
}

func (c *Client) controlReadLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, edgeAddr string) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		env, err := protocol.ReadEnvelope(conn)
		if err != nil {
			c.logger.Printf("[tunnel-client] control read err=%v", err)
			return
		}
		switch env.Type {
		case protocol.MessageTypeBridge:
			if env.Bridge == nil {
				continue
			}
			go c.handleBridgeCommand(ctx, edgeAddr, *env.Bridge)
		case protocol.MessageTypeHeartbeat:
			// server heartbeat not currently used
		default:
			c.logger.Printf("[tunnel-client] unknown envelope type=%s", env.Type)
		}
	}
}

func (c *Client) sendHeartbeats(ctx context.Context, conn net.Conn, cancel context.CancelFunc) {
	ticker := time.NewTicker(c.opts.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			env := protocol.Envelope{
				Type:      protocol.MessageTypeHeartbeat,
				Heartbeat: &protocol.Heartbeat{Timestamp: time.Now().UTC()},
			}
			if err := protocol.WriteEnvelope(conn, env); err != nil {
				c.logger.Printf("[tunnel-client] heartbeat error: %v", err)
				cancel()
				return
			}
		}
	}
}

func (c *Client) handleBridgeCommand(ctx context.Context, edgeAddr string, cmd protocol.BridgeCommand) {
	if !strings.EqualFold(cmd.Action, "open") {
		c.logger.Printf("[tunnel-client] unsupported bridge action=%s", cmd.Action)
		return
	}
	svc, ok := c.services[cmd.ServiceID]
	if !ok {
		c.logger.Printf("[tunnel-client] service not found id=%s", cmd.ServiceID)
		return
	}
	if svc.Protocol != "tcp" {
		c.logger.Printf("[tunnel-client] protocol %s not supported", svc.Protocol)
		return
	}
	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", svc.LocalAddress, svc.LocalPort), c.opts.DialTimeout)
	if err != nil {
		c.logger.Printf("[tunnel-client] local dial service=%s err=%v", svc.ID, err)
		return
	}
	dataConn, err := c.dialDataConn(edgeAddr, cmd.Token, svc.ID)
	if err != nil {
		c.logger.Printf("[tunnel-client] data dial service=%s err=%v", svc.ID, err)
		localConn.Close()
		return
	}
	go bridgeConnections(localConn, dataConn)
}

func (c *Client) dialDataConn(edgeAddr, token, serviceID string) (net.Conn, error) {
	conn, err := c.dialEdge(edgeAddr)
	if err != nil {
		return nil, err
	}
	shake := protocol.Envelope{
		Type: protocol.MessageTypeHandshake,
		Handshake: &protocol.HandshakeMessage{
			NodeID:    c.opts.NodeID,
			Key:       c.opts.Key,
			GroupID:   c.opts.GroupID,
			Version:   protocol.Version,
			Role:      "data",
			ServiceID: serviceID,
			Token:     token,
		},
	}
	if err := protocol.WriteEnvelope(conn, shake); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send data handshake: %w", err)
	}
	return conn, nil
}

func bridgeConnections(localConn, dataConn net.Conn) {
	defer localConn.Close()
	defer dataConn.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dataConn, localConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, dataConn)
	}()
	wg.Wait()
}

func shuffled(list []string) []string {
	out := append([]string(nil), list...)
	rand.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	return out
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}
