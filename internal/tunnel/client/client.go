package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"anyproxy.dev/any-proxy/internal/tunnel/protocol"
)

// Options controls tunnel-agent client behaviour.
type Options struct {
	NodeID            string
	Key               string
	GroupID           string
	EdgeCandidates    []string
	Logger            Logger
	DialTimeout       time.Duration
	HeartbeatInterval time.Duration
}

// Logger represents minimal logging operations.
type Logger interface {
	Printf(string, ...interface{})
}

// Client maintains a persistent tunnel connection.
type Client struct {
	opts Options
}

// New constructs a client.
func New(opts Options) (*Client, error) {
	if opts.NodeID == "" || opts.Key == "" {
		return nil, errors.New("node id and key required")
	}
	if len(opts.EdgeCandidates) == 0 {
		return nil, errors.New("edge candidate list required")
	}
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 15 * time.Second
	}
	return &Client{opts: opts}, nil
}

// Run keeps the tunnel connection alive until context cancellation.
func (c *Client) Run(ctx context.Context) error {
	for {
		if err := c.connectOnce(ctx); err != nil {
			c.opts.Logger.Printf("[tunnel-client] connect error: %v", err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	addr := c.opts.EdgeCandidates[0]
	dialCtx, cancel := context.WithTimeout(ctx, c.opts.DialTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	handshake := protocol.Envelope{
		Type: protocol.MessageTypeHandshake,
		Handshake: &protocol.HandshakeMessage{
			NodeID:              c.opts.NodeID,
			Key:                 c.opts.Key,
			Version:             protocol.Version,
			PreferredTransports: []string{"tcp"},
			Capabilities: protocol.Capabilities{
				SupportsUDP:         true,
				SupportsCompression: true,
			},
		},
	}
	if err := protocol.WriteEnvelope(conn, handshake); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	errCh := make(chan error, 2)
	go c.sendHeartbeats(conn, errCh)
	go c.readLoop(conn, errCh)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Client) sendHeartbeats(conn net.Conn, errCh chan<- error) {
	ticker := time.NewTicker(c.opts.HeartbeatInterval)
	defer ticker.Stop()
	for range ticker.C {
		env := protocol.Envelope{
			Type: protocol.MessageTypeHeartbeat,
			Heartbeat: &protocol.Heartbeat{
				Timestamp: time.Now().UTC(),
			},
		}
		if err := protocol.WriteEnvelope(conn, env); err != nil {
			errCh <- fmt.Errorf("heartbeat write: %w", err)
			return
		}
	}
}

func (c *Client) readLoop(conn net.Conn, errCh chan<- error) {
	for {
		if _, err := protocol.ReadEnvelope(conn); err != nil {
			errCh <- fmt.Errorf("read envelope: %w", err)
			return
		}
	}
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}
