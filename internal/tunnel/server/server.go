package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"anyproxy.dev/any-proxy/internal/tunnel/protocol"
)

// Options controls tunnel server behaviour.
type Options struct {
	ListenAddr       string
	GroupID          string
	Logger           Logger
	KeyStore         KeyStore
	HandshakeTimeout time.Duration
	HeartbeatTimeout time.Duration
}

// Logger is a minimal logging interface.
type Logger interface {
	Printf(string, ...interface{})
}

// KeyStore validates agent keys.
type KeyStore interface {
	ValidateKey(ctx context.Context, nodeID, key string) (SessionInfo, error)
}

// SessionInfo describes an authenticated tunnel client.
type SessionInfo struct {
	AgentID string
	NodeID  string
	GroupID string
}

// Server accepts tunnel-agent connections and bridges them to local transports.
type Server struct {
	opts   Options
	mu     sync.RWMutex
	sess   map[string]*session
	listen net.Listener
}

type session struct {
	nodeID    string
	agentID   string
	createdAt time.Time
	lastSeen  time.Time
	cancel    context.CancelFunc
}

// New creates a tunnel server.
func New(opts Options) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("listen addr required")
	}
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	return &Server{
		opts: normalizeOptions(opts),
		sess: make(map[string]*session),
	}, nil
}

func normalizeOptions(opts Options) Options {
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.HeartbeatTimeout <= 0 {
		opts.HeartbeatTimeout = 30 * time.Second
	}
	return opts
}

// Serve starts accepting tunnel connections.
func (s *Server) Serve(ctx context.Context) error {
	var err error
	s.listen, err = net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.opts.Logger.Printf("[tunnel-server] listening on %s group=%s", s.opts.ListenAddr, s.opts.GroupID)
	defer s.listen.Close()

	for {
		conn, err := s.listen.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				s.opts.Logger.Printf("[tunnel-server] accept error: %v", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		s.opts.Logger.Printf("[tunnel-server] failed to set deadline: %v", err)
		return
	}
	env, err := protocol.ReadEnvelope(conn)
	if err != nil {
		s.opts.Logger.Printf("[tunnel-server] handshake read error: %v", err)
		return
	}
	if env.Type != protocol.MessageTypeHandshake || env.Handshake == nil {
		s.opts.Logger.Printf("[tunnel-server] invalid handshake envelope")
		return
	}

	info := SessionInfo{
		NodeID: env.Handshake.NodeID,
	}
	if s.opts.KeyStore != nil {
		info, err = s.opts.KeyStore.ValidateKey(ctx, env.Handshake.NodeID, env.Handshake.Key)
		if err != nil {
			s.opts.Logger.Printf("[tunnel-server] key validation failed node=%s: %v", env.Handshake.NodeID, err)
			return
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.opts.Logger.Printf("[tunnel-server] clear deadline: %v", err)
		return
	}

	cCtx, cancel := context.WithCancel(ctx)
	s.registerSession(info, cancel)
	defer s.unregisterSession(info.NodeID)

	s.opts.Logger.Printf("[tunnel-server] session established node=%s agent=%s", info.NodeID, info.AgentID)

	readErr := s.readLoop(cCtx, conn, info.NodeID)
	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		s.opts.Logger.Printf("[tunnel-server] session error node=%s: %v", info.NodeID, readErr)
	}
}

func (s *Server) readLoop(ctx context.Context, conn net.Conn, nodeID string) error {
	for {
		if deadlineErr := conn.SetReadDeadline(time.Now().Add(s.opts.HeartbeatTimeout * 2)); deadlineErr != nil {
			return deadlineErr
		}
		env, err := protocol.ReadEnvelope(conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case protocol.MessageTypeHeartbeat:
			s.touchSession(nodeID)
		default:
			s.opts.Logger.Printf("[tunnel-server] node=%s received unsupported envelope=%s", nodeID, env.Type)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (s *Server) registerSession(info SessionInfo, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.sess[info.NodeID] = &session{
		nodeID:    info.NodeID,
		agentID:   info.AgentID,
		createdAt: now,
		lastSeen:  now,
		cancel:    cancel,
	}
}

func (s *Server) unregisterSession(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sess[nodeID]; ok {
		sess.cancel()
		delete(s.sess, nodeID)
	}
}

func (s *Server) touchSession(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sess[nodeID]; ok {
		sess.lastSeen = time.Now().UTC()
	}
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}
