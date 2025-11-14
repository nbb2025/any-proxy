package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

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

// RouteConfig describes a bridge listener exposed to HAProxy.
type RouteConfig struct {
	ID                  string
	ServiceID           string
	ListenAddr          string
	Protocol            string
	IdleTimeout         time.Duration
	EnableProxyProtocol bool
}

// Config encapsulates runtime server configuration.
type Config struct {
	GroupID string
	Routes  []RouteConfig
}

// Server accepts tunnel-agent connections and bridges them to local transports.
type Server struct {
	opts   Options
	listen net.Listener

	mu           sync.RWMutex
	sessions     map[string]*agentSession
	serviceIndex map[string][]*agentSession
	pending      map[string]*pendingBridge
	bridges      map[string]*bridgeListener
	config       Config
}

// New creates a tunnel server.
func New(opts Options) (*Server, error) {
	if strings.TrimSpace(opts.ListenAddr) == "" {
		return nil, errors.New("listen addr required")
	}
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.HeartbeatTimeout <= 0 {
		opts.HeartbeatTimeout = 30 * time.Second
	}
	return &Server{
		opts:         opts,
		sessions:     make(map[string]*agentSession),
		serviceIndex: make(map[string][]*agentSession),
		pending:      make(map[string]*pendingBridge),
		bridges:      make(map[string]*bridgeListener),
	}, nil
}

// UpdateConfig applies the desired runtime routes.
func (s *Server) UpdateConfig(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	existing := make(map[string]*bridgeListener, len(s.bridges))
	for id, listener := range s.bridges {
		existing[id] = listener
	}
	for _, route := range cfg.Routes {
		listener, ok := s.bridges[route.ID]
		if ok {
			if listener.cfg.ListenAddr != route.ListenAddr {
				listener.stop()
				delete(s.bridges, route.ID)
				bl, err := s.startBridgeListener(route)
				if err != nil {
					s.opts.Logger.Printf("[tunnel-server] failed to restart bridge route=%s addr=%s err=%v", route.ID, route.ListenAddr, err)
					continue
				}
				s.bridges[route.ID] = bl
			} else {
				listener.update(route)
			}
			delete(existing, route.ID)
			continue
		}
		bl, err := s.startBridgeListener(route)
		if err != nil {
			s.opts.Logger.Printf("[tunnel-server] failed to start bridge route=%s addr=%s err=%v", route.ID, route.ListenAddr, err)
			continue
		}
		s.bridges[route.ID] = bl
	}
	for id, listener := range existing {
		listener.stop()
		delete(s.bridges, id)
	}
	return nil
}

// Serve starts accepting tunnel connections.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.listen = ln
	s.opts.Logger.Printf("[tunnel-server] listening on %s group=%s", s.opts.ListenAddr, s.opts.GroupID)
	go s.acceptLoop(ctx)
	<-ctx.Done()
	ln.Close()
	s.shutdown()
	return ctx.Err()
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listen.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.opts.Logger.Printf("[tunnel-server] accept error: %v", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	if err := conn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		s.opts.Logger.Printf("[tunnel-server] set deadline error: %v", err)
		conn.Close()
		return
	}
	env, err := protocol.ReadEnvelope(conn)
	if err != nil {
		s.opts.Logger.Printf("[tunnel-server] handshake read error: %v", err)
		conn.Close()
		return
	}
	if env.Type != protocol.MessageTypeHandshake || env.Handshake == nil {
		s.opts.Logger.Printf("[tunnel-server] invalid handshake envelope")
		conn.Close()
		return
	}
	handshake := env.Handshake
	info := SessionInfo{NodeID: handshake.NodeID}
	if s.opts.KeyStore != nil {
		info, err = s.opts.KeyStore.ValidateKey(ctx, handshake.NodeID, handshake.Key)
		if err != nil {
			s.opts.Logger.Printf("[tunnel-server] key validation failed node=%s: %v", handshake.NodeID, err)
			conn.Close()
			return
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.opts.Logger.Printf("[tunnel-server] clear deadline: %v", err)
		conn.Close()
		return
	}
	role := strings.ToLower(strings.TrimSpace(handshake.Role))
	switch role {
	case "data":
		s.handleDataSession(ctx, conn, handshake, info)
	default:
		s.handleControlSession(ctx, conn, handshake, info)
	}
}

func (s *Server) handleControlSession(ctx context.Context, conn net.Conn, handshake *protocol.HandshakeMessage, info SessionInfo) {
	services := make(map[string]struct{})
	for _, svc := range handshake.Services {
		id := strings.TrimSpace(svc.ID)
		if id == "" {
			continue
		}
		services[id] = struct{}{}
	}
	if len(services) == 0 && strings.TrimSpace(handshake.ServiceID) != "" {
		services[strings.TrimSpace(handshake.ServiceID)] = struct{}{}
	}
	if len(services) == 0 {
		s.opts.Logger.Printf("[tunnel-server] rejecting control session agent=%s reason=no-services", info.AgentID)
		conn.Close()
		return
	}
	if s.opts.GroupID != "" && strings.TrimSpace(handshake.GroupID) != "" && !strings.EqualFold(strings.TrimSpace(handshake.GroupID), s.opts.GroupID) {
		s.opts.Logger.Printf("[tunnel-server] group mismatch agent=%s expected=%s got=%s", info.AgentID, s.opts.GroupID, handshake.GroupID)
		conn.Close()
		return
	}
	sessionID := strings.TrimSpace(info.AgentID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(handshake.NodeID)
	}
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	sessCtx, cancel := context.WithCancel(ctx)
	session := &agentSession{
		agentID:  sessionID,
		nodeID:   info.NodeID,
		groupID:  info.GroupID,
		services: services,
		conn:     conn,
		sendCh:   make(chan protocol.Envelope, 16),
		ctx:      sessCtx,
		cancel:   cancel,
		lastSeen: time.Now().UTC(),
	}
	s.registerSession(session)
	s.opts.Logger.Printf("[tunnel-server] control session established agent=%s services=%d", info.AgentID, len(services))
	go s.controlWriteLoop(session)
	go s.controlReadLoop(session)
}

func (s *Server) handleDataSession(ctx context.Context, conn net.Conn, handshake *protocol.HandshakeMessage, info SessionInfo) {
	token := strings.TrimSpace(handshake.Token)
	serviceID := strings.TrimSpace(handshake.ServiceID)
	if token == "" {
		s.opts.Logger.Printf("[tunnel-server] data session missing token agent=%s", info.AgentID)
		conn.Close()
		return
	}
	if serviceID == "" {
		s.opts.Logger.Printf("[tunnel-server] data session missing serviceID agent=%s", info.AgentID)
		conn.Close()
		return
	}
	pending := s.takePendingBridge(token)
	if pending == nil {
		s.opts.Logger.Printf("[tunnel-server] token not found token=%s agent=%s", token, info.AgentID)
		conn.Close()
		return
	}
	if pending.serviceID != serviceID {
		s.opts.Logger.Printf("[tunnel-server] service mismatch token=%s expected=%s got=%s", token, pending.serviceID, serviceID)
		pending.close()
		conn.Close()
		return
	}
	s.startBridge(pending, conn)
}

func (s *Server) controlReadLoop(session *agentSession) {
	defer func() {
		s.unregisterSession(session.agentID)
		session.conn.Close()
		session.cancel()
	}()
	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}
		env, err := protocol.ReadEnvelope(session.conn)
		if err != nil {
			s.opts.Logger.Printf("[tunnel-server] control read error agent=%s err=%v", session.agentID, err)
			return
		}
		switch env.Type {
		case protocol.MessageTypeHeartbeat:
			session.touch()
		default:
			s.opts.Logger.Printf("[tunnel-server] control received unsupported envelope=%s agent=%s", env.Type, session.agentID)
		}
	}
}

func (s *Server) controlWriteLoop(session *agentSession) {
	for {
		select {
		case env := <-session.sendCh:
			if err := protocol.WriteEnvelope(session.conn, env); err != nil {
				s.opts.Logger.Printf("[tunnel-server] control write error agent=%s err=%v", session.agentID, err)
				return
			}
		case <-session.ctx.Done():
			return
		}
	}
}

func (s *Server) registerSession(session *agentSession) {
	var previous *agentSession
	s.mu.Lock()
	if existing, ok := s.sessions[session.agentID]; ok {
		previous = existing
	}
	s.sessions[session.agentID] = session
	for svc := range session.services {
		list := s.serviceIndex[svc]
		list = append(list, session)
		s.serviceIndex[svc] = list
	}
	s.mu.Unlock()
	if previous != nil {
		previous.close()
		previous.conn.Close()
	}
}

func (s *Server) unregisterSession(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[agentID]
	if !ok {
		return
	}
	delete(s.sessions, agentID)
	for svc := range sess.services {
		list := s.serviceIndex[svc]
		filtered := list[:0]
		for _, candidate := range list {
			if candidate.agentID == agentID {
				continue
			}
			filtered = append(filtered, candidate)
		}
		if len(filtered) == 0 {
			delete(s.serviceIndex, svc)
		} else {
			s.serviceIndex[svc] = filtered
		}
	}
}

func (s *Server) pickSession(serviceID string) *agentSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.serviceIndex[serviceID]
	if len(list) == 0 {
		return nil
	}
	session := list[0]
	if len(list) > 1 {
		s.serviceIndex[serviceID] = append(list[1:], session)
	}
	return session
}

func (s *Server) handleBridgeConn(route RouteConfig, clientConn net.Conn) {
	session := s.pickSession(route.ServiceID)
	if session == nil {
		s.opts.Logger.Printf("[tunnel-server] no session for service=%s", route.ServiceID)
		clientConn.Close()
		return
	}
	token := uuid.NewString()
	pending := &pendingBridge{
		token:     token,
		serviceID: route.ServiceID,
		route:     route,
		conn:      clientConn,
		created:   time.Now().UTC(),
		server:    s,
	}
	s.storePending(pending)
	cmd := protocol.Envelope{
		Type: protocol.MessageTypeBridge,
		Bridge: &protocol.BridgeCommand{
			Action:    "open",
			Token:     token,
			ServiceID: route.ServiceID,
		},
	}
	if err := session.send(cmd); err != nil {
		s.opts.Logger.Printf("[tunnel-server] send command failed agent=%s err=%v", session.agentID, err)
		s.dropPending(token)
		pending.close()
	}
}

func (s *Server) storePending(pb *pendingBridge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[pb.token] = pb
	pb.startTimer()
}

func (s *Server) takePendingBridge(token string) *pendingBridge {
	s.mu.Lock()
	defer s.mu.Unlock()
	pb, ok := s.pending[token]
	if !ok {
		return nil
	}
	delete(s.pending, token)
	return pb
}

func (s *Server) dropPending(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, token)
}

func (s *Server) startBridge(pb *pendingBridge, dataConn net.Conn) {
	defer pb.cleanup()
	defer dataConn.Close()
	if pb.route.IdleTimeout > 0 {
		_ = pb.conn.SetDeadline(time.Now().Add(pb.route.IdleTimeout))
		_ = dataConn.SetDeadline(time.Now().Add(pb.route.IdleTimeout))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(pb.conn, dataConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dataConn, pb.conn)
	}()
	wg.Wait()
}

func (s *Server) startBridgeListener(route RouteConfig) (*bridgeListener, error) {
	ln, err := net.Listen("tcp", route.ListenAddr)
	if err != nil {
		return nil, err
	}
	bl := &bridgeListener{
		server:   s,
		listener: ln,
		cfg:      route,
		stopCh:   make(chan struct{}),
	}
	go bl.serve()
	return bl, nil
}

func (s *Server) shutdown() {
	s.mu.Lock()
	for _, bl := range s.bridges {
		bl.stop()
	}
	for _, pb := range s.pending {
		pb.close()
	}
	for _, sess := range s.sessions {
		sess.close()
	}
	sessions := s.sessions
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.conn.Close()
	}
}

type agentSession struct {
	agentID  string
	nodeID   string
	groupID  string
	services map[string]struct{}
	conn     net.Conn
	sendCh   chan protocol.Envelope
	ctx      context.Context
	cancel   context.CancelFunc
	lastSeen time.Time
}

func (s *agentSession) send(env protocol.Envelope) error {
	select {
	case s.sendCh <- env:
		return nil
	case <-s.ctx.Done():
		return errors.New("session closed")
	}
}

func (s *agentSession) touch() {
	s.lastSeen = time.Now().UTC()
}

func (s *agentSession) close() {
	s.cancel()
}

type bridgeListener struct {
	server   *Server
	listener net.Listener
	stopCh   chan struct{}
	cfg      RouteConfig
}

func (b *bridgeListener) serve() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			select {
			case <-b.stopCh:
				return
			default:
				b.server.opts.Logger.Printf("[tunnel-server] bridge accept error route=%s err=%v", b.cfg.ID, err)
				continue
			}
		}
		go b.server.handleBridgeConn(b.cfg, conn)
	}
}

func (b *bridgeListener) stop() {
	close(b.stopCh)
	_ = b.listener.Close()
}

func (b *bridgeListener) update(cfg RouteConfig) {
	b.cfg = cfg
}

type pendingBridge struct {
	token     string
	serviceID string
	route     RouteConfig
	conn      net.Conn
	created   time.Time
	server    *Server
	timer     *time.Timer
}

func (p *pendingBridge) startTimer() {
	const timeout = 10 * time.Second
	p.timer = time.AfterFunc(timeout, func() {
		p.server.mu.Lock()
		if current, ok := p.server.pending[p.token]; ok && current == p {
			delete(p.server.pending, p.token)
		}
		p.server.mu.Unlock()
		p.close()
	})
}

func (p *pendingBridge) close() {
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
}

func (p *pendingBridge) cleanup() {
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}
