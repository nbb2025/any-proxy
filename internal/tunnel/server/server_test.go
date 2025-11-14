package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"anyproxy.dev/any-proxy/internal/tunnel/protocol"
)

func TestServerBridgeLifecycle(t *testing.T) {
	ingress := freePort(t)
	bridgeAddr := freePort(t)
	backendAddr := freePort(t)

	srv, err := New(Options{
		ListenAddr: ingress,
		Logger:     noopLogger{},
		KeyStore:   &staticKeyStore{secret: "secret", agentID: "agent-1", groupID: "group-1"},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Serve(ctx)
	}()

	if err := srv.UpdateConfig(Config{GroupID: "group-1", Routes: []RouteConfig{{
		ID:         "route-1",
		ServiceID:  "svc-1",
		ListenAddr: bridgeAddr,
		Protocol:   "tcp",
	}}}); err != nil {
		t.Fatalf("update config: %v", err)
	}

	backendLn, err := net.Listen("tcp", backendAddr)
	if err != nil {
		t.Skipf("backend listen: %v", err)
	}
	defer backendLn.Close()
	var backendWG sync.WaitGroup
	backendWG.Add(1)
	go func() {
		defer backendWG.Done()
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write([]byte(strings.ToUpper(string(buf[:n]))))
		}
	}()

	agentCtx, agentCancel := context.WithCancel(ctx)
	defer agentCancel()
	agentReady := make(chan struct{})
	go runFakeAgent(t, agentCtx, ingress, backendAddr, agentReady)
	select {
	case <-agentReady:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent handshake timeout")
	}

	tryBridgeRoundTrip(t, bridgeAddr)
	backendWG.Wait()
}

func tryBridgeRoundTrip(t *testing.T, addr string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				lastErr = err
				return
			}
			buf := make([]byte, 16)
			n, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				return
			}
			if got := string(buf[:n]); got != "PING" {
				lastErr = fmt.Errorf("unexpected response %q", got)
				return
			}
			lastErr = nil
		}()
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("bridge roundtrip failed: %v", lastErr)
}

func runFakeAgent(t *testing.T, ctx context.Context, ingress, backendAddr string, ready chan<- struct{}) {
	conn, err := net.Dial("tcp", ingress)
	if err != nil {
		t.Fatalf("agent control dial: %v", err)
	}
	defer conn.Close()
	shake := protocol.Envelope{
		Type: protocol.MessageTypeHandshake,
		Handshake: &protocol.HandshakeMessage{
			NodeID:   "node-1",
			Key:      "secret",
			GroupID:  "group-1",
			Version:  protocol.Version,
			Role:     "control",
			Services: []protocol.ServiceAdvertisement{{ID: "svc-1", Protocol: "tcp"}},
		},
	}
	if err := protocol.WriteEnvelope(conn, shake); err != nil {
		t.Fatalf("agent handshake: %v", err)
	}
	if ready != nil {
		close(ready)
		ready = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		env, err := protocol.ReadEnvelope(conn)
		if err != nil {
			return
		}
		if env.Type != protocol.MessageTypeBridge || env.Bridge == nil {
			continue
		}
		go func(cmd protocol.BridgeCommand) {
			dataConn, err := net.Dial("tcp", ingress)
			if err != nil {
				t.Fatalf("agent data dial: %v", err)
			}
			shake := protocol.Envelope{
				Type: protocol.MessageTypeHandshake,
				Handshake: &protocol.HandshakeMessage{
					NodeID:    "node-1",
					Key:       "secret",
					GroupID:   "group-1",
					Version:   protocol.Version,
					Role:      "data",
					ServiceID: cmd.ServiceID,
					Token:     cmd.Token,
				},
			}
			if err := protocol.WriteEnvelope(dataConn, shake); err != nil {
				t.Fatalf("agent data handshake: %v", err)
			}
			localConn, err := net.Dial("tcp", backendAddr)
			if err != nil {
				t.Fatalf("agent backend dial: %v", err)
			}
			go func() {
				defer dataConn.Close()
				defer localConn.Close()
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
			}()
		}(*env.Bridge)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping server test: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

type staticKeyStore struct {
	secret  string
	agentID string
	groupID string
}

func (s *staticKeyStore) ValidateKey(ctx context.Context, nodeID, key string) (SessionInfo, error) {
	if key != s.secret {
		return SessionInfo{}, fmt.Errorf("invalid key")
	}
	return SessionInfo{AgentID: s.agentID, NodeID: nodeID, GroupID: s.groupID}, nil
}
