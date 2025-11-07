package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Version identifies the tunnel protocol version.
const Version = 1

// HandshakeMessage is exchanged when a tunnel-agent connects to edge-agent.
type HandshakeMessage struct {
	NodeID              string       `json:"nodeId"`
	Key                 string       `json:"key"`
	Version             int          `json:"version"`
	PreferredTransports []string     `json:"preferredTransports,omitempty"` // quic, websocket
	Capabilities        Capabilities `json:"capabilities"`
}

// Capabilities advertises optional features.
type Capabilities struct {
	SupportsUDP         bool `json:"supportsUdp"`
	SupportsCompression bool `json:"supportsCompression"`
}

// Heartbeat carries keepalive metadata.
type Heartbeat struct {
	Timestamp     time.Time `json:"timestamp"`
	ActiveStreams int       `json:"activeStreams"`
}

// FrameType enumerates multiplexed frame types.
type FrameType uint8

const (
	FrameTypeData FrameType = iota + 1
	FrameTypeOpen
	FrameTypeClose
	FrameTypeHeartbeat
)

// DataFrame transports TCP/UDP payloads.
type DataFrame struct {
	StreamID uint32
	Flags    uint8
	Payload  []byte
}

const (
	MessageTypeHandshake = "handshake"
	MessageTypeHeartbeat = "heartbeat"
)

// Envelope is a generic tunnel control message.
type Envelope struct {
	Type      string            `json:"type"`
	Handshake *HandshakeMessage `json:"handshake,omitempty"`
	Heartbeat *Heartbeat        `json:"heartbeat,omitempty"`
}

// WriteEnvelope serialises an envelope with a length prefix.
func WriteEnvelope(w io.Writer, env Envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	var lenBuf [4]byte
	if len(payload) > int(^uint32(0)) {
		return fmt.Errorf("payload too large")
	}
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ReadEnvelope decodes an envelope from a length-prefixed frame.
func ReadEnvelope(r io.Reader) (Envelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Envelope{}, fmt.Errorf("read length: %w", err)
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 {
		return Envelope{}, fmt.Errorf("empty envelope")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Envelope{}, fmt.Errorf("read payload: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return env, nil
}
