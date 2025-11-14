package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"anyproxy.dev/any-proxy/internal/agent"
	"anyproxy.dev/any-proxy/pkg/version"
)

type stringList []string

func (s *stringList) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		*s = append(*s, trimmed)
	}
	return nil
}

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func main() {
	var (
		controlPlane  = flag.String("control-plane", "http://127.0.0.1:8080", "Control plane base URL")
		nodeID        = flag.String("node-id", "", "Unique identifier for this tunnel node")
		agentKey      = flag.String("agent-key", "", "Agent key issued by control plane")
		agentKeyPath  = flag.String("agent-key-file", "", "Path to file containing the agent key")
		groupID       = flag.String("group-id", "", "Optional tunnel group identifier override")
		watchTimeout  = flag.Duration("watch-timeout", 55*time.Second, "Snapshot watch timeout interval")
		retryInterval = flag.Duration("retry-interval", 5*time.Second, "Retry interval when fetching snapshots")
		printVersion  = flag.Bool("version", false, "Print agent version and exit")
	)
	var edges stringList
	flag.Var(&edges, "edge", "Edge candidate host:port (repeatable or comma separated)")
	flag.Parse()

	if *printVersion {
		fmt.Println(version.Summary())
		return
	}

	logger := log.New(os.Stdout, "[tunnel-agent] ", log.LstdFlags|log.Lmicroseconds)

	options := agent.TunnelOptions{
		ControlPlaneURL: *controlPlane,
		NodeID:          *nodeID,
		AgentKey:        *agentKey,
		AgentKeyPath:    *agentKeyPath,
		GroupID:         *groupID,
		EdgeCandidates:  edges,
		WatchTimeout:    *watchTimeout,
		RetryInterval:   *retryInterval,
		Logger:          logger,
	}

	tunnel, err := agent.NewTunnelAgent(options)
	if err != nil {
		logger.Fatalf("init tunnel agent failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := tunnel.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("tunnel agent terminated: %v", err)
	}
}
