package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"anyproxy.dev/any-proxy/internal/agent"
)

func main() {
	var (
		controlPlane = flag.String("control-plane", "http://127.0.0.1:8080", "Control plane base URL")
		nodeID       = flag.String("node-id", "", "Unique identifier for this tunnel node")
		outputPath   = flag.String("output", "/usr/local/openresty/nginx/conf/stream.conf", "Path to render nginx stream config")
		templatePath = flag.String("template", "", "Optional custom template path")
		reloadCmdRaw = flag.String("reload", "openresty -s reload", "Command used to reload nginx/openresty (space separated)")
		dryRun       = flag.Bool("dry-run", false, "Render config but skip reload commands")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "[tunnel-agent] ", log.LstdFlags|log.Lmicroseconds)
	reloadArgs := strings.Fields(strings.TrimSpace(*reloadCmdRaw))

	options := agent.TunnelOptions{
		ControlPlaneURL: *controlPlane,
		NodeID:          *nodeID,
		OutputPath:      *outputPath,
		TemplatePath:    *templatePath,
		ReloadCommand:   reloadArgs,
		Logger:          logger,
		DryRun:          *dryRun,
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
