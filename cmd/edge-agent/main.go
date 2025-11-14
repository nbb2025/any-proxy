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

	"anyproxy.dev/any-proxy/internal/agent"
	"anyproxy.dev/any-proxy/pkg/version"
)

func main() {
	var (
		controlPlane     = flag.String("control-plane", "http://127.0.0.1:8080", "Control plane base URL")
		nodeID           = flag.String("node-id", "", "Unique identifier for this edge node")
		outputPath       = flag.String("output", "/usr/local/openresty/nginx/conf/nginx.conf", "Path to render nginx HTTP config")
		streamOutputPath = flag.String("stream-output", "/etc/haproxy/haproxy.cfg", "Path to render HAProxy TCP/UDP config")
		certDir          = flag.String("cert-dir", "", "Directory to store edge TLS certificates (defaults to <output>/../certs)")
		clientCADir      = flag.String("client-ca-dir", "", "Directory to store client CA bundles (defaults to cert-dir)")
		templatePath     = flag.String("template", "", "Optional custom template path for HTTP config")
		streamTemplate   = flag.String("stream-template", "", "Optional custom HAProxy template path")
		authToken        = flag.String("auth-token", "", "Optional bearer token used to authenticate against control plane")
		nodeKeyPath      = flag.String("node-key-path", "", "Path used to persist the issued node key (defaults to <output dir>/.anyproxy-node.key)")
		statusFile       = flag.String("status-file", "", "Path used to persist runtime status (defaults to /var/lib/anyproxy/edge-status-<node>.env)")
		reloadCmdRaw     = flag.String("reload", "openresty -s reload", "Command used to reload nginx/openresty (space separated)")
		haproxyReloadRaw = flag.String("haproxy-reload", "systemctl reload haproxy", "Command used to reload HAProxy (space separated, leave empty to skip)")
		dryRun           = flag.Bool("dry-run", false, "Render config but skip reload commands")
		groupID          = flag.String("group-id", "", "Optional node group identifier used for classification")
		nodeCategory     = flag.String("node-category", "", "Optional node category hint: cdn / tunnel")
		nodeName         = flag.String("node-name", "", "Optional friendly name for this node")
		agentVersion     = flag.String("agent-version", "", "Semantic version reported to control plane (leave empty or set to 'latest' to auto-detect)")
		printVersion     = flag.Bool("version", false, "Print agent version and exit")
	)
	flag.Parse()

	if *printVersion {
		fmt.Println(version.Summary())
		return
	}

	logger := log.New(os.Stdout, "[edge-agent] ", log.LstdFlags|log.Lmicroseconds)

	reloadArgs := strings.Fields(strings.TrimSpace(*reloadCmdRaw))
	var haproxyReloadArgs []string
	if trimmed := strings.TrimSpace(*haproxyReloadRaw); trimmed != "" {
		haproxyReloadArgs = strings.Fields(trimmed)
	}

	resolvedVersion := strings.TrimSpace(*agentVersion)
	if resolvedVersion == "" || strings.EqualFold(resolvedVersion, "latest") {
		resolvedVersion = version.Version
	}

	options := agent.EdgeOptions{
		ControlPlaneURL:      *controlPlane,
		NodeID:               *nodeID,
		OutputPath:           *outputPath,
		StreamOutputPath:     *streamOutputPath,
		StreamTemplatePath:   *streamTemplate,
		CertificateDir:       *certDir,
		ClientCADir:          *clientCADir,
		TemplatePath:         *templatePath,
		AuthToken:            *authToken,
		NodeKeyPath:          *nodeKeyPath,
		GroupID:              *groupID,
		NodeCategory:         *nodeCategory,
		NodeName:             *nodeName,
		ReloadCommand:        reloadArgs,
		HAProxyReloadCommand: haproxyReloadArgs,
		Logger:               logger,
		DryRun:               *dryRun,
		AgentVersion:         resolvedVersion,
		StatusPath:           strings.TrimSpace(*statusFile),
	}

	edge, err := agent.NewEdgeAgent(options)
	if err != nil {
		logger.Fatalf("init edge agent failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := edge.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("edge agent terminated: %v", err)
	}
}
