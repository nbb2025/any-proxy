package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"anyproxy.dev/any-proxy/internal/api"
	"anyproxy.dev/any-proxy/internal/auth"
	"anyproxy.dev/any-proxy/internal/configstore"
)

func main() {
	var (
		listenAddr      = flag.String("listen", ":8080", "HTTP listen address")
		seedPath        = flag.String("seed", "", "Optional JSON file used to seed initial configuration")
		etcdEndpoints   = flag.String("etcd-endpoints", "", "Comma separated etcd endpoints, enables persistent store if set")
		etcdUsername    = flag.String("etcd-username", "", "Username for etcd authentication")
		etcdPassword    = flag.String("etcd-password", "", "Password for etcd authentication")
		etcdPrefix      = flag.String("etcd-prefix", "/any-proxy/", "Key prefix when storing data in etcd")
		etcdTimeout     = flag.Duration("etcd-timeout", 5*time.Second, "Per-request timeout when talking to etcd")
		etcdDialTimeout = flag.Duration("etcd-dial-timeout", 5*time.Second, "Dial timeout when connecting to etcd")
		etcdCertPath    = flag.String("etcd-cert", "", "Client TLS certificate file for etcd")
		etcdKeyPath     = flag.String("etcd-key", "", "Client TLS key file for etcd")
		etcdCAPath      = flag.String("etcd-ca", "", "CA bundle for verifying etcd server certificates")
		etcdSkipVerify  = flag.Bool("etcd-insecure-skip-verify", false, "Skip TLS certificate verification for etcd (NOT recommended)")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "[control-plane] ", log.LstdFlags|log.Lmicroseconds)

	var (
		store      configstore.Store
		etcdClient *clientv3.Client
		healthFn   func(context.Context) error
	)

	if endpointsRaw := strings.TrimSpace(*etcdEndpoints); endpointsRaw != "" {
		endpoints := splitAndClean(endpointsRaw)
		if len(endpoints) == 0 {
			logger.Fatalf("etcd endpoints empty after trimming input")
		}

		tlsCfg, err := buildEtcdTLSConfig(*etcdCertPath, *etcdKeyPath, *etcdCAPath, *etcdSkipVerify)
		if err != nil {
			logger.Fatalf("failed to build etcd TLS config: %v", err)
		}

		cfg := clientv3.Config{
			Endpoints:   endpoints,
			DialTimeout: *etcdDialTimeout,
		}
		if tlsCfg != nil {
			cfg.TLS = tlsCfg
		}
		if *etcdUsername != "" {
			cfg.Username = *etcdUsername
			cfg.Password = *etcdPassword
		}

		etcdClient, err = clientv3.New(cfg)
		if err != nil {
			logger.Fatalf("failed to connect etcd: %v", err)
		}
		defer func() {
			_ = etcdClient.Close()
		}()

		store, err = configstore.NewEtcdStore(etcdClient, configstore.EtcdOptions{
			Prefix:  *etcdPrefix,
			Timeout: *etcdTimeout,
		})
		if err != nil {
			logger.Fatalf("init etcd store failed: %v", err)
		}

		healthFn = makeEtcdHealthFunc(etcdClient, endpoints, *etcdTimeout)
		logger.Printf("using etcd store endpoints=%v prefix=%s", endpoints, *etcdPrefix)
	} else {
		store = configstore.NewMemoryStore()
		logger.Printf("using in-memory store (data resets on restart)")
	}

	if *seedPath != "" {
		if err := loadSeed(store, *seedPath); err != nil {
			logger.Fatalf("failed to load seed file: %v", err)
		}
		logger.Printf("seed configuration loaded from %s", *seedPath)
	}

	opts := []api.Option{api.WithLogger(logger)}
	if healthFn != nil {
		opts = append(opts, api.WithHealthCheck(healthFn))
	}
	apiServer := api.NewServer(store, opts...)

	authCfg, err := auth.LoadConfigFromEnv()
	if err != nil {
		logger.Fatalf("auth configuration error: %v", err)
	}
	authMgr, err := auth.NewManager(authCfg)
	if err != nil {
		logger.Fatalf("auth manager setup failed: %v", err)
	}

	protectedMux := http.NewServeMux()
	apiServer.Register(protectedMux)

	rootMux := http.NewServeMux()
	rootMux.Handle("/auth/login", auth.LoginHandler(authMgr))
	rootMux.Handle("/auth/refresh", auth.RefreshHandler(authMgr))

	authenticatedHandler := auth.Middleware(
		protectedMux,
		authMgr,
		auth.WithSkip("GET", "/healthz"),
		auth.WithSkip("GET", "/install/"),
		auth.WithSkip("GET", "/install/*"),
		auth.WithSkip("GET", "/agent/healthz"),
	)
	rootMux.Handle("/", authenticatedHandler)

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           loggingMiddleware(logger, rootMux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Printf("control plane listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("shutdown signal received, draining...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}

	logger.Printf("control plane stopped")
}

func loadSeed(store configstore.Store, path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var seed struct {
		Domains []configstore.DomainRoute `json:"domains"`
		Tunnels []configstore.TunnelRoute `json:"tunnels"`
	}
	if err := json.Unmarshal(payload, &seed); err != nil {
		return err
	}

	for _, d := range seed.Domains {
		if _, err := store.UpsertDomain(d); err != nil {
			return err
		}
	}
	for _, t := range seed.Tunnels {
		if _, err := store.UpsertTunnel(t); err != nil {
			return err
		}
	}
	return nil
}

func splitAndClean(endpoints string) []string {
	raw := strings.Split(endpoints, ",")
	cleaned := make([]string, 0, len(raw))
	for _, ep := range raw {
		ep = strings.TrimSpace(ep)
		if ep != "" {
			cleaned = append(cleaned, ep)
		}
	}
	return cleaned
}

func buildEtcdTLSConfig(certPath, keyPath, caPath string, insecure bool) (*tls.Config, error) {
	if certPath == "" && keyPath == "" && caPath == "" && !insecure {
		return nil, nil
	}

	cfg := &tls.Config{InsecureSkipVerify: insecure}

	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, errors.New("etcd-cert and etcd-key must be provided together")
		}
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read etcd-ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("failed to parse etcd CA bundle")
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}

func makeEtcdHealthFunc(cli *clientv3.Client, endpoints []string, timeout time.Duration) func(context.Context) error {
	eps := append([]string(nil), endpoints...)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return func(ctx context.Context) error {
		for _, ep := range eps {
			reqCtx, cancel := context.WithTimeout(ctx, timeout)
			_, err := cli.Status(reqCtx, ep)
			cancel()
			if err != nil {
				return fmt.Errorf("etcd endpoint %s: %w", ep, err)
			}
		}
		return nil
	}
}

func loggingMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)
		logger.Printf("%s %s status=%d duration=%s", r.Method, r.URL.Path, ww.status, time.Since(start))
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
