package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	installassets "anyproxy.dev/any-proxy"
	"anyproxy.dev/any-proxy/internal/api"
	"anyproxy.dev/any-proxy/internal/auth"
	"anyproxy.dev/any-proxy/internal/configstore"
	"golang.org/x/mod/semver"
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
		pgDSN           = flag.String("pg-dsn", "", "PostgreSQL DSN for management-plane data")
		pgMaxIdle       = flag.Int("pg-max-idle", 4, "Max idle Postgres connections")
		pgMaxOpen       = flag.Int("pg-max-open", 16, "Max open Postgres connections")
		pgConnLifetime  = flag.Duration("pg-conn-max-lifetime", 2*time.Hour, "Max lifetime for Postgres connections")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "[control-plane] ", log.LstdFlags|log.Lmicroseconds)

	var (
		store      configstore.Store
		etcdClient *clientv3.Client
		etcdStore  *configstore.EtcdStore
		pgDB       *gorm.DB
		healthFn   func(context.Context) error
		healthFns  []func(context.Context) error
	)

	endpointsRaw := strings.TrimSpace(*etcdEndpoints)
	if endpointsRaw == "" {
		logger.Fatalf("etcd endpoints are required; set -etcd-endpoints or ETCD_ENDPOINTS")
	}
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

	etcdStore, err = configstore.NewEtcdStore(etcdClient, configstore.EtcdOptions{
		Prefix:  *etcdPrefix,
		Timeout: *etcdTimeout,
	})
	if err != nil {
		logger.Fatalf("init etcd store failed: %v", err)
	}

	store = etcdStore
	healthFns = append(healthFns, makeEtcdHealthFunc(etcdClient, endpoints, *etcdTimeout))
	logger.Printf("using etcd store endpoints=%v prefix=%s", endpoints, *etcdPrefix)

	if dsn := strings.TrimSpace(*pgDSN); dsn != "" {
		if etcdStore == nil {
			logger.Fatalf("postgres store requires etcd endpoints; set -etcd-endpoints")
		}
		var err error
		pgDB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			logger.Fatalf("postgres connection failed: %v", err)
		}
		sqlDB, err := pgDB.DB()
		if err != nil {
			logger.Fatalf("postgres driver unwrap failed: %v", err)
		}
		sqlDB.SetMaxIdleConns(*pgMaxIdle)
		sqlDB.SetMaxOpenConns(*pgMaxOpen)
		sqlDB.SetConnMaxLifetime(*pgConnLifetime)
		defer func(db *sql.DB) {
			_ = db.Close()
		}(sqlDB)

		mgmtStore, err := configstore.NewPGStore(pgDB)
		if err != nil {
			logger.Fatalf("init pg store failed: %v", err)
		}
		hybridStore, err := configstore.NewHybridStore(etcdStore, mgmtStore)
		if err != nil {
			logger.Fatalf("init hybrid store failed: %v", err)
		}
		store = hybridStore
		healthFns = append(healthFns, makePGHealthFunc(pgDB))
		logger.Printf("using hybrid store etcd-prefix=%s pg=%s", *etcdPrefix, sanitizeDSN(dsn))
	}

	if len(healthFns) == 1 {
		healthFn = healthFns[0]
	} else if len(healthFns) > 1 {
		healthFn = func(ctx context.Context) error {
			for _, fn := range healthFns {
				if err := fn(ctx); err != nil {
					return err
				}
			}
			return nil
		}
	}

	if *seedPath != "" {
		if err := loadSeed(store, *seedPath); err != nil {
			logger.Fatalf("failed to load seed file: %v", err)
		}
		logger.Printf("seed configuration loaded from %s", *seedPath)
	}

	installDir := detectInstallAssetsDir()
	versionLister := newAgentVersionLister(logger, installDir)

	opts := []api.Option{api.WithLogger(logger)}
	if healthFn != nil {
		opts = append(opts, api.WithHealthCheck(healthFn))
	}
	if versionLister != nil {
		opts = append(opts, api.WithAgentVersionLister(versionLister))
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
	installFS := http.FS(newInstallFS(logger, installDir))
	installHandler := http.StripPrefix("/install/", http.FileServer(installFS))
	rootMux.Handle("/install/", withNoStore(installHandler))
	rootMux.Handle("/install", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/install/", http.StatusMovedPermanently)
	}))
	rootMux.Handle("/auth/login", auth.LoginHandler(authMgr))
	rootMux.Handle("/auth/refresh", auth.RefreshHandler(authMgr))

	nodeKeyValidator := &nodeKeyValidator{store: store}
	authenticatedHandler := auth.Middleware(
		protectedMux,
		authMgr,
		auth.WithSkip("GET", "/healthz"),
		auth.WithSkip("GET", "/install/"),
		auth.WithSkip("GET", "/install/*"),
		auth.WithSkip("GET", "/agent/healthz"),
		auth.WithNodeKeyValidator(
			nodeKeyValidator,
			"GET /v1/config/snapshot",
			"POST /v1/nodes/register",
		),
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

func withNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func newInstallFS(logger *log.Logger, diskDir string) fs.FS {
	embedded := installassets.FS()
	if diskDir == "" {
		logger.Printf("serving installer assets from embedded bundle only")
		return embedded
	}

	absPath := diskDir
	if resolved, err := filepath.Abs(diskDir); err == nil {
		absPath = resolved
	}
	logger.Printf("serving installer assets from %s with embedded fallback", absPath)
	return &compositeInstallFS{
		disk:     os.DirFS(absPath),
		embedded: embedded,
		diskRoot: absPath,
	}
}

func detectInstallAssetsDir() string {
	candidates := []string{}
	if envDir := strings.TrimSpace(os.Getenv("INSTALL_ASSETS_DIR")); envDir != "" {
		candidates = append(candidates, envDir)
	}
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "install"))
	}
	candidates = append(candidates, "install")
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

type nodeKeyValidator struct {
	store configstore.Store
}

func (v *nodeKeyValidator) ValidateNodeKey(ctx context.Context, nodeID, secret string) error {
	if v == nil || v.store == nil {
		return fmt.Errorf("node key validator not initialised")
	}
	id := strings.TrimSpace(nodeID)
	key := strings.TrimSpace(secret)
	if id == "" || key == "" {
		return auth.ErrInvalidNodeKey
	}
	snap, err := v.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	for _, node := range snap.Nodes {
		if node.ID != id {
			continue
		}
		hash := strings.TrimSpace(node.NodeKeyHash)
		if hash == "" {
			return auth.ErrInvalidNodeKey
		}
		if configstore.HashNodeKey(key) != hash {
			return auth.ErrInvalidNodeKey
		}
		return nil
	}
	return auth.ErrInvalidNodeKey
}

type compositeInstallFS struct {
	disk     fs.FS
	embedded fs.FS
	diskRoot string
}

func (c *compositeInstallFS) Open(name string) (fs.File, error) {
	if resolved := c.resolveLatestPath(name); resolved != "" {
		name = resolved
	}
	if c.disk != nil {
		f, err := c.disk.Open(name)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return c.embedded.Open(name)
}

func (c *compositeInstallFS) resolveLatestPath(name string) string {
	const latestPrefix = "binaries/latest/"
	if c.diskRoot == "" || !strings.HasPrefix(name, latestPrefix) {
		return ""
	}
	latest := c.latestVersionDir()
	if latest == "" {
		return ""
	}
	return "binaries/" + latest + "/" + strings.TrimPrefix(name, latestPrefix)
}

func (c *compositeInstallFS) latestVersionDir() string {
	binariesDir := filepath.Join(c.diskRoot, "binaries")
	entries, err := os.ReadDir(binariesDir)
	if err != nil {
		return ""
	}
	var semverDirs []string
	var otherDirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if semver.IsValid(name) {
			semverDirs = append(semverDirs, name)
		} else {
			otherDirs = append(otherDirs, name)
		}
	}
	if len(semverDirs) > 0 {
		sort.Slice(semverDirs, func(i, j int) bool {
			return semver.Compare(semverDirs[i], semverDirs[j]) > 0
		})
		return semverDirs[0]
	}
	if len(otherDirs) > 0 {
		sort.Slice(otherDirs, func(i, j int) bool {
			return strings.ToLower(otherDirs[i]) > strings.ToLower(otherDirs[j])
		})
		return otherDirs[0]
	}
	return ""
}

func loadSeed(store configstore.Store, path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var seed struct {
		Domains      []configstore.DomainRoute `json:"domains"`
		Tunnels      []configstore.TunnelRoute `json:"tunnels"`
		TunnelGroups []configstore.TunnelGroup `json:"tunnelGroups"`
		TunnelAgents []configstore.TunnelAgent `json:"tunnelAgents"`
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
	for _, group := range seed.TunnelGroups {
		if _, _, err := store.UpsertTunnelGroup(group); err != nil {
			return err
		}
	}
	for _, agent := range seed.TunnelAgents {
		if _, _, err := store.UpsertTunnelAgent(agent); err != nil {
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

func makePGHealthFunc(db *gorm.DB) func(context.Context) error {
	return func(ctx context.Context) error {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.PingContext(ctx)
	}
}

func sanitizeDSN(dsn string) string {
	if i := strings.LastIndex(dsn, "@"); i >= 0 {
		return "***" + dsn[i:]
	}
	return dsn
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
