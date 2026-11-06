// Package app wires configuration, storage, the API server and background workers together.
//
// Implementations plug in through the registries below, from init() functions in their own
// files (wire_storage.go, wire_tls.go).
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/config"
	_ "github.com/nathabonfim59/segredium/internal/ops" // registers every operation
	"github.com/nathabonfim59/segredium/internal/peercred"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

type (
	StoreFactory      func(cfg *config.Config) (store.Store, error)
	AuthFactory       func(cfg *config.Config, d *sm.Deps) (api.Authenticator, error)
	TLSFactory        func(cfg *config.Config, d *sm.Deps) (api.TLSProvider, error)
	ReplicatorFactory func(d *sm.Deps) sm.Replicator
	// Worker runs until ctx is done. Returning an error before that stops the server.
	Worker func(ctx context.Context, d *sm.Deps) error
)

var (
	mu         sync.Mutex
	stores     = map[string]StoreFactory{}
	auths      = map[string]AuthFactory{}
	tlss       = map[string]TLSFactory{}
	workers    = map[string]Worker{}
	replicator ReplicatorFactory
)

func register[T any](m map[string]T, kind, name string, v T) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := m[name]; dup {
		panic(fmt.Sprintf("app: duplicate %s %q", kind, name))
	}
	m[name] = v
}

func RegisterStore(backend string, f StoreFactory) { register(stores, "store", backend, f) }
func RegisterAuth(mode string, f AuthFactory)      { register(auths, "auth mode", mode, f) }
func RegisterTLS(mode string, f TLSFactory)        { register(tlss, "tls mode", mode, f) }
func RegisterWorker(name string, w Worker)         { register(workers, "worker", name, w) }

// SetReplicator installs the replication implementation (default: no-op).
func SetReplicator(f ReplicatorFactory) {
	mu.Lock()
	defer mu.Unlock()
	replicator = f
}

func init() {
	RegisterStore("memory", func(*config.Config) (store.Store, error) { return memstore.New(), nil })
	RegisterAuth("none", func(*config.Config, *sm.Deps) (api.Authenticator, error) { return api.ParseOnlyAuthenticator{}, nil })
	RegisterTLS("files", func(c *config.Config, _ *sm.Deps) (api.TLSProvider, error) {
		return api.FilesTLSProvider{CertFile: c.TLS.CertFile, KeyFile: c.TLS.KeyFile}, nil
	})
}

func get[T any](m map[string]T, kind, name string) (T, error) {
	mu.Lock()
	defer mu.Unlock()
	v, ok := m[name]
	if !ok {
		var zero T
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		return zero, fmt.Errorf("unknown %s %q (available: %v)", kind, name, names)
	}
	return v, nil
}

// BuildDeps opens the store and assembles Deps (the caller closes d.Store).
func BuildDeps(cfg *config.Config, log *slog.Logger) (*sm.Deps, error) {
	sf, err := get(stores, "storage backend", cfg.Storage.Backend)
	if err != nil {
		return nil, err
	}
	st, err := sf(cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	d := &sm.Deps{Store: st, Clock: sm.SystemClock{}, Rand: rand.Reader, Config: cfg, Replicator: sm.NopReplicator{}, Log: log}
	mu.Lock()
	rf := replicator
	mu.Unlock()
	if rf != nil {
		d.Replicator = rf(d)
	}
	return d, nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	d, err := BuildDeps(cfg, log)
	if err != nil {
		return err
	}
	defer d.Store.Close()

	af, err := get(auths, "auth mode", cfg.Auth.Mode)
	if err != nil {
		return err
	}
	auth, err := af(cfg, d)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	handler := api.NewServer(d, auth)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 8)
	var wg sync.WaitGroup
	var servers []*http.Server

	listen := func(addr string, tlsOn bool) error {
		// Tight timeouts and header limits keep idle/slow clients from pinning memory.
		srv := &http.Server{Addr: addr, Handler: handler,
			ConnContext:       peercred.ConnContext,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 32 << 10,
			ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
		if tlsOn {
			tf, err := get(tlss, "tls mode", cfg.TLS.Mode)
			if err != nil {
				return err
			}
			tp, err := tf(cfg, d)
			if err != nil {
				return fmt.Errorf("tls: %w", err)
			}
			if srv.TLSConfig, err = tp.TLSConfig(); err != nil {
				return err
			}
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		servers = append(servers, srv)
		log.Info("listening", "addr", ln.Addr().String(), "tls", tlsOn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if tlsOn {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("listener %s: %w", addr, err)
			}
		}()
		return nil
	}
	if cfg.Server.HTTPSAddr != "" {
		if err := listen(cfg.Server.HTTPSAddr, true); err != nil {
			return err
		}
	}
	if cfg.Server.HTTPAddr != "" {
		if err := listen(cfg.Server.HTTPAddr, false); err != nil {
			return err
		}
	}

	mu.Lock()
	names := make([]string, 0, len(workers))
	for n := range workers {
		names = append(names, n)
	}
	mu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		w, _ := get(workers, "worker", n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w(ctx, d); err != nil && ctx.Err() == nil {
				errc <- fmt.Errorf("worker %s: %w", n, err)
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	for _, s := range servers {
		_ = s.Shutdown(shCtx)
	}
	wg.Wait()
	return runErr
}
