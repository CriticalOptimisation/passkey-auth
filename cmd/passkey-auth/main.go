// Command passkey-auth serves the WebAuthn ceremonies of docs/api.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/config"
	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/hostapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
)

// Timeouts of the HTTP servers. Request bodies are small (httpapi.MaxBodyKiB),
// so a slow client is cut off early.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
	// shutdownTimeout is how long in-flight requests get after SIGTERM.
	shutdownTimeout = 10 * time.Second
)

// wrap adds routes around the public API; the e2e build replaces it.
var wrap = func(h http.Handler) http.Handler { return h }

// fetchHostDocument, when set, replaces the HTTPS fetch of the host's DID
// document; only the e2e build sets it.
var fetchHostDocument func(ctx context.Context, url string) ([]byte, error)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// ctx gets cancelled when SIGINT or SIGTERM arrives.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, log)
	stop()
	if err != nil {
		log.Error("exit", "error", err.Error())
		os.Exit(1)
	}
}

// run serves until a server fails or ctx is cancelled.
func run(ctx context.Context, log *slog.Logger) error {
	// Read the PA_* settings from the environment; stop on the first invalid one.
	settings, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	// Open the SQLite store; the deferred Close runs on every return below, error or not.
	st, err := sqlite.Open(ctx, settings.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// Build the HTTP handlers of docs/api.md on top of the store: the public
	// API, and the host API with the keys of the host's DID document.
	settings.API.Logger = log
	api, err := httpapi.New(settings.API, st)
	if err != nil {
		return err
	}
	keys, err := didweb.New(didweb.Config{DID: settings.HostDID, Fetch: fetchHostDocument, Logger: log})
	if err != nil {
		return err
	}
	host, err := hostapi.New(hostapi.Config{
		HostDID: settings.HostDID, Audience: settings.API.Issuer, Keys: keys, Tickets: api,
		TicketTTL: settings.API.TicketTTL, Logger: log,
	}, st)
	if err != nil {
		return err
	}

	// Bind both listeners before serving: a taken port stops the service at once.
	servers := []*http.Server{newServer(settings.Listen, wrap(api)), newServer(settings.HostListen, host)}
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		l, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return fmt.Errorf("listen %s: %w", srv.Addr, err)
		}
		listeners = append(listeners, l)
	}
	// Serve each in a background goroutine, which sends its final error on errc.
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	log.Info("listening", "addr", settings.Listen, "host_addr", settings.HostListen,
		"rp_id", settings.API.RPID, "host_did", settings.HostDID)

	// Block until a server fails or a signal cancels ctx; either way, both stop.
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	// Graceful shutdown of both servers at once: refuse new connections, give
	// in-flight requests one shutdownTimeout.
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errs <- srv.Shutdown(shutdown) }()
	}
	for range servers {
		if e := <-errs; e != nil && err == nil {
			err = e
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// newServer configures a server; the timeouts cut slow clients off.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | service entry point, graceful shutdown                        |
