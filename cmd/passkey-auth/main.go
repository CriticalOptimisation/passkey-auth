// Command passkey-auth serves the WebAuthn ceremonies of docs/api.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/config"
	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
)

// Timeouts of the HTTP server. Request bodies are small (httpapi.MaxBodyKiB),
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
var wrap = func(_ *httpapi.Server, h http.Handler) http.Handler { return h }

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

// run serves until the server fails or ctx is cancelled.
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

	// Build the HTTP handlers of docs/api.md on top of the store.
	settings.API.Logger = log
	api, err := httpapi.New(settings.API, st)
	if err != nil {
		return err
	}
	// Configure the HTTP server; the timeouts cut slow clients off.
	srv := &http.Server{
		Addr:              settings.Listen,
		Handler:           wrap(api, api),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	// Serve in a background goroutine, which sends its final error on errc.
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", settings.Listen, "rp_id", settings.API.RPID)

	// Block until the server fails (port in use, ...) or a signal cancels ctx.
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Graceful shutdown: refuse new connections, give in-flight requests shutdownTimeout.
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | service entry point, graceful shutdown                        |
