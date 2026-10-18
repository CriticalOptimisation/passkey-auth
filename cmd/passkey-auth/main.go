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
	if err := run(log); err != nil {
		log.Error("exit", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	settings, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := sqlite.Open(ctx, settings.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	settings.API.Logger = log
	api, err := httpapi.New(settings.API, st)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              settings.Listen,
		Handler:           wrap(api, api),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", settings.Listen, "rp_id", settings.API.RPID)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
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
