//go:build e2e

// Test-only additions of the e2e build (docs/configuration.md, Development
// builds). Release builds never carry the e2e tag.
package main

import (
	"context"
	"net/http"
	"os"
)

func init() {
	if path := os.Getenv("PA_E2E_HOST_DID_FILE"); path != "" {
		fetchHostDocument = func(context.Context, string) ([]byte, error) { return os.ReadFile(path) }
	}
	wrap = func(h http.Handler) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /test/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8><title>passkey-auth e2e</title>"))
		})
		mux.Handle("/", h)
		return mux
	}
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | test-only routes /test/tickets and /test/ (e2e tag)           |
