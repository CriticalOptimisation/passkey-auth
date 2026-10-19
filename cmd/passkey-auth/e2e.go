//go:build e2e

// Test-only routes of the e2e build (docs/configuration.md, Development
// builds). Release builds never carry the e2e tag.
package main

import (
	"encoding/json"
	"net/http"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
)

func init() {
	wrap = func(api *httpapi.Server, h http.Handler) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /test/tickets", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Account     string `json:"account"`
				DisplayName string `json:"displayName"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ticket, err := api.IssueTicket(r.Context(), req.Account, req.DisplayName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"ticket": ticket})
		})
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
