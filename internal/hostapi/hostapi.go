// Package hostapi serves the host-facing routes of docs/api.md: registration
// tickets, and the listing and revocation of an account's credentials. It is
// served on the host listener only.
package hostapi

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net/http"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/store"
)

// Host token rules of docs/api.md.
const (
	TokenType        = "passkey-host+jwt"
	MaxTokenLifetime = 60 * time.Second
	ClockSkew        = 5 * time.Second

	CodeHostUnauthorized = "host_unauthorized"
)

// KeySource gives the host's public key named by a token's kid
// (didweb.Resolver).
type KeySource interface {
	HostKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// TicketIssuer creates registration tickets (httpapi.Server).
type TicketIssuer interface {
	IssueTicket(ctx context.Context, account, displayName string) (string, error)
}

// Config of the host API. Zero durations take the defaults of
// docs/configuration.md.
type Config struct {
	HostDID   string // iss of host tokens: PA_HOST_DID
	Audience  string // aud of host tokens: PA_ISSUER
	Keys      KeySource
	Tickets   TicketIssuer
	TicketTTL time.Duration
	Now       func() time.Time
	Logger    *slog.Logger
}

// Server is the host-facing HTTP API.
type Server struct {
	cfg Config
	st  store.Store
}

// New validates the configuration and builds the server.
func New(cfg Config, st store.Store) (*Server, error) { return &Server{cfg: cfg, st: st}, nil }

// ServeHTTP is the skeleton of #5: nothing is served yet.
func (s *Server) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
