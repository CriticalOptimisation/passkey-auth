// Package didweb resolves a did:web identifier to its DID document and gives
// the keys the document lists under "authentication" (docs/api.md, Host
// authentication).
package didweb

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Limits of docs/api.md.
const (
	CacheTTL         = 5 * time.Minute  // how long a fetched document is kept
	RefetchInterval  = 30 * time.Second // least time between two early fetches
	FetchTimeout     = 5 * time.Second
	MaxDocumentBytes = 64 << 10
)

var (
	// ErrUnavailable: no document has been fetched yet.
	ErrUnavailable = errors.New("didweb: DID document unavailable")
	// ErrUnknownKey: the document has no usable authentication key of that id.
	ErrUnknownKey = errors.New("didweb: no such authentication key")
)

// errNotImplemented marks the skeleton of #5; the implementation replaces it.
var errNotImplemented = errors.New("didweb: not implemented")

// URL is the HTTPS address of the DID document of a did:web identifier.
func URL(did string) (string, error) { return "", errNotImplemented }

// Config of a resolver. Zero values take the defaults.
type Config struct {
	DID    string
	Client *http.Client // default: an http.Client with FetchTimeout
	// Fetch, if set, replaces the HTTPS fetch of the document (e2e build).
	Fetch  func(ctx context.Context, url string) ([]byte, error)
	Now    func() time.Time
	Logger *slog.Logger
}

// Resolver keeps the host's DID document and looks keys up in it.
type Resolver struct {
	cfg Config
}

// New checks the DID and returns a resolver; it fetches nothing yet.
func New(cfg Config) (*Resolver, error) { return &Resolver{cfg: cfg}, nil }

// HostKey returns the P-256 key whose DID URL is kid, if the document lists
// it under authentication and it is not revoked.
func (r *Resolver) HostKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	return nil, errNotImplemented
}
