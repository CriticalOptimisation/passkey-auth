// Package didweb resolves a did:web identifier to its DID document and gives
// the keys the document lists under "authentication" (docs/api.md, Host
// authentication).
package didweb

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
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

const prefix = "did:web:"

var (
	// hostPart is a domain name, with an optional port once %3A is decoded.
	hostPart = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	// pathPart is one path segment: unreserved characters and %-escapes.
	pathPart = regexp.MustCompile(`^([A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$`)
)

// URL is the HTTPS address of the DID document of a did:web identifier.
func URL(did string) (string, error) {
	rest, ok := strings.CutPrefix(did, prefix)
	if !ok || rest == "" {
		return "", fmt.Errorf("didweb: %q is not a did:web identifier", did)
	}
	parts := strings.Split(rest, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil || !hostPart.MatchString(host) {
		return "", fmt.Errorf("didweb: %q: invalid domain %q", did, parts[0])
	}
	path := "/.well-known"
	if len(parts) > 1 {
		path = ""
		for _, p := range parts[1:] {
			if !pathPart.MatchString(p) || p == "." || p == ".." {
				return "", fmt.Errorf("didweb: %q: invalid path segment %q", did, p)
			}
			path += "/" + p
		}
	}
	return "https://" + host + path + "/did.json", nil
}

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
	url string

	mu        sync.Mutex // held during a fetch: concurrent lookups wait for it
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time // of the kept document
	nextFetch time.Time // when the kept document is fetched again
	lastEarly time.Time // last early fetch, for an unknown kid
}

// New checks the DID and returns a resolver; it fetches nothing yet.
func New(cfg Config) (*Resolver, error) {
	u, err := URL(cfg.DID)
	if err != nil {
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: FetchTimeout}
	}
	// A redirect may not leave HTTPS.
	client := *cfg.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s refused: HTTPS only", req.URL.Scheme)
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	cfg.Client = &client
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Resolver{cfg: cfg, url: u}, nil
}

// HostKey returns the P-256 key whose DID URL is kid, if the document lists
// it under authentication and it is not revoked.
func (r *Resolver) HostKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	fetched := false
	if r.keys == nil || !now.Before(r.nextFetch) {
		r.refresh(ctx, now)
		fetched = true
	}
	if r.keys == nil {
		return nil, ErrUnavailable
	}
	if k, ok := r.keys[kid]; ok {
		return k, nil
	}
	// A key added since the last fetch works at once, but invented kids
	// cannot make the service flood the host's site.
	if !fetched && (r.lastEarly.IsZero() || now.Sub(r.lastEarly) >= RefetchInterval) {
		r.lastEarly = now
		r.refresh(ctx, now)
		if k, ok := r.keys[kid]; ok {
			return k, nil
		}
	}
	return nil, ErrUnknownKey
}

// refresh fetches the document. On failure it keeps the last good one, and
// tries again after RefetchInterval at the earliest.
func (r *Resolver) refresh(ctx context.Context, now time.Time) {
	keys, err := r.fetch(ctx)
	if err != nil {
		r.nextFetch = now.Add(RefetchInterval)
		args := []any{"url", r.url, "error", err.Error()}
		if r.keys != nil {
			args = append(args, "kept_since", r.fetchedAt.UTC().Format(time.RFC3339))
		}
		r.cfg.Logger.Warn("host DID document fetch failed", args...)
		return
	}
	r.keys, r.fetchedAt, r.nextFetch = keys, now, now.Add(CacheTTL)
	r.cfg.Logger.Info("host DID document fetched", "url", r.url, "keys", len(keys))
}

func (r *Resolver) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	// The fetch serves every waiting lookup: the caller's cancellation does
	// not cut it short, the timeout does.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), FetchTimeout)
	defer cancel()
	var body []byte
	var err error
	if r.cfg.Fetch != nil {
		body, err = r.cfg.Fetch(ctx, r.url)
	} else {
		body, err = r.get(ctx)
	}
	if err != nil {
		return nil, err
	}
	if len(body) > MaxDocumentBytes {
		return nil, fmt.Errorf("document over %d bytes", MaxDocumentBytes)
	}
	return parse(r.cfg.DID, body)
}

func (r *Resolver) get(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/did+json, application/json")
	res, err := r.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// method is a verification method of a DID document.
type method struct {
	ID           string          `json:"id"`
	PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	Revoked      json.RawMessage `json:"revoked"`
}

// parse gives the usable authentication keys of a document, by DID URL.
func parse(did string, body []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc struct {
		ID                 string            `json:"id"`
		VerificationMethod []method          `json:"verificationMethod"`
		Authentication     []json.RawMessage `json:"authentication"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("not a DID document: %v", err)
	}
	if doc.ID != did {
		return nil, fmt.Errorf("document of %q, not of %q", doc.ID, did)
	}
	// Methods by absolute id; an id given twice names no usable key.
	methods := map[string]*method{}
	for i := range doc.VerificationMethod {
		m := &doc.VerificationMethod[i]
		id := absolute(did, m.ID)
		if _, dup := methods[id]; dup {
			methods[id] = nil
			continue
		}
		methods[id] = m
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, raw := range doc.Authentication {
		var m *method
		var ref string
		if json.Unmarshal(raw, &ref) == nil {
			m = methods[absolute(did, ref)]
		} else if json.Unmarshal(raw, &m) != nil {
			m = nil
		}
		if m == nil {
			continue
		}
		id := absolute(did, m.ID)
		if !strings.HasPrefix(id, did+"#") || id == did+"#" || revoked(m.Revoked) {
			continue
		}
		if k, err := p256(m.PublicKeyJwk); err == nil {
			keys[id] = k
		}
	}
	return keys, nil
}

// absolute reads a relative DID URL ("#fragment") against did.
func absolute(did, id string) string {
	if strings.HasPrefix(id, "#") {
		return did + id
	}
	return id
}

// revoked: any value but null or false marks the key revoked.
func revoked(v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	return len(v) > 0 && !bytes.Equal(v, []byte("null")) && !bytes.Equal(v, []byte("false"))
}

// p256 reads an EC P-256 public JWK; any other key type or curve is refused.
func p256(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.D != "" {
		return nil, errors.New("not an EC P-256 public key")
	}
	x, errX := base64.RawURLEncoding.Strict().DecodeString(jwk.X)
	y, errY := base64.RawURLEncoding.Strict().DecodeString(jwk.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("invalid P-256 coordinates")
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
}
