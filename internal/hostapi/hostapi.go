// Package hostapi serves the host-facing routes of docs/api.md: registration
// tickets, and the listing and revocation of an account's credentials. It is
// served on the host listener only.
package hostapi

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/CriticalOptimisation/passkey-auth/internal/ceremony"
	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
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
	log *slog.Logger
}

// New validates the configuration and builds the server.
func New(cfg Config, st store.Store) (*Server, error) {
	if cfg.HostDID == "" || cfg.Audience == "" || cfg.Keys == nil || cfg.Tickets == nil || st == nil {
		return nil, errors.New("hostapi: host DID, audience, keys, ticket issuer and store are required")
	}
	if cfg.TicketTTL == 0 {
		cfg.TicketTTL = httpapi.DefaultTicketTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, st: st, log: cfg.Logger}, nil
}

// Route names, logged in place of the path: a path holds an account
// reference, which the logs never carry (docs/configuration.md, Logs).
const (
	routeTickets     = "/v1/registration-tickets"
	routeCredentials = "/v1/accounts/{account}/credentials"
	routeCredential  = "/v1/accounts/{account}/credentials/{id}"
	routeUnknown     = "unknown"
)

// ServeHTTP routes a request and writes one log line for it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	name := s.serve(rec, r)
	s.log.Info("request", "method", r.Method, "route", name, "status", rec.status,
		"duration_ms", time.Since(start).Milliseconds())
}

// serve matches the route on the escaped path, so that an account reference
// may hold "%2F"; then it checks the host token, then runs the route.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) string {
	seg := strings.Split(r.URL.EscapedPath(), "/")
	var name, method, account string
	var id []byte
	switch {
	case len(seg) == 3 && seg[0] == "" && seg[1] == "v1" && seg[2] == "registration-tickets":
		name, method = routeTickets, http.MethodPost
	case len(seg) == 5 && seg[0] == "" && seg[1] == "v1" && seg[2] == "accounts" && seg[4] == "credentials":
		name, method = routeCredentials, http.MethodGet
	case len(seg) == 6 && seg[0] == "" && seg[1] == "v1" && seg[2] == "accounts" && seg[4] == "credentials" && seg[5] != "":
		name, method = routeCredential, http.MethodDelete
	default:
		httpapi.WriteError(w, http.StatusNotFound, "not_found", "no such route")
		return routeUnknown
	}
	if name != routeTickets {
		a, err := url.PathUnescape(seg[3])
		if err != nil || a == "" {
			httpapi.WriteError(w, http.StatusNotFound, "not_found", "no such route")
			return routeUnknown
		}
		account = a
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		httpapi.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+method)
		return name
	}
	if !s.authenticate(w, r) {
		return name
	}
	switch name {
	case routeTickets:
		s.ticket(w, r)
	case routeCredentials:
		s.credentials(w, r, account)
	case routeCredential:
		// An ID that is not base64url names no credential.
		var err error
		if id, err = base64.RawURLEncoding.Strict().DecodeString(seg[5]); err != nil || len(id) == 0 {
			httpapi.WriteError(w, http.StatusNotFound, "not_found", "no such credential for this account")
			return name
		}
		s.revoke(w, r, account, id)
	}
	return name
}

// authenticate checks the host token; on failure it answers and returns false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	reason, err := s.check(r)
	switch {
	case err == nil:
		return true
	case errors.Is(err, didweb.ErrUnavailable):
		s.log.Warn("host refused", "reason", "DID document unavailable")
		httpapi.WriteError(w, http.StatusServiceUnavailable, ceremony.CodeUnavailable, "the host's DID document is unavailable, retry later")
	default:
		s.log.Warn("host refused", "reason", reason)
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpapi.WriteError(w, http.StatusUnauthorized, CodeHostUnauthorized, "the host token is missing or invalid")
	}
	return false
}

var errRefused = errors.New("host token refused")

// check verifies the host token of r. The reason is for the log; it never
// holds the token.
func (s *Server) check(r *http.Request) (string, error) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return "no bearer token", errRefused
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return "not a compact ES256 JWS", errRefused
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TokenType {
		return "typ is not " + TokenType, errRefused
	}
	if !strings.HasPrefix(h.KeyID, s.cfg.HostDID+"#") {
		return "kid is not a key of the host's DID", errRefused
	}
	key, err := s.cfg.Keys.HostKey(r.Context(), h.KeyID)
	if errors.Is(err, didweb.ErrUnavailable) {
		return "", err
	} else if err != nil {
		return "kid " + h.KeyID + ": " + err.Error(), errRefused
	}
	var c jwt.Claims
	if err := tok.Claims(key, &c); err != nil {
		return "signature or claims: " + err.Error(), errRefused
	}
	now := s.cfg.Now()
	switch {
	case c.Issuer != s.cfg.HostDID:
		return "iss is not the host's DID", errRefused
	case !c.Audience.Contains(s.cfg.Audience):
		return "aud is not this service", errRefused
	case c.IssuedAt == nil || c.Expiry == nil:
		return "iat or exp missing", errRefused
	}
	iat, exp := c.IssuedAt.Time(), c.Expiry.Time()
	switch {
	case !exp.After(iat) || exp.Sub(iat) > MaxTokenLifetime:
		return "lifetime not within 60 s", errRefused
	case iat.After(now.Add(ClockSkew)):
		return "iat in the future", errRefused
	case now.After(exp.Add(ClockSkew)):
		return "expired", errRefused
	}
	return "", nil
}

func (s *Server) ticket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account     string `json:"account"`
		DisplayName string `json:"displayName"`
	}
	if _, ok := httpapi.Decode(w, r, &req); !ok {
		return
	}
	expires := s.cfg.Now().Add(s.cfg.TicketTTL)
	ticket, err := s.cfg.Tickets.IssueTicket(r.Context(), req.Account, req.DisplayName)
	var refusal *ceremony.Error
	if errors.As(err, &refusal) && refusal.Code == ceremony.CodeInvalidRequest {
		s.log.Warn("refused", "step", "registration ticket", "code", refusal.Code, "reason", refusal.Reason)
		httpapi.WriteError(w, http.StatusBadRequest, refusal.Code, "the request is invalid")
		return
	} else if err != nil {
		s.internal(w, "registration ticket", err)
		return
	}
	s.json(w, http.StatusCreated, map[string]string{"ticket": ticket, "expiresAt": rfc3339(expires)})
}

// credential is one item of the list of docs/api.md.
type credential struct {
	ID         string   `json:"id"`
	CreatedAt  string   `json:"createdAt"`
	LastUsedAt string   `json:"lastUsedAt"`
	AAGUID     string   `json:"aaguid"`
	BE         bool     `json:"be"`
	BS         bool     `json:"bs"`
	Fmt        string   `json:"fmt"`
	Transports []string `json:"transports"`
}

func (s *Server) credentials(w http.ResponseWriter, r *http.Request, account string) {
	out := []credential{}
	handle, err := s.st.UserHandle(r.Context(), account)
	if errors.Is(err, store.ErrNotFound) {
		s.json(w, http.StatusOK, out)
		return
	} else if err != nil {
		s.internal(w, "credential list", err)
		return
	}
	creds, err := s.st.CredentialsOf(r.Context(), handle)
	if err != nil {
		s.internal(w, "credential list", err)
		return
	}
	for _, c := range creds {
		transports := c.Transports
		if transports == nil {
			transports = []string{}
		}
		out = append(out, credential{
			ID: base64.RawURLEncoding.EncodeToString(c.ID), CreatedAt: rfc3339(c.CreatedAt), LastUsedAt: rfc3339(c.LastUsedAt),
			AAGUID: ceremony.UUID(c.AAGUID), BE: c.BackupEligible, BS: c.BackupState, Fmt: c.AttestationFormat,
			Transports: transports,
		})
	}
	s.json(w, http.StatusOK, out)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, account string, id []byte) {
	handle, err := s.st.UserHandle(r.Context(), account)
	if err == nil {
		err = s.st.DeleteCredential(r.Context(), handle, id)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpapi.WriteError(w, http.StatusNotFound, "not_found", "no such credential for this account")
	case err != nil:
		s.internal(w, "credential revocation", err)
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) json(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		s.internal(w, "encoding", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error("internal error", "step", what, "error", err.Error())
	httpapi.WriteError(w, http.StatusInternalServerError, "internal", "unexpected error")
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
