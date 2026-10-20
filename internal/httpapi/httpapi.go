// Package httpapi serves the public routes of docs/api.md: the ceremonies,
// the JWKS and the browser helper.
package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/ceremony"
	"github.com/CriticalOptimisation/passkey-auth/internal/store"
	"github.com/CriticalOptimisation/passkey-auth/internal/token"
	"github.com/CriticalOptimisation/passkey-auth/web"
)

// Limits and defaults of docs/api.md and docs/configuration.md.
const (
	MaxBodyKiB = 64               // request body limit, in KiB
	maxBody    = MaxBodyKiB << 10 // the same, in bytes

	DefaultChallengeTTL  = 5 * time.Minute
	DefaultTicketTTL     = 15 * time.Minute
	DefaultTokenTTL      = 60 * time.Second
	MaxTokenTTL          = 5 * time.Minute
	DefaultMaxChallenges = 100_000

	// publicMaxAge is how long clients and proxies may cache the JWKS and
	// the browser helper.
	publicMaxAge = 5 * time.Minute
	// preflightMaxAge is how long a browser may cache a CORS preflight.
	preflightMaxAge = 10 * time.Minute
	// retryAfter is the Retry-After of a 503 unavailable.
	retryAfter = 60 * time.Second
)

// Config of the public API. Zero durations and counts take the defaults of
// docs/configuration.md.
type Config struct {
	RPID          string
	RPName        string
	Origins       []string
	Issuer        string
	Audience      string
	SigningKey    ed25519.PrivateKey
	PreviousKey   ed25519.PublicKey
	ChallengeTTL  time.Duration
	TicketTTL     time.Duration
	TokenTTL      time.Duration
	MaxChallenges int
	Now           func() time.Time
	Logger        *slog.Logger
}

// Server is the public HTTP API.
type Server struct {
	cfg     Config
	cer     *ceremony.Ceremonies
	tokens  *token.Issuer
	log     *slog.Logger
	routes  map[string]route
	origins []string
}

type route struct {
	method  string
	cors    bool // CORS restricted to the allowed origins
	handler func(w http.ResponseWriter, r *http.Request)
}

// New validates the configuration and builds the server.
func New(cfg Config, st store.Store) (*Server, error) {
	if cfg.RPID == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("httpapi: RP ID, issuer and audience are required")
	}
	origins, err := ceremony.NormalizeOrigins(cfg.Origins)
	if err != nil {
		return nil, fmt.Errorf("httpapi: %w", err)
	}
	if cfg.RPName == "" {
		cfg.RPName = cfg.RPID
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = DefaultChallengeTTL
	}
	if cfg.TicketTTL == 0 {
		cfg.TicketTTL = DefaultTicketTTL
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = DefaultTokenTTL
	}
	if cfg.MaxChallenges == 0 {
		cfg.MaxChallenges = DefaultMaxChallenges
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	tokens, err := token.NewIssuer(cfg.Issuer, cfg.Audience, cfg.TokenTTL, cfg.SigningKey, cfg.PreviousKey)
	if err != nil {
		return nil, err
	}
	cer, err := ceremony.New(ceremony.Config{
		RPID: cfg.RPID, RPName: cfg.RPName, Origins: origins,
		ChallengeTTL: cfg.ChallengeTTL, TicketTTL: cfg.TicketTTL, MaxChallenges: cfg.MaxChallenges,
		Now: cfg.Now, Logger: cfg.Logger,
	}, st)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, cer: cer, tokens: tokens, log: cfg.Logger, origins: origins}
	s.routes = map[string]route{
		"/v1/registration/options":   {http.MethodPost, true, s.registrationOptions},
		"/v1/registration/verify":    {http.MethodPost, true, s.registrationVerify},
		"/v1/authentication/options": {http.MethodPost, true, s.authenticationOptions},
		"/v1/authentication/verify":  {http.MethodPost, true, s.authenticationVerify},
		"/v1/jwks.json":              {http.MethodGet, false, s.jwks},
		"/v1/passkey-auth.js":        {http.MethodGet, false, s.helper},
	}
	return s, nil
}

// IssueTicket creates a registration ticket. The host-facing API
// (internal/hostapi) exposes it on the host listener; no public route does.
func (s *Server) IssueTicket(ctx context.Context, account, displayName string) (string, error) {
	return s.cer.IssueTicket(ctx, account, displayName)
}

// ServeHTTP routes a request and writes one log line for it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	s.serve(rec, r)
	s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
		"duration_ms", time.Since(start).Milliseconds())
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.routes[r.URL.Path]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such route")
		return
	}
	if rt.cors {
		w.Header().Add("Vary", "Origin")
		if o := r.Header.Get("Origin"); o != "" && slices.Contains(s.origins, o) {
			w.Header().Set("Access-Control-Allow-Origin", o)
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "POST")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Set("Access-Control-Max-Age", seconds(preflightMaxAge))
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if r.Method != rt.method {
		w.Header().Set("Allow", rt.method)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+rt.method)
		return
	}
	rt.handler(w, r)
}

// Decode applies the body conventions of docs/api.md to another API: the
// host-facing one.
func Decode(w http.ResponseWriter, r *http.Request, v any) ([]byte, bool) { return decode(w, r, v) }

// WriteError writes the error envelope of docs/api.md.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	writeError(w, status, code, message)
}

// decode reads a JSON body strictly into v and returns the raw bytes.
func decode(w http.ResponseWriter, r *http.Request, v any) ([]byte, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", fmt.Sprintf("the body exceeds %d KiB", MaxBodyKiB))
		return nil, false
	} else if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON: "+err.Error())
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "trailing data after the JSON value")
		return nil, false
	}
	return body, true
}

// Shapes of the WebAuthn Level 3 JSON serialisation, to reject unknown fields.
type registrationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON     string   `json:"clientDataJSON"`
		AttestationObject  string   `json:"attestationObject"`
		AuthenticatorData  string   `json:"authenticatorData"`
		PublicKey          string   `json:"publicKey"`
		PublicKeyAlgorithm *int64   `json:"publicKeyAlgorithm"`
		Transports         []string `json:"transports"`
	} `json:"response"`
	AuthenticatorAttachment string          `json:"authenticatorAttachment"`
	ClientExtensionResults  json.RawMessage `json:"clientExtensionResults"`
}

type authenticationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
	AuthenticatorAttachment string          `json:"authenticatorAttachment"`
	ClientExtensionResults  json.RawMessage `json:"clientExtensionResults"`
}

func (s *Server) registrationOptions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
	}
	if _, ok := decode(w, r, &req); !ok {
		return
	}
	opts, err := s.cer.RegistrationOptions(r.Context(), req.Ticket)
	s.reply(w, opts, err, "registration options")
}

func (s *Server) authenticationOptions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}
	if _, ok := decode(w, r, &req); !ok {
		return
	}
	opts, err := s.cer.AuthenticationOptions(r.Context(), req.Nonce)
	s.reply(w, opts, err, "authentication options")
}

func (s *Server) registrationVerify(w http.ResponseWriter, r *http.Request) {
	body, ok := decode(w, r, &registrationResponse{})
	if !ok {
		return
	}
	res, err := s.cer.VerifyRegistration(r.Context(), body)
	s.replyToken(w, res, err, "registration")
}

func (s *Server) authenticationVerify(w http.ResponseWriter, r *http.Request) {
	body, ok := decode(w, r, &authenticationResponse{})
	if !ok {
		return
	}
	res, err := s.cer.VerifyAuthentication(r.Context(), body)
	s.replyToken(w, res, err, "authentication")
}

func (s *Server) replyToken(w http.ResponseWriter, res ceremony.Result, err error, kind string) {
	if err != nil {
		s.reply(w, nil, err, kind)
		return
	}
	tok, err := s.tokens.Sign(res.Account, token.Claims{
		Ceremony: kind, Origin: res.Origin, Cred: b64(res.CredentialID),
		UV: res.UserVerified, BE: res.BackupEligible, BS: res.BackupState,
		Assurance: ceremony.AssurancePasskey, AAGUID: ceremony.UUID(res.AAGUID),
		Nonce: res.Nonce, Fmt: res.AttestationFormat,
	}, s.cfg.Now())
	if err != nil {
		s.reply(w, nil, err, kind)
		return
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	s.reply(w, body, nil, kind)
}

// reply writes a JSON body, or the error envelope for err. The reason of a
// refusal goes to the log only.
func (s *Server) reply(w http.ResponseWriter, body []byte, err error, what string) {
	var refusal *ceremony.Error
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	case errors.As(err, &refusal):
		s.log.Warn("refused", "step", what, "code", refusal.Code, "reason", refusal.Reason)
		status := http.StatusBadRequest
		if refusal.Code == ceremony.CodeUnavailable {
			status = http.StatusServiceUnavailable
			w.Header().Set("Retry-After", seconds(retryAfter))
		}
		writeError(w, status, refusal.Code, messages[refusal.Code])
	default:
		s.log.Error("internal error", "step", what, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal", "unexpected error")
	}
}

var messages = map[string]string{
	ceremony.CodeInvalidRequest:     "the request is invalid",
	ceremony.CodeTicketInvalid:      "the registration ticket is unknown, expired or already used",
	ceremony.CodeChallengeInvalid:   "the challenge is unknown, expired or already used",
	ceremony.CodeCredentialUnknown:  "the credential is unknown",
	ceremony.CodeVerificationFailed: "the ceremony could not be verified",
	ceremony.CodeUnavailable:        "too many ceremonies in progress, retry later",
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age="+seconds(publicMaxAge))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(s.tokens.JWKS())
}

func (s *Server) helper(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age="+seconds(publicMaxAge))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	s.log.Info("helper loaded", "origin", requestingOrigin(r), "version", web.Version)
	_, _ = w.Write(web.Helper)
}

// requestingOrigin is the page origin from Origin, else Referer, reduced to
// scheme://host[:port]; nothing else of the page URL is logged.
func requestingOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return o
	}
	if u, err := url.Parse(r.Header.Get("Referer")); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	_, _ = w.Write(body)
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// seconds formats a duration as the whole seconds of an HTTP header.
func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) }

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | public routes, strict JSON, CORS, errors                      |
