package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

const (
	rpID     = "example.com"
	origin   = "https://example.com"
	issuer   = "https://example.com/auth"
	audience = "example-host"
)

// env is one service instance with its own database, key and clock.
type env struct {
	t       *testing.T
	srv     *httpapi.Server
	ts      *httptest.Server
	key     ed25519.PrivateKey
	dbPath  string
	now     time.Time
	closeDB func()
}

func newEnv(t *testing.T, edit ...func(*httpapi.Config)) *env {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, key: key, dbPath: filepath.Join(t.TempDir(), "passkey-auth.db"), now: time.Unix(1_800_000_000, 0)}

	st, err := sqlite.Open(context.Background(), e.dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	closed := false
	e.closeDB = func() {
		if !closed {
			closed = true
			if err := st.Close(); err != nil {
				t.Errorf("close store: %v", err)
			}
		}
	}

	cfg := httpapi.Config{
		RPID:         rpID,
		RPName:       "Example",
		Origins:      []string{origin},
		Issuer:       issuer,
		Audience:     audience,
		SigningKey:   key,
		ChallengeTTL: 5 * time.Minute,
		TicketTTL:    15 * time.Minute,
		TokenTTL:     60 * time.Second,
		Now:          func() time.Time { return e.now },
	}
	for _, f := range edit {
		f(&cfg)
	}
	e.srv, err = httpapi.New(cfg, st)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	e.ts = httptest.NewServer(e.srv)
	t.Cleanup(func() {
		e.ts.Close()
		e.closeDB()
	})
	return e
}

// advance moves the service clock forward.
func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

// reply is a decoded HTTP response.
type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

// ErrorCode returns error.code of an error envelope, or "".
func (r reply) ErrorCode() string {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &env)
	return env.Error.Code
}

func (e *env) do(method, path string, body []byte, header map[string]string) reply {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := e.ts.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return reply{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (e *env) post(path string, body any) reply {
	e.t.Helper()
	b, ok := body.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(body); err != nil {
			e.t.Fatal(err)
		}
	}
	return e.do(http.MethodPost, path, b, map[string]string{"Origin": origin})
}

// mustOK fails the test unless the reply is 200.
func mustOK(t *testing.T, r reply) []byte {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status %d, body %s", r.Status, r.Body)
	}
	return r.Body
}

// mustFail fails the test unless the reply is an error with this status and code.
func mustFail(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.Status != status || r.ErrorCode() != code {
		t.Fatalf("want %d %s, got %d %s", status, code, r.Status, r.Body)
	}
}

func tokenOf(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Token == "" {
		t.Fatalf("no token in %s", body)
	}
	return v.Token
}

func (e *env) ticket(account, displayName string) string {
	e.t.Helper()
	tk, err := e.srv.IssueTicket(context.Background(), account, displayName)
	if err != nil {
		e.t.Fatalf("issue ticket: %v", err)
	}
	return tk
}

// registrationOptions starts a registration for a new ticket of account.
func (e *env) registrationOptions(account string) []byte {
	e.t.Helper()
	return mustOK(e.t, e.post("/v1/registration/options", map[string]string{"ticket": e.ticket(account, account+" display")}))
}

// register runs a whole honest registration and returns the token.
func (e *env) register(a *testauthn.Authenticator, account string) string {
	e.t.Helper()
	resp, err := a.Register(e.registrationOptions(account), testauthn.Overrides{})
	if err != nil {
		e.t.Fatal(err)
	}
	return tokenOf(e.t, mustOK(e.t, e.post("/v1/registration/verify", resp)))
}

func newNonce() string { return testauthn.B64(random(32)) }

func (e *env) authenticationOptions(nonce string) []byte {
	e.t.Helper()
	return mustOK(e.t, e.post("/v1/authentication/options", map[string]string{"nonce": nonce}))
}

// assertion signs an assertion with overrides and posts it.
func (e *env) assertion(a *testauthn.Authenticator, nonce string, o testauthn.Overrides) reply {
	e.t.Helper()
	resp, err := a.Authenticate(e.authenticationOptions(nonce), o)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.post("/v1/authentication/verify", resp)
}

// custom holds the service-specific claims of a result token.
type custom struct {
	Ceremony  string `json:"ceremony"`
	Origin    string `json:"origin"`
	Cred      string `json:"cred"`
	UV        bool   `json:"uv"`
	BE        bool   `json:"be"`
	BS        bool   `json:"bs"`
	Nonce     string `json:"nonce,omitempty"`
	Assurance string `json:"assurance"`
	AAGUID    string `json:"aaguid,omitempty"`
	Fmt       string `json:"fmt,omitempty"`
}

// claims is the payload of a result token.
type claims struct {
	jwt.Claims
	custom
}

// verifyToken checks a result token with nothing but the JWKS published by
// the service, as a host would, and returns its claims.
func (e *env) verifyToken(token string) (claims, error) {
	e.t.Helper()
	r := e.do(http.MethodGet, "/v1/jwks.json", nil, nil)
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(mustOK(e.t, r), &set); err != nil {
		e.t.Fatalf("jwks: %v", err)
	}
	return verifyWith(set, token)
}

func verifyWith(set jose.JSONWebKeySet, token string) (claims, error) {
	var c claims
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return c, err
	}
	if len(tok.Headers) != 1 {
		return c, errStr("want one signature")
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "passkey-result+jwt" {
		return c, errStr("typ is " + typ)
	}
	keys := set.Key(h.KeyID)
	if len(keys) != 1 {
		return c, errStr("kid not in JWKS: " + h.KeyID)
	}
	if err := tok.Claims(keys[0].Key, &c); err != nil {
		return c, err
	}
	return c, nil
}

// checkStandardClaims verifies iss, aud and lifetime at the service's clock.
func (e *env) checkStandardClaims(c claims) {
	e.t.Helper()
	err := c.Claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{audience}, Time: e.now}, 0)
	if err != nil {
		e.t.Errorf("standard claims: %v", err)
	}
	if c.Expiry == nil || c.IssuedAt == nil || c.Expiry.Time().Sub(c.IssuedAt.Time()) != 60*time.Second {
		e.t.Errorf("lifetime: iat %v exp %v, want 60s", c.IssuedAt, c.Expiry)
	}
	if c.ID == "" {
		e.t.Error("jti missing")
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func ptr[T any](v T) *T { return &v }

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | test service, HTTP and JWKS-only token helpers                |
