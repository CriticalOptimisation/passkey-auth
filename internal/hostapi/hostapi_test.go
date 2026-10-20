package hostapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/hostapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
	"github.com/CriticalOptimisation/passkey-auth/internal/testhost"
)

const (
	rpID      = "example.com"
	origin    = "https://example.com"
	issuer    = "https://example.com/auth" // PA_ISSUER: the aud of host tokens
	audience  = "example-host"
	ticketTTL = 15 * time.Minute
)

// env is one service, its public and host listeners on one database, and the
// host with its DID document.
type env struct {
	t      *testing.T
	now    time.Time
	host   *testhost.Host
	public *httptest.Server
	hostTS *httptest.Server
}

func newEnv(t *testing.T) *env { t.Helper(); return newLoggedEnv(t, nil) }

// newLoggedEnv is newEnv, with the host API and the resolver writing to log.
func newLoggedEnv(t *testing.T, log *slog.Logger) *env {
	t.Helper()
	e := &env{t: t, now: time.Unix(1_800_000_000, 0), host: testhost.New(t)}
	now := func() time.Time { return e.now }

	st, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "passkey-auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub, err := httpapi.New(httpapi.Config{
		RPID: rpID, RPName: "Example", Origins: []string{origin}, Issuer: issuer, Audience: audience,
		SigningKey: key, TicketTTL: ticketTTL, Now: now,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := didweb.New(didweb.Config{DID: e.host.DID, Client: e.host.Client(), Now: now, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	h, err := hostapi.New(hostapi.Config{
		HostDID: e.host.DID, Audience: issuer, Keys: keys, Tickets: pub, TicketTTL: ticketTTL, Now: now, Logger: log,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	e.public = httptest.NewServer(pub)
	e.hostTS = httptest.NewServer(h)
	t.Cleanup(func() { e.public.Close(); e.hostTS.Close() })
	return e
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

// token is a valid host token at the service's clock, edited if asked.
func (e *env) token(edit ...func(*testhost.Token)) string {
	return e.host.Token(testhost.Main, issuer, e.now, edit...)
}

type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r reply) code() string {
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &v)
	return v.Error.Code
}

func send(t *testing.T, method, url string, body []byte, header map[string]string) reply {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header, b}
}

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// call sends a host request with a valid token.
func (e *env) call(method, path string, body any) reply {
	e.t.Helper()
	var b []byte
	if body != nil {
		b = jsonBody(e.t, body)
	}
	return send(e.t, method, e.hostTS.URL+path, b, map[string]string{"Authorization": "Bearer " + e.token()})
}

// ticket asks the host API for a ticket.
func (e *env) ticket(account, displayName string) string {
	e.t.Helper()
	r := e.call(http.MethodPost, "/v1/registration-tickets", map[string]string{"account": account, "displayName": displayName})
	if r.Status != http.StatusCreated {
		e.t.Fatalf("ticket: %d %s", r.Status, r.Body)
	}
	var v struct {
		Ticket    string `json:"ticket"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(r.Body, &v); err != nil || v.Ticket == "" {
		e.t.Fatalf("ticket body %s", r.Body)
	}
	return v.Ticket
}

func (e *env) publicPost(path string, body []byte) reply {
	e.t.Helper()
	return send(e.t, http.MethodPost, e.public.URL+path, body, map[string]string{"Origin": origin})
}

// register runs a whole registration with a ticket from the host API and
// returns the credential ID as the list gives it.
func (e *env) register(a *testauthn.Authenticator, account string) string {
	e.t.Helper()
	opts := e.publicPost("/v1/registration/options", jsonBody(e.t, map[string]string{"ticket": e.ticket(account, account+" display")}))
	if opts.Status != http.StatusOK {
		e.t.Fatalf("registration options: %d %s", opts.Status, opts.Body)
	}
	resp, err := a.Register(opts.Body, testauthn.Overrides{})
	if err != nil {
		e.t.Fatal(err)
	}
	if r := e.publicPost("/v1/registration/verify", resp); r.Status != http.StatusOK {
		e.t.Fatalf("registration verify: %d %s", r.Status, r.Body)
	}
	return testauthn.B64(a.Latest().ID)
}

// authenticate runs an authentication and returns the reply of verify.
func (e *env) authenticate(a *testauthn.Authenticator) reply {
	e.t.Helper()
	nonce := testauthn.B64(bytes.Repeat([]byte{7}, 32))
	opts := e.publicPost("/v1/authentication/options", jsonBody(e.t, map[string]string{"nonce": nonce}))
	if opts.Status != http.StatusOK {
		e.t.Fatalf("authentication options: %d %s", opts.Status, opts.Body)
	}
	resp, err := a.Authenticate(opts.Body, testauthn.Overrides{})
	if err != nil {
		e.t.Fatal(err)
	}
	return e.publicPost("/v1/authentication/verify", resp)
}

type listed struct {
	ID         string   `json:"id"`
	CreatedAt  string   `json:"createdAt"`
	LastUsedAt string   `json:"lastUsedAt"`
	AAGUID     string   `json:"aaguid"`
	BE         *bool    `json:"be"`
	BS         *bool    `json:"bs"`
	Fmt        string   `json:"fmt"`
	Transports []string `json:"transports"`
}

func (e *env) list(escapedAccount string) []listed {
	e.t.Helper()
	r := e.call(http.MethodGet, "/v1/accounts/"+escapedAccount+"/credentials", nil)
	if r.Status != http.StatusOK {
		e.t.Fatalf("list: %d %s", r.Status, r.Body)
	}
	var out []listed
	if err := json.Unmarshal(r.Body, &out); err != nil || out == nil {
		e.t.Fatalf("list body %s: %v", r.Body, err)
	}
	return out
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// --- Registration tickets ----------------------------------------------------

func TestTicketIsCreated(t *testing.T) {
	e := newEnv(t)
	r := e.call(http.MethodPost, "/v1/registration-tickets", map[string]string{"account": "account-1", "displayName": "Library card 1234"})
	if r.Status != http.StatusCreated {
		t.Fatalf("status %d, body %s", r.Status, r.Body)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var v map[string]string
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	if v["ticket"] == "" || v["expiresAt"] != rfc3339(e.now.Add(ticketTTL)) || len(v) != 2 {
		t.Fatalf("body %s, want ticket and expiresAt %s", r.Body, rfc3339(e.now.Add(ticketTTL)))
	}
}

// A ticket from the host API starts one registration, once.
func TestTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	tk := jsonBody(t, map[string]string{"ticket": e.ticket("account-1", "One")})
	if r := e.publicPost("/v1/registration/options", tk); r.Status != http.StatusOK {
		t.Fatalf("first use: %d %s", r.Status, r.Body)
	}
	if r := e.publicPost("/v1/registration/options", tk); r.Status != http.StatusBadRequest || r.code() != "ticket_invalid" {
		t.Fatalf("second use: %d %s", r.Status, r.Body)
	}
}

func TestTicketExpires(t *testing.T) {
	e := newEnv(t)
	tk := jsonBody(t, map[string]string{"ticket": e.ticket("account-1", "One")})
	e.advance(ticketTTL + time.Second)
	if r := e.publicPost("/v1/registration/options", tk); r.Status != http.StatusBadRequest || r.code() != "ticket_invalid" {
		t.Fatalf("expired ticket: %d %s", r.Status, r.Body)
	}
}

func TestTicketRegistersAPasskey(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	id := e.register(a, "account-1")
	if r := e.authenticate(a); r.Status != http.StatusOK {
		t.Fatalf("authentication: %d %s", r.Status, r.Body)
	}
	if got := e.list("account-1"); len(got) != 1 || got[0].ID != id {
		t.Fatalf("list = %+v, want %s", got, id)
	}
}

func TestTicketRequestIsChecked(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("a", 257)
	for name, body := range map[string]string{
		"no account":         `{"displayName":"A"}`,
		"empty account":      `{"account":"","displayName":"A"}`,
		"no display name":    `{"account":"a"}`,
		"account too long":   `{"account":"` + long + `","displayName":"A"}`,
		"display too long":   `{"account":"a","displayName":"` + long + `"}`,
		"unknown field":      `{"account":"a","displayName":"A","role":"admin"}`,
		"malformed JSON":     `{"account":`,
		"trailing JSON data": `{"account":"a","displayName":"A"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(body), map[string]string{"Authorization": "Bearer " + e.token()})
			if r.Status != http.StatusBadRequest || r.code() != "invalid_request" {
				t.Fatalf("%d %s, want 400 invalid_request", r.Status, r.Body)
			}
		})
	}
}

// --- Listing ----------------------------------------------------------------

func TestListGivesEachCredential(t *testing.T) {
	e := newEnv(t)
	roaming := testauthn.New(testauthn.Roaming, origin)
	platform := testauthn.New(testauthn.Platform, origin)
	created := e.now
	idR := e.register(roaming, "account-1")
	e.advance(time.Minute)
	idP := e.register(platform, "account-1")
	e.advance(time.Hour)
	if r := e.authenticate(roaming); r.Status != http.StatusOK {
		t.Fatalf("authentication: %d %s", r.Status, r.Body)
	}

	got := e.list("account-1")
	if len(got) != 2 || got[0].ID != idR || got[1].ID != idP {
		t.Fatalf("list = %+v, want %s then %s", got, idR, idP)
	}
	r, p := got[0], got[1]
	if r.CreatedAt != rfc3339(created) || r.LastUsedAt != rfc3339(e.now) {
		t.Errorf("roaming times: %s / %s", r.CreatedAt, r.LastUsedAt)
	}
	if r.AAGUID != "01234567-89ab-cdef-0123-456789abcdef" || r.BE == nil || *r.BE || r.BS == nil || *r.BS ||
		r.Fmt != "none" || strings.Join(r.Transports, ",") != "usb" {
		t.Errorf("roaming: %+v", r)
	}
	if p.CreatedAt != rfc3339(created.Add(time.Minute)) || p.LastUsedAt != p.CreatedAt {
		t.Errorf("platform times: %s / %s", p.CreatedAt, p.LastUsedAt)
	}
	if p.AAGUID != "fedcba98-7654-3210-fedc-ba9876543210" || p.BE == nil || !*p.BE || p.BS == nil || !*p.BS ||
		strings.Join(p.Transports, ",") != "internal,hybrid" {
		t.Errorf("platform: %+v", p)
	}
}

func TestListOfAnUnknownAccountIsEmpty(t *testing.T) {
	e := newEnv(t)
	r := e.call(http.MethodGet, "/v1/accounts/nobody/credentials", nil)
	if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) != "[]" {
		t.Fatalf("%d %s, want 200 []", r.Status, r.Body)
	}
}

// An account reference with "/" travels percent-encoded, as one segment.
func TestAccountWithASlash(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	id := e.register(a, "org/alice")
	if got := e.list("org%2Falice"); len(got) != 1 || got[0].ID != id {
		t.Fatalf("list = %+v", got)
	}
	if got := e.list("org%2Fbob"); len(got) != 0 {
		t.Fatalf("org/bob: %+v", got)
	}
	if r := e.call(http.MethodGet, "/v1/accounts/org/alice/credentials", nil); r.Status != http.StatusNotFound {
		t.Fatalf("unescaped slash: %d %s, want 404", r.Status, r.Body)
	}
	if r := e.call(http.MethodDelete, "/v1/accounts/org%2Falice/credentials/"+id, nil); r.Status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
}

// --- Revocation -------------------------------------------------------------

func TestRevokedCredentialCannotAuthenticate(t *testing.T) {
	e := newEnv(t)
	keep := testauthn.New(testauthn.Platform, origin)
	lose := testauthn.New(testauthn.Roaming, origin)
	e.register(keep, "account-1")
	id := e.register(lose, "account-1")

	r := e.call(http.MethodDelete, "/v1/accounts/account-1/credentials/"+id, nil)
	if r.Status != http.StatusNoContent || len(r.Body) != 0 {
		t.Fatalf("delete: %d %q, want 204 with no body", r.Status, r.Body)
	}
	if r := e.authenticate(lose); r.Status != http.StatusBadRequest || r.code() != "credential_unknown" {
		t.Fatalf("revoked credential: %d %s, want credential_unknown", r.Status, r.Body)
	}
	if r := e.authenticate(keep); r.Status != http.StatusOK {
		t.Fatalf("other credential: %d %s", r.Status, r.Body)
	}
	if got := e.list("account-1"); len(got) != 1 || got[0].ID == id {
		t.Fatalf("list after revoke: %+v", got)
	}
	if r := e.call(http.MethodDelete, "/v1/accounts/account-1/credentials/"+id, nil); r.Status != http.StatusNotFound || r.code() != "not_found" {
		t.Fatalf("second delete: %d %s, want 404", r.Status, r.Body)
	}
}

// Revoking the last credential deletes the account: user handle and open
// tickets. A new registration starts with a new user handle.
func TestRevokingTheLastCredentialDeletesTheAccount(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	id := e.register(a, "account-1")
	oldHandle := a.Latest().UserHandle
	open := jsonBody(t, map[string]string{"ticket": e.ticket("account-1", "Pending")})

	if r := e.call(http.MethodDelete, "/v1/accounts/account-1/credentials/"+id, nil); r.Status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
	if r := e.publicPost("/v1/registration/options", open); r.Status != http.StatusBadRequest || r.code() != "ticket_invalid" {
		t.Fatalf("open ticket after the account's deletion: %d %s", r.Status, r.Body)
	}
	b := testauthn.New(testauthn.Roaming, origin)
	e.register(b, "account-1")
	if bytes.Equal(b.Latest().UserHandle, oldHandle) {
		t.Fatal("the account kept its user handle")
	}
}

func TestRevokeWhatIsNotTheAccounts(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	b := testauthn.New(testauthn.Roaming, origin)
	e.register(a, "account-a")
	idB := e.register(b, "account-b")
	for name, path := range map[string]string{
		"another account's credential": "/v1/accounts/account-a/credentials/" + idB,
		"unknown credential":           "/v1/accounts/account-a/credentials/AAAA",
		"unknown account":              "/v1/accounts/nobody/credentials/" + idB,
	} {
		t.Run(name, func(t *testing.T) {
			if r := e.call(http.MethodDelete, path, nil); r.Status != http.StatusNotFound || r.code() != "not_found" {
				t.Fatalf("%d %s, want 404 not_found", r.Status, r.Body)
			}
		})
	}
	if r := e.authenticate(b); r.Status != http.StatusOK {
		t.Fatalf("account-b's credential after refused deletes: %d %s", r.Status, r.Body)
	}
}

// --- Host authentication ----------------------------------------------------

// Every host route needs a valid token.
func TestEveryRouteNeedsAHostToken(t *testing.T) {
	e := newEnv(t)
	routes := []struct {
		method, path string
		withToken    int // status with a valid token
	}{
		{http.MethodPost, "/v1/registration-tickets", http.StatusCreated},
		{http.MethodGet, "/v1/accounts/a/credentials", http.StatusOK},
		{http.MethodDelete, "/v1/accounts/a/credentials/AAAA", http.StatusNotFound}, // reached: no such credential
	}
	for _, rt := range routes {
		t.Run(rt.method, func(t *testing.T) {
			r := send(t, rt.method, e.hostTS.URL+rt.path, []byte(`{"account":"a","displayName":"A"}`), nil)
			if r.Status != http.StatusUnauthorized || r.code() != hostapi.CodeHostUnauthorized {
				t.Fatalf("%d %s, want 401 host_unauthorized", r.Status, r.Body)
			}
			if !strings.HasPrefix(r.Header.Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("WWW-Authenticate = %q", r.Header.Get("WWW-Authenticate"))
			}
			r = send(t, rt.method, e.hostTS.URL+rt.path, []byte(`{"account":"a","displayName":"A"}`), map[string]string{"Authorization": "Bearer " + e.token()})
			if r.Status != rt.withToken {
				t.Fatalf("with a valid token: %d %s, want %d", r.Status, r.Body, rt.withToken)
			}
		})
	}
}

// Each rule of the host token, broken alone, is refused with 401.
func TestBrokenHostTokens(t *testing.T) {
	e := newEnv(t)
	e.host.AddKey("signer", testhost.AssertionMethod)
	e.host.AddKey("revoked", testhost.Authentication)
	e.host.Revoke("revoked")
	e.host.AddKey("other", testhost.Authentication)
	header := func(k string, v any) func(*testhost.Token) {
		return func(tk *testhost.Token) {
			if v == nil {
				delete(tk.Header, k)
			} else {
				tk.Header[k] = v
			}
		}
	}
	claim := func(k string, v any) func(*testhost.Token) {
		return func(tk *testhost.Token) {
			if v == nil {
				delete(tk.Claims, k)
			} else {
				tk.Claims[k] = v
			}
		}
	}
	now := e.now.Unix()
	signed := map[string]func(*testhost.Token){
		"typ missing":            header("typ", nil),
		"typ of a result token":  header("typ", "passkey-result+jwt"),
		"alg EdDSA":              header("alg", "EdDSA"),
		"alg ES384":              header("alg", "ES384"),
		"alg HS256":              header("alg", "HS256"),
		"kid missing":            header("kid", nil),
		"kid unknown":            header("kid", e.host.DID+"#unknown"),
		"kid of another DID":     header("kid", "did:web:elsewhere.example#"+e.host.Fragment(testhost.Main)),
		"kid under assertion":    func(tk *testhost.Token) { tk.Header["kid"], tk.SignWith = e.host.KID("signer"), "signer" },
		"kid revoked":            func(tk *testhost.Token) { tk.Header["kid"], tk.SignWith = e.host.KID("revoked"), "revoked" },
		"signed by another key":  func(tk *testhost.Token) { tk.SignWith = "other" },
		"iss missing":            claim("iss", nil),
		"iss another DID":        claim("iss", "did:web:elsewhere.example"),
		"aud missing":            claim("aud", nil),
		"aud the result tokens'": claim("aud", audience),
		"aud another service":    claim("aud", "https://elsewhere.example/auth"),
		"iat missing":            claim("iat", nil),
		"exp missing":            claim("exp", nil),
		"expired":                func(tk *testhost.Token) { tk.Claims["iat"], tk.Claims["exp"] = now-70, now-6 },
		"lifetime over 60 s":     claim("exp", now+61),
		"iat in the future":      func(tk *testhost.Token) { tk.Claims["iat"], tk.Claims["exp"] = now+10, now+40 },
	}
	cases := map[string]string{}
	for name, edit := range signed {
		cases[name] = e.token(edit)
	}
	good := e.token()
	parts := strings.Split(good, ".")
	cases["alg none, unsigned"] = testhost.B64JSON(map[string]any{"alg": "none", "typ": "passkey-host+jwt", "kid": e.host.KID(testhost.Main)}) + "." + parts[1] + "."
	cases["payload altered"] = parts[0] + "." + testhost.B64JSON(map[string]any{"iss": e.host.DID, "aud": issuer, "iat": now, "exp": now + 30}) + "." + parts[2]
	cases["signature cut"] = parts[0] + "." + parts[1] + "."
	cases["not a JWT"] = "abc"
	cases["JWS JSON serialisation"] = `{"payload":"` + parts[1] + `"}`

	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`), map[string]string{"Authorization": "Bearer " + tok})
			if r.Status != http.StatusUnauthorized || r.code() != hostapi.CodeHostUnauthorized {
				t.Fatalf("%d %s, want 401 host_unauthorized", r.Status, r.Body)
			}
		})
	}

	for name, value := range map[string]string{"Basic scheme": "Basic " + good, "no scheme": good, "empty bearer": "Bearer "} {
		t.Run(name, func(t *testing.T) {
			r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`), map[string]string{"Authorization": value})
			if r.Status != http.StatusUnauthorized || r.code() != hostapi.CodeHostUnauthorized {
				t.Fatalf("%d %s, want 401 host_unauthorized", r.Status, r.Body)
			}
		})
	}
}

// Tokens within the limits are accepted: 5 s of skew, 60 s of lifetime.
func TestHostTokenLimits(t *testing.T) {
	e := newEnv(t)
	now := e.now.Unix()
	for name, edit := range map[string]func(*testhost.Token){
		"lifetime of exactly 60 s":    func(tk *testhost.Token) { tk.Claims["exp"] = now + 60 },
		"iat 5 s ahead":               func(tk *testhost.Token) { tk.Claims["iat"], tk.Claims["exp"] = now+5, now+30 },
		"expired less than 5 s ago":   func(tk *testhost.Token) { tk.Claims["iat"], tk.Claims["exp"] = now-60, now-4 },
		"aud as an array of one item": func(tk *testhost.Token) { tk.Claims["aud"] = []string{issuer} },
	} {
		t.Run(name, func(t *testing.T) {
			r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`),
				map[string]string{"Authorization": "Bearer " + e.token(edit)})
			if r.Status != http.StatusCreated {
				t.Fatalf("%d %s, want 201", r.Status, r.Body)
			}
		})
	}
}

// A key added to the DID document works at once.
func TestRotatedHostKeyWorksAtOnce(t *testing.T) {
	e := newEnv(t)
	e.ticket("a", "A") // the document is now kept
	e.host.AddKey("next", testhost.Authentication)
	tok := e.host.Token("next", issuer, e.now)
	r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`), map[string]string{"Authorization": "Bearer " + tok})
	if r.Status != http.StatusCreated {
		t.Fatalf("new key: %d %s", r.Status, r.Body)
	}
}

// Until the DID document has been fetched once, host routes answer 503.
func TestHostDocumentUnavailable(t *testing.T) {
	e := newEnv(t)
	e.host.SetStatus(http.StatusBadGateway)
	r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`), map[string]string{"Authorization": "Bearer " + e.token()})
	if r.Status != http.StatusServiceUnavailable || r.code() != "unavailable" {
		t.Fatalf("%d %s, want 503 unavailable", r.Status, r.Body)
	}
}

// The conventions of the public routes hold on the host routes.
func TestHostRouteConventions(t *testing.T) {
	e := newEnv(t)
	auth := map[string]string{"Authorization": "Bearer " + e.token()}
	if r := send(t, http.MethodGet, e.hostTS.URL+"/v1/registration-tickets", nil, auth); r.Status != http.StatusMethodNotAllowed || r.code() != "method_not_allowed" {
		t.Errorf("wrong method: %d %s", r.Status, r.Body)
	}
	if r := send(t, http.MethodGet, e.hostTS.URL+"/v1/nothing", nil, auth); r.Status != http.StatusNotFound || r.code() != "not_found" {
		t.Errorf("unknown route: %d %s", r.Status, r.Body)
	}
	h := map[string]string{"Authorization": auth["Authorization"], "Content-Type": "text/plain"}
	if r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`), h); r.Status != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d %s", r.Status, r.Body)
	}
	big := []byte(`{"account":"a","displayName":"` + strings.Repeat("A", 65*1024) + `"}`)
	if r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", big, auth); r.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: %d %s", r.Status, r.Body)
	}
	// The public routes are not served here.
	if r := send(t, http.MethodPost, e.hostTS.URL+"/v1/authentication/options", []byte(`{"nonce":"x"}`), auth); r.Status != http.StatusNotFound {
		t.Errorf("public route on the host listener: %d %s", r.Status, r.Body)
	}
}
