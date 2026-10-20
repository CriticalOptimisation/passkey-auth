package hostapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
	"github.com/CriticalOptimisation/passkey-auth/internal/testhost"
)

// A registration started before the account's deletion cannot finish
// after it: the account does not come back.
func TestRegistrationFinishedAfterTheAccountsDeletion(t *testing.T) {
	e := newEnv(t)
	first := testauthn.New(testauthn.Roaming, origin)
	id := e.register(first, "account-1")

	opts := e.publicPost("/v1/registration/options", jsonBody(t, map[string]string{"ticket": e.ticket("account-1", "Second")}))
	if opts.Status != http.StatusOK {
		t.Fatalf("registration options: %d %s", opts.Status, opts.Body)
	}
	second := testauthn.New(testauthn.Platform, origin)
	resp, err := second.Register(opts.Body, testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.call(http.MethodDelete, "/v1/accounts/account-1/credentials/"+id, nil); r.Status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
	if r := e.publicPost("/v1/registration/verify", resp); r.Status != http.StatusBadRequest || r.code() != "challenge_invalid" {
		t.Fatalf("registration after the deletion: %d %s, want 400 challenge_invalid", r.Status, r.Body)
	}
	if got := e.list("account-1"); len(got) != 0 {
		t.Fatalf("the account came back: %+v", got)
	}
}

// Two concurrent revocations of an account's last two credentials both
// succeed, and the account is gone.
func TestConcurrentRevocationOfTheLastTwoCredentials(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	b := testauthn.New(testauthn.Platform, origin)
	ids := []string{e.register(a, "account-1"), e.register(b, "account-1")}
	oldHandle := b.Latest().UserHandle
	tokens := []string{e.token(), e.token()}

	var wg sync.WaitGroup
	statuses := make([]int, len(ids))
	for i, id := range ids {
		wg.Go(func() {
			req, _ := http.NewRequest(http.MethodDelete, e.hostTS.URL+"/v1/accounts/account-1/credentials/"+id, nil)
			req.Header.Set("Authorization", "Bearer "+tokens[i])
			if res, err := http.DefaultClient.Do(req); err == nil {
				statuses[i] = res.StatusCode
				res.Body.Close()
			}
		})
	}
	wg.Wait()
	for i, s := range statuses {
		if s != http.StatusNoContent {
			t.Errorf("delete %d: %d, want 204", i, s)
		}
	}
	if got := e.list("account-1"); len(got) != 0 {
		t.Fatalf("list: %+v", got)
	}
	c := testauthn.New(testauthn.Roaming, origin)
	e.register(c, "account-1")
	if bytes.Equal(c.Latest().UserHandle, oldHandle) {
		t.Fatal("the account kept its user handle")
	}
}

// Path segments that name no account or no credential answer 404.
func TestMalformedPathSegments(t *testing.T) {
	e := newEnv(t)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/v1/accounts//credentials"},
		{http.MethodGet, "/v1/accounts/a/credentials/"},
		{http.MethodPost, "/v1/registration-tickets/"},
		{http.MethodDelete, "/v1/accounts/a/credentials/not*base64"},
		{http.MethodDelete, "/v1/accounts/a/credentials/AAAA%3D"},
		{http.MethodDelete, "/v1/accounts/a/credentials/AAAA/x"},
	} {
		r := e.call(rt.method, rt.path, nil)
		if r.Status != http.StatusNotFound || r.code() != "not_found" {
			t.Errorf("%s %s: %d %s, want 404 not_found", rt.method, rt.path, r.Status, r.Body)
		}
	}
}

// The limits of a ticket request are inclusive: 256 bytes pass.
func TestTicketAtTheLimits(t *testing.T) {
	e := newEnv(t)
	max := strings.Repeat("é", 128) // 256 bytes
	r := e.call(http.MethodPost, "/v1/registration-tickets", map[string]string{"account": max, "displayName": max})
	if r.Status != http.StatusCreated {
		t.Fatalf("%d %s, want 201", r.Status, r.Body)
	}
}

// The auth scheme is case-insensitive (RFC 9110); the 405 names the method.
func TestHTTPDetails(t *testing.T) {
	e := newEnv(t)
	r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`),
		map[string]string{"Authorization": "bearer " + e.token()})
	if r.Status != http.StatusCreated {
		t.Errorf("lower-case scheme: %d %s", r.Status, r.Body)
	}
	r = e.call(http.MethodDelete, "/v1/registration-tickets", nil)
	if r.Status != http.StatusMethodNotAllowed || r.Header.Get("Allow") != http.MethodPost {
		t.Errorf("405: %d, Allow %q", r.Status, r.Header.Get("Allow"))
	}
	r = e.call(http.MethodGet, "/v1/accounts/nobody/credentials", nil)
	if r.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Errorf("list headers: %v", r.Header)
	}
}

// A kid that does not name a key of the host's DID is refused before any
// fetch: forged tokens cannot make the service fetch documents.
func TestForeignKidFetchesNothing(t *testing.T) {
	e := newEnv(t)
	tok := e.token(func(tk *testhost.Token) { tk.Header["kid"] = "did:web:elsewhere.example#k" })
	r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", []byte(`{"account":"a","displayName":"A"}`),
		map[string]string{"Authorization": "Bearer " + tok})
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("%d %s, want 401", r.Status, r.Body)
	}
	if n := e.host.Fetches(); n != 0 {
		t.Fatalf("%d fetches, want 0", n)
	}
}

// Once the document can be fetched again, after RefetchInterval, the host
// routes work.
func TestHostDocumentBecomesAvailable(t *testing.T) {
	e := newEnv(t)
	e.host.SetStatus(http.StatusBadGateway)
	body := []byte(`{"account":"a","displayName":"A"}`)
	if r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", body, map[string]string{"Authorization": "Bearer " + e.token()}); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("%d %s, want 503", r.Status, r.Body)
	}
	e.host.SetStatus(0)
	e.advance(didweb.RefetchInterval + time.Second)
	if r := send(t, http.MethodPost, e.hostTS.URL+"/v1/registration-tickets", body, map[string]string{"Authorization": "Bearer " + e.token()}); r.Status != http.StatusCreated {
		t.Fatalf("%d %s, want 201", r.Status, r.Body)
	}
}

// The log carries no account reference, display name, ticket or token
// (docs/configuration.md, Logs), whatever the outcome of the request.
func TestLogsCarryNoPersonalDataOrSecret(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	log := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}), nil))
	e := newLoggedEnv(t, log)
	const account, display = "org/secret-account-ref", "Secret Display Name"
	a := testauthn.New(testauthn.Roaming, origin)
	opts := e.publicPost("/v1/registration/options", jsonBody(t, map[string]string{"ticket": e.ticket(account, display)}))
	resp, err := a.Register(opts.Body, testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.publicPost("/v1/registration/verify", resp); r.Status != http.StatusOK {
		t.Fatalf("registration: %d %s", r.Status, r.Body)
	}
	escaped := "org%2Fsecret-account-ref"
	id := testauthn.B64(a.Latest().ID)
	ticket := e.ticket(account, display)
	e.list(escaped)
	e.call(http.MethodDelete, "/v1/accounts/"+escaped+"/credentials/AAAA", nil)
	e.call(http.MethodDelete, "/v1/accounts/"+escaped+"/credentials/"+id, nil)
	e.call(http.MethodPost, "/v1/registration-tickets", map[string]string{"account": account})
	badToken := e.token(func(tk *testhost.Token) { tk.Claims["aud"] = "elsewhere" })
	send(t, http.MethodGet, e.hostTS.URL+"/v1/accounts/"+escaped+"/credentials", nil, map[string]string{"Authorization": "Bearer " + badToken})

	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	for name, secret := range map[string]string{
		"account": "secret-account-ref", "display name": display, "ticket": ticket,
		"bad token signature": badToken[strings.LastIndex(badToken, ".")+1:],
		"bad token payload":   strings.Split(badToken, ".")[1],
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log holds the %s", name)
		}
	}
	for _, want := range []string{`"route":"/v1/accounts/{account}/credentials/{id}"`, `"route":"/v1/registration-tickets"`, `"host refused"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("the log lacks %s", want)
		}
	}
	// Every line is JSON.
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("not JSON: %s", line)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

var _ io.Writer = writerFunc(nil)
