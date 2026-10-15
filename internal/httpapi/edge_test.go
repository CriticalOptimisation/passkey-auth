package httpapi_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

func TestChallengeCap(t *testing.T) {
	e := newEnv(t, func(c *httpapi.Config) { c.MaxChallenges = 2 })
	e.authenticationOptions(newNonce())
	e.authenticationOptions(newNonce())
	r := e.post("/v1/authentication/options", map[string]string{"nonce": newNonce()})
	mustFail(t, r, http.StatusServiceUnavailable, "unavailable")
	if r.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	mustFail(t, e.post("/v1/registration/options", map[string]string{"ticket": e.ticket("a", "A")}), http.StatusServiceUnavailable, "unavailable")

	// Expired challenges no longer count, and are purged.
	e.advance(5*time.Minute + time.Second)
	e.authenticationOptions(newNonce())
}

// Of two concurrent posts of the same response, exactly one succeeds.
func TestConcurrentReplay(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	e.register(a, "account-1")
	assertion, err := a.Authenticate(e.authenticationOptions(newNonce()), testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- e.post("/v1/authentication/verify", assertion).Status
		}()
	}
	wg.Wait()
	close(statuses)
	ok := 0
	for s := range statuses {
		if s == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d successes, want 1", ok)
	}
}

// A credential presented with another account's user handle is unknown.
func TestCredentialOfAnotherUser(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	b := testauthn.New(testauthn.Roaming, origin)
	e.register(a, "account-1")
	e.register(b, "account-2")
	a.Latest().UserHandle = b.Latest().UserHandle
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{}), http.StatusBadRequest, "credential_unknown")
}

func TestIssueTicketValidation(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{{"", "A"}, {"a", ""}, {strings.Repeat("a", 257), "A"}} {
		if _, err := e.srv.IssueTicket(t.Context(), c[0], c[1]); err == nil {
			t.Errorf("ticket issued for %q / %q", c[0], c[1])
		}
	}
}

// Logs carry no IP address, account reference, ticket, challenge or token.
func TestLogsCarryNoSecretOrIdentifier(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	e := newEnv(t, func(c *httpapi.Config) {
		c.Logger = slog.New(slog.NewJSONHandler(&lockedWriter{w: &buf, mu: &mu}, nil))
	})
	a := testauthn.New(testauthn.Roaming, origin)
	ticket := e.ticket("account-secret-ref", "Display")
	opts := mustOK(t, e.post("/v1/registration/options", map[string]string{"ticket": ticket}))
	resp, _ := a.Register(opts, testauthn.Overrides{})
	token := tokenOf(t, mustOK(t, e.post("/v1/registration/verify", resp)))
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Origin: "https://evil.example"}), http.StatusBadRequest, "verification_failed")
	e.do(http.MethodGet, "/v1/passkey-auth.js", nil, map[string]string{"Referer": "https://site.example/page?user=42"})

	mu.Lock()
	logs := buf.String()
	mu.Unlock()
	for _, secret := range []string{"account-secret-ref", ticket, token, "127.0.0.1", "user=42", "/page"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
	for _, want := range []string{`"msg":"refused"`, "https://evil.example", `"msg":"helper loaded"`, `"origin":"https://site.example"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %s", want)
		}
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
