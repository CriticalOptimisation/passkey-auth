package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

// PA_ORIGINS is normalised once: these spellings all mean https://example.com.
func TestOriginListIsNormalised(t *testing.T) {
	for _, configured := range []string{"https://example.com", "HTTPS://Example.COM", "https://example.com:443", "https://example.com/"} {
		t.Run(configured, func(t *testing.T) {
			e := newEnv(t, func(c *httpapi.Config) { c.Origins = []string{configured} })
			a := testauthn.New(testauthn.Roaming, origin)
			e.register(a, "account-1")
			mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{}))
		})
	}
}

// The received origin is compared byte for byte: a browser always sends the
// canonical form, so any other spelling is rejected.
func TestNonCanonicalOriginIsRejected(t *testing.T) {
	for _, received := range []string{"https://EXAMPLE.com", "https://example.com:443", "https://example.com/", "https://example.com/path", "https://example.com."} {
		t.Run(received, func(t *testing.T) {
			e := newEnv(t)
			a := testauthn.New(testauthn.Roaming, origin)
			e.register(a, "account-1")
			mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Origin: received}), http.StatusBadRequest, "verification_failed")
		})
	}
}

func TestCrossOriginFrameIsRejected(t *testing.T) {
	cases := map[string]testauthn.Overrides{
		"crossOrigin true": {CrossOrigin: true},
		"topOrigin set":    {TopOrigin: "https://third-party.example"},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			a := testauthn.New(testauthn.Roaming, origin)
			resp, err := a.Register(e.registrationOptions("account-1"), o)
			if err != nil {
				t.Fatal(err)
			}
			mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "verification_failed")

			e.register(a, "account-1")
			mustFail(t, e.assertion(a, newNonce(), o), http.StatusBadRequest, "verification_failed")
		})
	}
}

func TestInvalidOriginListIsRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, bad := range []string{
		"", "example.com", "https://example.com/auth", "https://example.com?x=1", "https://example.com#f",
		"https://user@example.com", "https://ex%61mple.com", "https://exämple.com", "http://example.com", "ftp://example.com",
	} {
		t.Run(bad, func(t *testing.T) {
			st, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			cfg := httpapi.Config{RPID: rpID, Origins: []string{bad}, Issuer: issuer, Audience: audience, SigningKey: key}
			if _, err := httpapi.New(cfg, st); err == nil {
				t.Errorf("origin %q accepted", bad)
			}
		})
	}
	// Plain HTTP is accepted for local development only.
	for _, ok := range []string{"http://localhost:8080", "http://127.0.0.1:3000", "https://xn--exmple-cua.com"} {
		st, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := httpapi.Config{RPID: rpID, Origins: []string{ok}, Issuer: issuer, Audience: audience, SigningKey: key}
		if _, err := httpapi.New(cfg, st); err != nil {
			t.Errorf("origin %q refused: %v", ok, err)
		}
		st.Close()
	}
}
