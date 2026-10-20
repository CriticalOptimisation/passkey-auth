package didweb_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/testhost"
)

// The did:web method maps an identifier to the HTTPS address of its document.
func TestURL(t *testing.T) {
	valid := map[string]string{
		"did:web:example.com":            "https://example.com/.well-known/did.json",
		"did:web:example.com:hosts:demo": "https://example.com/hosts/demo/did.json",
		"did:web:localhost%3A8443":       "https://localhost:8443/.well-known/did.json",
		"did:web:calcool.ai":             "https://calcool.ai/.well-known/did.json",
	}
	for did, want := range valid {
		if got, err := didweb.URL(did); err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", did, got, err, want)
		}
	}
	for _, did := range []string{
		"",
		"did:web:",
		"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"web:example.com",
		"did:web:example.com/path",
		"did:web:example.com?query",
		"did:web:example.com#fragment",
		"did:web:exa mple.com",
		"did:web:example.com::x",
		"did:web:user@example.com",
	} {
		if got, err := didweb.URL(did); err == nil {
			t.Errorf("URL(%q) = %q, want an error", did, got)
		}
	}
}

func TestNewRefusesAnInvalidDID(t *testing.T) {
	for _, did := range []string{"", "did:key:z6Mk", "did:web:"} {
		if _, err := didweb.New(didweb.Config{DID: did}); err == nil {
			t.Errorf("New accepted %q", did)
		}
	}
}

// clock is a settable time source.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newResolver(t *testing.T, h *testhost.Host, c *clock) *didweb.Resolver {
	t.Helper()
	r, err := didweb.New(didweb.Config{DID: h.DID, Client: h.Client(), Now: c.Now})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	return r
}

func newClock() *clock { return &clock{now: time.Unix(1_800_000_000, 0)} }

func TestAuthenticationKeyIsFound(t *testing.T) {
	h := testhost.New(t)
	r := newResolver(t, h, newClock())
	got, err := r.HostKey(context.Background(), h.KID(testhost.Main))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(h.Public(testhost.Main)) {
		t.Fatal("HostKey returned another key")
	}
}

// Relative ids ("#fragment") are read against the DID, and a key may be
// embedded in "authentication" rather than referenced.
func TestRelativeAndEmbeddedKeys(t *testing.T) {
	h := testhost.New(t)
	h.AddKey("embedded")
	jwk := func(name string) map[string]string { return testhost.JWK(h.Public(name)) }
	doc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       h.DID,
		"verificationMethod": []any{map[string]any{
			"id": "#" + h.Fragment(testhost.Main), "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": jwk(testhost.Main),
		}},
		"authentication": []any{
			"#" + h.Fragment(testhost.Main),
			map[string]any{"id": h.KID("embedded"), "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": jwk("embedded")},
		},
	}
	body, _ := json.Marshal(doc)
	h.SetRaw(body)
	r := newResolver(t, h, newClock())
	for _, name := range []string{testhost.Main, "embedded"} {
		got, err := r.HostKey(context.Background(), h.KID(name))
		if err != nil || !got.Equal(h.Public(name)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Only a P-256 key listed under authentication, not revoked, of this DID.
func TestRefusedKeys(t *testing.T) {
	h := testhost.New(t)
	h.AddKey("signer", testhost.AssertionMethod)
	h.AddKey("revoked", testhost.Authentication)
	h.Revoke("revoked")
	h.AddKey("unlisted")
	r := newResolver(t, h, newClock())
	ctx := context.Background()
	cases := map[string]string{
		"assertionMethod only": h.KID("signer"),
		"revoked":              h.KID("revoked"),
		"in no relation":       h.KID("unlisted"),
		"unknown fragment":     h.DID + "#nope",
		"another DID":          "did:web:elsewhere.example#" + h.Fragment(testhost.Main),
		"no fragment":          h.DID,
		"bare fragment":        "#" + h.Fragment(testhost.Main),
	}
	for name, kid := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.HostKey(ctx, kid); !errors.Is(err, didweb.ErrUnknownKey) {
				t.Fatalf("err = %v, want ErrUnknownKey", err)
			}
		})
	}
}

// A key under authentication that is not EC P-256 is refused.
func TestNonP256KeysAreRefused(t *testing.T) {
	h := testhost.New(t)
	ok := testhost.JWK(h.Public(testhost.Main))
	keys := map[string]map[string]string{
		"ed25519": {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
		"p384":    {"kty": "EC", "crv": "P-384", "x": ok["x"], "y": ok["y"]},
		"no crv":  {"kty": "EC", "x": ok["x"], "y": ok["y"]},
	}
	var methods, auth []any
	for name, jwk := range keys {
		id := h.DID + "#" + strings.ReplaceAll(name, " ", "-")
		methods = append(methods, map[string]any{"id": id, "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": jwk})
		auth = append(auth, id)
	}
	body, _ := json.Marshal(map[string]any{"id": h.DID, "verificationMethod": methods, "authentication": auth})
	h.SetRaw(body)
	r := newResolver(t, h, newClock())
	for name := range keys {
		if _, err := r.HostKey(context.Background(), h.DID+"#"+strings.ReplaceAll(name, " ", "-")); !errors.Is(err, didweb.ErrUnknownKey) {
			t.Errorf("%s: err = %v, want ErrUnknownKey", name, err)
		}
	}
}

// A document whose id is another DID is not the host's.
func TestDocumentOfAnotherDID(t *testing.T) {
	h := testhost.New(t)
	var doc map[string]any
	_ = json.Unmarshal(h.Document(), &doc)
	doc["id"] = "did:web:elsewhere.example"
	body, _ := json.Marshal(doc)
	h.SetRaw(body)
	r := newResolver(t, h, newClock())
	if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// The document is kept for CacheTTL, then fetched again.
func TestDocumentIsCached(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	for range 3 {
		if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
			t.Fatal(err)
		}
	}
	if n := h.Fetches(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
	c.advance(didweb.CacheTTL + time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	if n := h.Fetches(); n != 2 {
		t.Fatalf("%d fetches after the TTL, want 2", n)
	}
}

// An unknown kid causes one early fetch, at most once every RefetchInterval:
// a new key works at once, and invented kids cannot flood the host's site.
func TestEarlyFetchOnUnknownKid(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	h.AddKey("rotated", testhost.Authentication)
	if _, err := r.HostKey(ctx, h.KID("rotated")); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if n := h.Fetches(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
	for range 5 {
		if _, err := r.HostKey(ctx, h.DID+"#invented"); !errors.Is(err, didweb.ErrUnknownKey) {
			t.Fatalf("invented kid: %v", err)
		}
	}
	if n := h.Fetches(); n != 2 {
		t.Fatalf("%d fetches within the refetch interval, want 2", n)
	}
	c.advance(didweb.RefetchInterval + time.Second)
	_, _ = r.HostKey(ctx, h.DID+"#invented")
	if n := h.Fetches(); n != 3 {
		t.Fatalf("%d fetches after the refetch interval, want 3", n)
	}
}

// A revoked key keeps working until the kept document expires.
func TestRevocationTakesEffectWithinTheCacheTTL(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	h.Revoke(testhost.Main)
	c.advance(didweb.CacheTTL - time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("within the TTL: %v", err)
	}
	c.advance(2 * time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnknownKey) {
		t.Fatalf("after the TTL: %v, want ErrUnknownKey", err)
	}
}

// A failed fetch keeps the last good document.
func TestFailedFetchKeepsTheLastDocument(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	h.SetStatus(http.StatusInternalServerError)
	c.advance(didweb.CacheTTL + time.Minute)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("after a failed fetch: %v", err)
	}
	if n := h.Fetches(); n != 2 {
		t.Fatalf("%d fetches, want 2: the expired document must be fetched again", n)
	}
}

// Before a first document, every lookup is ErrUnavailable.
func TestUnavailableBeforeTheFirstDocument(t *testing.T) {
	cases := map[string]func(h *testhost.Host){
		"server error": func(h *testhost.Host) { h.SetStatus(http.StatusInternalServerError) },
		"not found":    func(h *testhost.Host) { h.SetStatus(http.StatusNotFound) },
		"not JSON":     func(h *testhost.Host) { h.SetRaw([]byte("<html>")) },
		"too large": func(h *testhost.Host) {
			var doc map[string]any
			_ = json.Unmarshal(h.Document(), &doc)
			doc["padding"] = strings.Repeat("x", didweb.MaxDocumentBytes)
			b, _ := json.Marshal(doc)
			h.SetRaw(b)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			h := testhost.New(t)
			breakIt(h)
			r := newResolver(t, h, newClock())
			if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
		})
	}
}

// The document is fetched over HTTPS only: a host serving plain HTTP is
// unavailable.
func TestHTTPSOnly(t *testing.T) {
	h := testhost.New(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(h.Document())
	}))
	defer plain.Close()
	u, _ := url.Parse(plain.URL)
	did := "did:web:" + strings.ReplaceAll(u.Host, ":", "%3A")
	r, err := didweb.New(didweb.Config{DID: did, Client: plain.Client(), Now: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.HostKey(context.Background(), did+"#"+h.Fragment(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// Config.Fetch replaces the HTTPS fetch, and receives the did:web URL.
func TestFetchOverride(t *testing.T) {
	h := testhost.New(t)
	var asked string
	r, err := didweb.New(didweb.Config{DID: h.DID, Now: newClock().Now,
		Fetch: func(_ context.Context, u string) ([]byte, error) { asked = u; return h.Document(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	if want, _ := didweb.URL(h.DID); asked != want || want == "" {
		t.Fatalf("fetched %q, want %q", asked, want)
	}
	if h.Fetches() != 0 {
		t.Fatal("the HTTPS fetch ran despite Config.Fetch")
	}
}
