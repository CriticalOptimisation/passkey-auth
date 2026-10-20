package didweb_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/testhost"
)

// Edge cases of the did:web method's mapping.
func TestURLEdgeCases(t *testing.T) {
	valid := map[string]string{
		"did:web:example.com:a%2Bb":          "https://example.com/a%2Bb/did.json",
		"did:web:sub.example.com%3A8443:x:y": "https://sub.example.com:8443/x/y/did.json",
		"did:web:a":                          "https://a/.well-known/did.json",
	}
	for did, want := range valid {
		if got, err := didweb.URL(did); err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", did, got, err, want)
		}
	}
	for _, did := range []string{
		"did:web:example.com:..",
		"did:web:example.com:.",
		"did:web:example.com:a/b",
		"did:web:example.com:",
		"did:web:-example.com",
		"did:web:example.com%3Ahttp",
		"did:web:example.com%3A",
		"did:web:example.com%2Fpath",
		"did:web:%zz",
		"DID:WEB:example.com",
	} {
		if got, err := didweb.URL(did); err == nil {
			t.Errorf("URL(%q) = %q, want an error", did, got)
		}
	}
}

// A document that never arrives is given up after FetchTimeout.
func TestSlowDocumentTimesOut(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * didweb.FetchTimeout):
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	did := "did:web:" + strings.ReplaceAll(u.Host, ":", "%3A")
	r, err := didweb.New(didweb.Config{DID: did, Client: srv.Client(), Now: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := r.HostKey(context.Background(), did+"#k"); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d < didweb.FetchTimeout-time.Second || d > didweb.FetchTimeout+3*time.Second {
		t.Fatalf("gave up after %s, want about %s", d, didweb.FetchTimeout)
	}
}

// The size limit holds for Config.Fetch too.
func TestFetchOverrideTooLarge(t *testing.T) {
	h := testhost.New(t)
	var doc map[string]any
	_ = json.Unmarshal(h.Document(), &doc)
	doc["padding"] = strings.Repeat("x", didweb.MaxDocumentBytes)
	big, _ := json.Marshal(doc)
	r, err := didweb.New(didweb.Config{DID: h.DID, Now: newClock().Now,
		Fetch: func(context.Context, string) ([]byte, error) { return big, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// A redirect may not leave HTTPS.
func TestRedirectToPlainHTTPIsRefused(t *testing.T) {
	h := testhost.New(t)
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		_, _ = w.Write(h.Document())
	}))
	defer plain.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/.well-known/did.json", http.StatusFound)
	}))
	defer redirect.Close()
	u, _ := url.Parse(redirect.URL)
	did := "did:web:" + strings.ReplaceAll(u.Host, ":", "%3A")
	r, err := didweb.New(didweb.Config{DID: did, Client: redirect.Client(), Now: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.HostKey(context.Background(), did+"#"+h.Fragment(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Fatalf("the plain HTTP server was asked %d times", n)
	}
}

// A failed fetch is tried again after RefetchInterval, not on every lookup:
// a host site that is down is not flooded.
func TestFailedFetchIsRetriedAfterTheRefetchInterval(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	h.SetStatus(http.StatusInternalServerError)
	for range 3 {
		if _, err := r.HostKey(ctx, h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	}
	if n := h.Fetches(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
	h.SetStatus(0)
	c.advance(didweb.RefetchInterval - time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnavailable) {
		t.Fatalf("within the interval: %v, want ErrUnavailable", err)
	}
	c.advance(2 * time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("after the interval: %v", err)
	}
	if n := h.Fetches(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
}

// After a failed fetch of an expired document, the kept one serves until
// the next try, RefetchInterval later.
func TestKeptDocumentIsRefreshedAfterAFailure(t *testing.T) {
	h := testhost.New(t)
	c := newClock()
	r := newResolver(t, h, c)
	ctx := context.Background()
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatal(err)
	}
	h.SetStatus(http.StatusInternalServerError)
	c.advance(didweb.CacheTTL)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("kept document: %v", err)
	}
	h.SetStatus(0)
	h.Revoke(testhost.Main)
	c.advance(didweb.RefetchInterval - time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("before the next try: %v", err)
	}
	c.advance(2 * time.Second)
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); !errors.Is(err, didweb.ErrUnknownKey) {
		t.Fatalf("after the next try: %v, want ErrUnknownKey", err)
	}
	if n := h.Fetches(); n != 3 {
		t.Fatalf("%d fetches, want 3", n)
	}
}

// docWith serves a document holding the given verification methods, all
// listed under authentication by reference.
func docWith(t *testing.T, h *testhost.Host, methods ...map[string]any) {
	t.Helper()
	var auth []string
	for _, m := range methods {
		auth = append(auth, m["id"].(string))
	}
	body, _ := json.Marshal(map[string]any{"id": h.DID, "verificationMethod": methods, "authentication": auth})
	h.SetRaw(body)
}

// An id given twice names no key: which entry is meant cannot be told.
func TestDuplicateMethodIDsNameNoKey(t *testing.T) {
	h := testhost.New(t)
	h.AddKey("twin")
	kid := h.KID(testhost.Main)
	docWith(t, h,
		map[string]any{"id": kid, "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": testhost.JWK(h.Public(testhost.Main))},
		map[string]any{"id": kid, "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": testhost.JWK(h.Public("twin"))},
	)
	r := newResolver(t, h, newClock())
	if _, err := r.HostKey(context.Background(), kid); !errors.Is(err, didweb.ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

// A JWK that carries its private part, or bad coordinates, is refused; a
// "revoked" of false or null is not a revocation.
func TestKeyMaterialEdgeCases(t *testing.T) {
	h := testhost.New(t)
	ok := testhost.JWK(h.Public(testhost.Main))
	withD := map[string]string{"kty": "EC", "crv": "P-256", "x": ok["x"], "y": ok["y"], "d": "AAAA"}
	offCurve := map[string]string{"kty": "EC", "crv": "P-256", "x": ok["x"], "y": ok["x"]}
	short := map[string]string{"kty": "EC", "crv": "P-256", "x": ok["x"][:20], "y": ok["y"]}
	method := func(frag string, jwk any, extra ...any) map[string]any {
		m := map[string]any{"id": h.DID + "#" + frag, "type": "JsonWebKey", "controller": h.DID, "publicKeyJwk": jwk}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}
	docWith(t, h,
		method("private", withD), method("off-curve", offCurve), method("short", short),
		method("revoked-false", ok, "revoked", false), method("revoked-null", ok, "revoked", nil),
		method("revoked-true", ok, "revoked", true),
	)
	r := newResolver(t, h, newClock())
	ctx := context.Background()
	for _, frag := range []string{"private", "off-curve", "short", "revoked-true"} {
		if _, err := r.HostKey(ctx, h.DID+"#"+frag); !errors.Is(err, didweb.ErrUnknownKey) {
			t.Errorf("%s: err = %v, want ErrUnknownKey", frag, err)
		}
	}
	for _, frag := range []string{"revoked-false", "revoked-null"} {
		if _, err := r.HostKey(ctx, h.DID+"#"+frag); err != nil {
			t.Errorf("%s: %v", frag, err)
		}
	}
}

// Concurrent lookups share one fetch.
func TestConcurrentLookupsFetchOnce(t *testing.T) {
	h := testhost.New(t)
	r := newResolver(t, h, newClock())
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := h.Fetches(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

// The fetch serves every waiting lookup, so the caller's cancellation does
// not make it fail and leave the others without a document.
func TestCancelledCallerDoesNotFailTheFetch(t *testing.T) {
	h := testhost.New(t)
	r := newResolver(t, h, newClock())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.HostKey(ctx, h.KID(testhost.Main)); err != nil {
		t.Fatalf("cancelled caller: %v", err)
	}
	if _, err := r.HostKey(context.Background(), h.KID(testhost.Main)); err != nil || h.Fetches() != 1 {
		t.Fatalf("next lookup: %v, %d fetches", err, h.Fetches())
	}
}
