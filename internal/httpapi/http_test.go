package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestHelperIsLoadableFromAnyOrigin(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodGet, "/v1/passkey-auth.js", nil, map[string]string{"Origin": "https://third-party.example"})
	body := mustOK(t, r)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q", ct)
	}
	if got := r.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := r.Header.Get("Cross-Origin-Resource-Policy"); got != "cross-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q, want cross-origin", got)
	}
	for _, export := range []string{"export async function register", "export async function authenticate", "export class PasskeyAuthError", "baseURL"} {
		if !strings.Contains(string(body), export) {
			t.Errorf("helper lacks %q", export)
		}
	}
}

func TestCORSOnCeremonyRoutes(t *testing.T) {
	e := newEnv(t)
	routes := []string{"/v1/registration/options", "/v1/registration/verify", "/v1/authentication/options", "/v1/authentication/verify"}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			// Preflight from an allowed origin.
			r := e.do(http.MethodOptions, route, nil, map[string]string{
				"Origin":                         origin,
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "content-type",
			})
			if r.Status != http.StatusNoContent {
				t.Errorf("preflight status %d", r.Status)
			}
			if got := r.Header.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, origin)
			}
			if !strings.Contains(r.Header.Get("Access-Control-Allow-Methods"), "POST") {
				t.Errorf("Access-Control-Allow-Methods = %q", r.Header.Get("Access-Control-Allow-Methods"))
			}
			if !strings.Contains(strings.ToLower(r.Header.Get("Access-Control-Allow-Headers")), "content-type") {
				t.Errorf("Access-Control-Allow-Headers = %q", r.Header.Get("Access-Control-Allow-Headers"))
			}
			if r.Header.Get("Access-Control-Allow-Credentials") != "" {
				t.Error("credentials allowed")
			}
			if !strings.Contains(r.Header.Get("Vary"), "Origin") {
				t.Errorf("Vary = %q, want Origin", r.Header.Get("Vary"))
			}

			// Preflight from any other origin gets no CORS header.
			r = e.do(http.MethodOptions, route, nil, map[string]string{
				"Origin":                        "https://third-party.example",
				"Access-Control-Request-Method": "POST",
			})
			if got := r.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("third-party origin allowed: %q", got)
			}
		})
	}

	// Actual responses carry the header too, errors included.
	r := e.post("/v1/authentication/options", map[string]string{"nonce": newNonce()})
	if got := r.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("response Access-Control-Allow-Origin = %q", got)
	}
	r = e.post("/v1/registration/options", map[string]string{"ticket": "unknown"})
	if got := r.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("error response Access-Control-Allow-Origin = %q", got)
	}
}

func TestErrorEnvelope(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		header map[string]string
		status int
		code   string
	}{
		{"unknown route", http.MethodGet, "/v1/nothing", nil, nil, 404, "not_found"},
		{"wrong method", http.MethodGet, "/v1/authentication/options", nil, nil, 405, "method_not_allowed"},
		{"no JSON content type", http.MethodPost, "/v1/authentication/options", []byte(`{"nonce":"x"}`), map[string]string{"Content-Type": "text/plain"}, 415, "unsupported_media_type"},
		{"malformed JSON", http.MethodPost, "/v1/authentication/options", []byte(`{"nonce":`), nil, 400, "invalid_request"},
		{"unknown field", http.MethodPost, "/v1/authentication/options", []byte(`{"nonce":"` + newNonce() + `","extra":1}`), nil, 400, "invalid_request"},
		{"too large", http.MethodPost, "/v1/authentication/options", []byte(`{"nonce":"` + strings.Repeat("A", 65*1024) + `"}`), nil, 413, "request_too_large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.do(c.method, c.path, c.body, c.header)
			mustFail(t, r, c.status, c.code)
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q", ct)
			}
		})
	}
}

// The service serves nothing under /.well-known/: the domain root belongs to
// the host's site.
func TestNothingUnderWellKnown(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/.well-known/jwks.json", "/.well-known/webauthn"} {
		mustFail(t, e.do(http.MethodGet, path, nil, nil), http.StatusNotFound, "not_found")
	}
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | helper, CORS, error envelope, no /.well-known                 |
