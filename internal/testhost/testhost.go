// Package testhost plays the host application in tests: it holds P-256 keys,
// serves its did:web DID document over HTTPS, and signs host tokens
// (docs/api.md, Host authentication).
package testhost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Relations of a key in the DID document.
const (
	Authentication  = "authentication"
	AssertionMethod = "assertionMethod"
)

// Main is the name of the key every host starts with, under authentication.
const Main = "main"

// Host is a host application with its DID document served over HTTPS.
type Host struct {
	DID string
	srv *httptest.Server

	mu      sync.Mutex
	keys    map[string]*key
	order   []string
	raw     []byte // served instead of the generated document, when set
	status  int    // answered instead of the document, when not 0
	fetches int
}

type key struct {
	priv      *ecdsa.PrivateKey
	fragment  string
	relations []string
	revoked   bool
}

// New starts a host whose DID resolves to its own TLS test server, with the
// key Main under authentication.
func New(t testing.TB) *Host {
	t.Helper()
	h := &Host{keys: map[string]*key{}}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.srv.Close)
	u, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.DID = "did:web:" + strings.ReplaceAll(u.Host, ":", "%3A")
	h.AddKey(Main, Authentication)
	return h
}

// Client trusts the host's TLS certificate.
func (h *Host) Client() *http.Client { return h.srv.Client() }

// URL of the host's test server, e.g. https://127.0.0.1:41234.
func (h *Host) URL() string { return h.srv.URL }

// AddKey creates a P-256 key and lists it under the given relations.
func (h *Host) AddKey(name string, relations ...string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys[name] = &key{priv: priv, fragment: Thumbprint(&priv.PublicKey), relations: relations}
	h.order = append(h.order, name)
}

// Revoke marks a key revoked in the document; the key itself stays listed.
func (h *Host) Revoke(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys[name].revoked = true
}

// Public returns the public key of a key.
func (h *Host) Public(name string) *ecdsa.PublicKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	return &h.keys[name].priv.PublicKey
}

// Fragment is the fragment of a key's DID URL: its RFC 7638 thumbprint.
func (h *Host) Fragment(name string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.keys[name].fragment
}

// KID is the DID URL of a key, as a host token's kid.
func (h *Host) KID(name string) string { return h.DID + "#" + h.Fragment(name) }

// SetRaw serves body as the document instead of the generated one; nil
// returns to the generated document.
func (h *Host) SetRaw(body []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.raw = body
}

// SetStatus makes every fetch answer this status; 0 serves the document again.
func (h *Host) SetStatus(status int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = status
}

// Fetches counts the requests for the document.
func (h *Host) Fetches() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fetches
}

// Document is the generated DID document, as official-did lays it out.
func (h *Host) Document() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.document()
}

func (h *Host) document() []byte {
	type method struct {
		ID           string            `json:"id"`
		Type         string            `json:"type"`
		Controller   string            `json:"controller"`
		PublicKeyJwk map[string]string `json:"publicKeyJwk"`
		Revoked      string            `json:"revoked,omitempty"`
	}
	doc := struct {
		Context            []string `json:"@context"`
		ID                 string   `json:"id"`
		VerificationMethod []method `json:"verificationMethod"`
		Authentication     []string `json:"authentication,omitempty"`
		AssertionMethod    []string `json:"assertionMethod,omitempty"`
	}{
		Context: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1", "https://www.w3.org/ns/cid/v1"},
		ID:      h.DID,
	}
	for _, name := range h.order {
		k := h.keys[name]
		id := h.DID + "#" + k.fragment
		m := method{ID: id, Type: "JsonWebKey", Controller: h.DID, PublicKeyJwk: JWK(&k.priv.PublicKey)}
		if k.revoked {
			m.Revoked = "2027-01-01T00:00:00Z"
		}
		doc.VerificationMethod = append(doc.VerificationMethod, m)
		for _, rel := range k.relations {
			switch rel {
			case Authentication:
				doc.Authentication = append(doc.Authentication, id)
			case AssertionMethod:
				doc.AssertionMethod = append(doc.AssertionMethod, id)
			}
		}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}

func (h *Host) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/did.json" {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	h.fetches++
	status, body := h.status, h.raw
	if body == nil {
		body = h.document()
	}
	h.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	_, _ = w.Write(body)
}

// Token is a host token before signing; tests edit it to break one rule.
type Token struct {
	Header map[string]any
	Claims map[string]any
	// SignWith names the key that signs; by default the key of kid.
	SignWith string
}

// Token signs a valid host token with key name, for audience (PA_ISSUER), at
// now; edit, if given, changes it before signing.
func (h *Host) Token(name, audience string, now time.Time, edit ...func(*Token)) string {
	tk := &Token{
		Header: map[string]any{"alg": "ES256", "typ": "passkey-host+jwt", "kid": h.KID(name)},
		Claims: map[string]any{
			"iss": h.DID, "aud": audience,
			"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
		},
		SignWith: name,
	}
	for _, f := range edit {
		f(tk)
	}
	h.mu.Lock()
	priv := h.keys[tk.SignWith].priv
	h.mu.Unlock()
	return Sign(priv, tk.Header, tk.Claims)
}

// Sign makes a compact JWS of header and claims with an ES256 signature,
// whatever the header says.
func Sign(priv *ecdsa.PrivateKey, header, claims map[string]any) string {
	input := part(header) + "." + part(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

// JWK is the public JWK of a P-256 key, members in RFC 7638 order.
func JWK(pub *ecdsa.PublicKey) map[string]string {
	e, err := pub.ECDH()
	if err != nil {
		panic(err)
	}
	point := e.Bytes() // 0x04 || x || y
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64(point[1:33]), "y": b64(point[33:])}
}

// Thumbprint is the RFC 7638 thumbprint of a P-256 public key, base64url.
func Thumbprint(pub *ecdsa.PublicKey) string {
	j := JWK(pub)
	canon := `{"crv":"P-256","kty":"EC","x":"` + j["x"] + `","y":"` + j["y"] + `"}`
	sum := sha256.Sum256([]byte(canon))
	return b64(sum[:])
}

func part(v map[string]any) string { return B64JSON(v) }

// B64JSON is the base64url of the JSON of v: one part of a compact JWS.
func B64JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b64(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #14    | test host: P-256 keys, DID document over TLS, tokens          |
