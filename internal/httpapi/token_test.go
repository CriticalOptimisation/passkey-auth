package httpapi_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

func thumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

func TestJWKS(t *testing.T) {
	_, previous, _ := ed25519.GenerateKey(rand.Reader)
	for _, rotating := range []bool{false, true} {
		name := map[bool]string{false: "single key", true: "during rotation"}[rotating]
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(c *httpapi.Config) {
				if rotating {
					c.PreviousKey = previous.Public().(ed25519.PublicKey)
				}
			})
			r := e.do(http.MethodGet, "/v1/jwks.json", nil, nil)
			mustOK(t, r)
			if got := r.Header.Get("Cache-Control"); got != "public, max-age=300" {
				t.Errorf("Cache-Control = %q", got)
			}
			if got := r.Header.Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
			}
			var raw struct {
				Keys []map[string]string `json:"keys"`
			}
			if err := json.Unmarshal(r.Body, &raw); err != nil {
				t.Fatal(err)
			}
			want := []ed25519.PublicKey{e.key.Public().(ed25519.PublicKey)}
			if rotating {
				want = append(want, previous.Public().(ed25519.PublicKey))
			}
			if len(raw.Keys) != len(want) {
				t.Fatalf("%d keys, want %d", len(raw.Keys), len(want))
			}
			for i, k := range raw.Keys {
				pub := base64.RawURLEncoding.EncodeToString(want[i])
				if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["alg"] != "EdDSA" || k["use"] != "sig" || k["x"] != pub {
					t.Errorf("key %d = %v", i, k)
				}
				if k["kid"] != thumbprint(t, want[i]) {
					t.Errorf("key %d kid = %q, want the RFC 7638 thumbprint", i, k["kid"])
				}
				if _, private := k["d"]; private {
					t.Errorf("key %d publishes private material", i)
				}
			}

			// Tokens are signed with the current key.
			a := testauthn.New(testauthn.Platform, origin)
			tok, err := jwt.ParseSigned(e.register(a, "account-1"), []jose.SignatureAlgorithm{jose.EdDSA})
			if err != nil {
				t.Fatal(err)
			}
			if tok.Headers[0].KeyID != raw.Keys[0]["kid"] {
				t.Errorf("token kid = %q, want the current key", tok.Headers[0].KeyID)
			}
		})
	}
}

func TestTamperedTokenIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	token := e.register(a, "account-1")
	if _, err := e.verifyToken(token); err != nil {
		t.Fatalf("genuine token rejected: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}

	// Payload rewritten to another account.
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["sub"] = "account-2"
	forged, _ := json.Marshal(m)
	otherPayload := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]

	// Signature altered.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	otherSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Header switched to "none" with no signature.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"passkey-result+jwt"}`)) + "." + parts[1] + "."

	// Same claims, signed by another key under the service's kid.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]any
	_ = json.Unmarshal(hdr, &h)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: rogue},
		(&jose.SignerOptions{}).WithType("passkey-result+jwt").WithHeader("kid", h["kid"]))
	if err != nil {
		t.Fatal(err)
	}
	rogueToken, err := jwt.Signed(signer).Claims(m).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	for name, tok := range map[string]string{"payload": otherPayload, "signature": otherSig, "alg none": none, "rogue key": rogueToken} {
		if _, err := e.verifyToken(tok); err == nil {
			t.Errorf("%s: tampered token verified", name)
		}
	}
}

func TestTokenExpires(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	c, err := e.verifyToken(e.register(a, "account-1"))
	if err != nil {
		t.Fatal(err)
	}
	later := e.now.Add(61 * time.Second)
	if err := c.Claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{audience}, Time: later}, 0); err == nil {
		t.Error("token still valid after its lifetime")
	}
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | JWKS, tampered and expired tokens                             |
