// Package token signs result tokens and publishes their verification keys.
package token

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Type is the JOSE "typ" header of every result token.
const Type = "passkey-result+jwt"

// Claims are the service-specific claims of a result token (docs/api.md).
type Claims struct {
	Ceremony  string `json:"ceremony"`
	Origin    string `json:"origin"`
	Cred      string `json:"cred"`
	UV        bool   `json:"uv"`
	BE        bool   `json:"be"`
	BS        bool   `json:"bs"`
	Assurance string `json:"assurance"`
	AAGUID    string `json:"aaguid"`
	Nonce     string `json:"nonce,omitempty"`
	Fmt       string `json:"fmt,omitempty"`
}

// Issuer signs result tokens with the current key and publishes the JWKS.
type Issuer struct {
	issuer, audience string
	ttl              time.Duration
	signer           jose.Signer
	jwks             []byte
}

// NewIssuer builds an issuer. previous, if not nil, is listed in the JWKS
// after the current key, for a rotation.
func NewIssuer(issuer, audience string, ttl time.Duration, key ed25519.PrivateKey, previous ed25519.PublicKey) (*Issuer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("token: signing key is not an Ed25519 private key")
	}
	current := key.Public().(ed25519.PublicKey)
	kid, err := KeyID(current)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType(Type).WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return nil, err
	}
	keys := []ed25519.PublicKey{current}
	if previous != nil {
		keys = append(keys, previous)
	}
	jwks, err := jwksOf(keys)
	if err != nil {
		return nil, err
	}
	return &Issuer{issuer: issuer, audience: audience, ttl: ttl, signer: signer, jwks: jwks}, nil
}

// Sign returns a compact JWS for subject with the given claims, issued at now.
func (i *Issuer) Sign(subject string, c Claims, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	std := jwt.Claims{
		Issuer:   i.issuer,
		Audience: jwt.Audience{i.audience},
		Subject:  subject,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(i.ttl)),
		ID:       base64.RawURLEncoding.EncodeToString(jti),
	}
	return jwt.Signed(i.signer).Claims(std).Claims(c).Serialize()
}

// JWKS returns the JSON Web Key Set document.
func (i *Issuer) JWKS() []byte { return i.jwks }

// KeyID is the RFC 7638 thumbprint of a public key, base64url.
func KeyID(pub ed25519.PublicKey) (string, error) {
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func jwksOf(keys []ed25519.PublicKey) ([]byte, error) {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{}
	for _, k := range keys {
		kid, err := KeyID(k)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jwk{"OKP", "Ed25519", base64.RawURLEncoding.EncodeToString(k), kid, "sig", "EdDSA"})
	}
	return json.Marshal(set)
}

// LoadPrivateKey reads an Ed25519 private key, PKCS#8 PEM.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("token: %s: %w", path, err)
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("token: %s: not an Ed25519 key", path)
	}
	return ed, nil
}

// LoadPublicKey reads an Ed25519 key, from a PKCS#8 private or an SPKI public
// PEM file, and returns its public half.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	if priv, err := LoadPrivateKey(path); err == nil {
		return priv.Public().(ed25519.PublicKey), nil
	}
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("token: %s: %w", path, err)
	}
	ed, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("token: %s: not an Ed25519 key", path)
	}
	return ed, nil
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("token: %s: no %s PEM block", path, typ)
	}
	return block.Bytes, nil
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | Ed25519 result tokens, JWKS, key loading                      |
