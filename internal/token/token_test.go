package token_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/CriticalOptimisation/passkey-auth/internal/token"
)

func write(t *testing.T, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)

	if k, err := token.LoadPrivateKey(write(t, "PRIVATE KEY", privDER)); err != nil || !k.Equal(priv) {
		t.Errorf("private key: %v", err)
	}
	if k, err := token.LoadPublicKey(write(t, "PUBLIC KEY", pubDER)); err != nil || !k.Equal(pub) {
		t.Errorf("public key: %v", err)
	}
	if k, err := token.LoadPublicKey(write(t, "PRIVATE KEY", privDER)); err != nil || !k.Equal(pub) {
		t.Errorf("public key from a private PEM: %v", err)
	}
	for name, path := range map[string]string{
		"P-256 key":  write(t, "PRIVATE KEY", ecDER),
		"public PEM": write(t, "PUBLIC KEY", pubDER),
		"missing":    filepath.Join(t.TempDir(), "none.pem"),
		"not PEM":    notPEM(t),
	} {
		if _, err := token.LoadPrivateKey(path); err == nil {
			t.Errorf("LoadPrivateKey accepted a %s", name)
		}
	}
}

func TestIssuerRefusesABadKey(t *testing.T) {
	if _, err := token.NewIssuer("i", "a", 60, ed25519.PrivateKey{1, 2, 3}, nil); err == nil {
		t.Error("short key accepted")
	}
}

func notPEM(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "x.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | key loading                                                   |
