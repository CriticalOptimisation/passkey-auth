package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/config"
)

func keyFile(t *testing.T) string {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func env(t *testing.T, override map[string]string) func(string) string {
	base := map[string]string{
		"PA_RP_ID": "example.com", "PA_ORIGINS": "https://example.com, https://www.example.com",
		"PA_ISSUER": "https://example.com/auth", "PA_AUDIENCE": "host", "PA_SIGNING_KEY_FILE": keyFile(t),
	}
	for k, v := range override {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestDefaults(t *testing.T) {
	s, err := config.Load(env(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	a := s.API
	if s.Listen != ":8080" || s.DBPath != "/data/passkey-auth.db" || a.RPName != "example.com" ||
		a.ChallengeTTL != 5*time.Minute || a.TicketTTL != 15*time.Minute || a.TokenTTL != 60*time.Second || a.MaxChallenges != 100000 {
		t.Errorf("defaults: %+v", s)
	}
	if len(a.Origins) != 2 || a.Origins[1] != "https://www.example.com" {
		t.Errorf("origins = %q", a.Origins)
	}
	if len(a.SigningKey) != ed25519.PrivateKeySize || a.PreviousKey != nil {
		t.Error("signing keys")
	}
}

func TestPreviousKeyFromPublicPEM(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	path := filepath.Join(t.TempDir(), "prev.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	s, err := config.Load(env(t, map[string]string{"PA_PREVIOUS_SIGNING_KEY_FILE": path}))
	if err != nil || !s.API.PreviousKey.Equal(pub) {
		t.Fatalf("previous key: %v", err)
	}
	s, err = config.Load(env(t, map[string]string{"PA_PREVIOUS_SIGNING_KEY_FILE": keyFile(t)}))
	if err != nil || s.API.PreviousKey == nil {
		t.Fatalf("previous key from a private PEM: %v", err)
	}
}

func TestRefused(t *testing.T) {
	notAKey := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(notAKey, []byte("not a key"), 0o600)
	cases := map[string]map[string]string{
		"PA_RP_ID":                     {"PA_RP_ID": ""},
		"PA_ORIGINS":                   {"PA_ORIGINS": ""},
		"PA_ISSUER":                    {"PA_ISSUER": ""},
		"PA_AUDIENCE":                  {"PA_AUDIENCE": ""},
		"PA_SIGNING_KEY_FILE":          {"PA_SIGNING_KEY_FILE": ""},
		"PA_SIGNING_KEY_FILE ":         {"PA_SIGNING_KEY_FILE": notAKey},
		"PA_PREVIOUS_SIGNING_KEY_FILE": {"PA_PREVIOUS_SIGNING_KEY_FILE": notAKey},
		"PA_CHALLENGE_TTL":             {"PA_CHALLENGE_TTL": "5"},
		"PA_TICKET_TTL":                {"PA_TICKET_TTL": "-1m"},
		"PA_TOKEN_TTL":                 {"PA_TOKEN_TTL": "6m"},
		"PA_MAX_CHALLENGES":            {"PA_MAX_CHALLENGES": "0"},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(env(t, override))
			if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(name)) {
				t.Fatalf("error %v does not name %s", err, name)
			}
		})
	}
}
