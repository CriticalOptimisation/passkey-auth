// Package config reads the service configuration from the environment
// (docs/configuration.md) and refuses anything missing or invalid.
package config

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/token"
)

// Settings is the whole configuration of one service instance.
type Settings struct {
	Listen string
	DBPath string
	API    httpapi.Config
}

// Load reads the configuration through getenv (os.Getenv in production).
func Load(getenv func(string) string) (Settings, error) {
	s := Settings{
		Listen: or(getenv("PA_LISTEN"), ":8080"),
		DBPath: or(getenv("PA_DB_PATH"), "/data/passkey-auth.db"),
	}
	api := &s.API
	var err error
	for _, req := range []struct {
		name string
		dst  *string
	}{{"PA_RP_ID", &api.RPID}, {"PA_ISSUER", &api.Issuer}, {"PA_AUDIENCE", &api.Audience}} {
		if *req.dst = getenv(req.name); *req.dst == "" {
			return s, fmt.Errorf("%s is required", req.name)
		}
	}
	api.RPName = or(getenv("PA_RP_NAME"), api.RPID)
	if v := getenv("PA_ORIGINS"); v == "" {
		return s, fmt.Errorf("PA_ORIGINS is required")
	} else {
		for _, o := range strings.Split(v, ",") {
			api.Origins = append(api.Origins, strings.TrimSpace(o))
		}
	}
	keyFile := getenv("PA_SIGNING_KEY_FILE")
	if keyFile == "" {
		return s, fmt.Errorf("PA_SIGNING_KEY_FILE is required")
	}
	if api.SigningKey, err = token.LoadPrivateKey(keyFile); err != nil {
		return s, fmt.Errorf("PA_SIGNING_KEY_FILE: %w", err)
	}
	if f := getenv("PA_PREVIOUS_SIGNING_KEY_FILE"); f != "" {
		var prev ed25519.PublicKey
		if prev, err = token.LoadPublicKey(f); err != nil {
			return s, fmt.Errorf("PA_PREVIOUS_SIGNING_KEY_FILE: %w", err)
		}
		api.PreviousKey = prev
	}
	for _, d := range []struct {
		name string
		dst  *time.Duration
		def  time.Duration
		max  time.Duration
	}{
		{"PA_CHALLENGE_TTL", &api.ChallengeTTL, 5 * time.Minute, 0},
		{"PA_TICKET_TTL", &api.TicketTTL, 15 * time.Minute, 0},
		{"PA_TOKEN_TTL", &api.TokenTTL, 60 * time.Second, 5 * time.Minute},
	} {
		*d.dst = d.def
		if v := getenv(d.name); v != "" {
			if *d.dst, err = time.ParseDuration(v); err != nil || *d.dst <= 0 {
				return s, fmt.Errorf("%s: a positive Go duration is required, got %q", d.name, v)
			}
		}
		if d.max > 0 && *d.dst > d.max {
			return s, fmt.Errorf("%s: at most %s", d.name, d.max)
		}
	}
	api.MaxChallenges = 100000
	if v := getenv("PA_MAX_CHALLENGES"); v != "" {
		if api.MaxChallenges, err = strconv.Atoi(v); err != nil || api.MaxChallenges <= 0 {
			return s, fmt.Errorf("PA_MAX_CHALLENGES: a positive integer is required, got %q", v)
		}
	}
	return s, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
