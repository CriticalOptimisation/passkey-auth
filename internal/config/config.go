// Package config reads the service configuration from the environment
// (docs/configuration.md) and refuses anything missing or invalid.
package config

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/didweb"
	"github.com/CriticalOptimisation/passkey-auth/internal/httpapi"
	"github.com/CriticalOptimisation/passkey-auth/internal/token"
)

// Settings is the whole configuration of one service instance.
type Settings struct {
	Listen     string
	HostListen string // host-facing routes
	HostDID    string // the host's did:web identifier
	DBPath     string
	API        httpapi.Config
}

// Defaults of docs/configuration.md that are not those of httpapi.
const (
	DefaultListen     = ":8080"
	DefaultHostListen = ":8081"
	DefaultDBPath     = "/data/passkey-auth.db"
)

// Load reads the configuration through getenv (os.Getenv in production).
func Load(getenv func(string) string) (Settings, error) {
	s := Settings{
		Listen:     or(getenv("PA_LISTEN"), DefaultListen),
		HostListen: or(getenv("PA_HOST_LISTEN"), DefaultHostListen),
		HostDID:    getenv("PA_HOST_DID"),
		DBPath:     or(getenv("PA_DB_PATH"), DefaultDBPath),
	}
	if s.HostListen == s.Listen {
		return s, fmt.Errorf("PA_HOST_LISTEN must differ from PA_LISTEN (%s)", s.Listen)
	}
	if s.HostDID == "" {
		return s, fmt.Errorf("PA_HOST_DID is required")
	}
	if _, err := didweb.URL(s.HostDID); err != nil {
		return s, fmt.Errorf("PA_HOST_DID: %w", err)
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
		{"PA_CHALLENGE_TTL", &api.ChallengeTTL, httpapi.DefaultChallengeTTL, 0},
		{"PA_TICKET_TTL", &api.TicketTTL, httpapi.DefaultTicketTTL, 0},
		{"PA_TOKEN_TTL", &api.TokenTTL, httpapi.DefaultTokenTTL, httpapi.MaxTokenTTL},
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
	api.MaxChallenges = httpapi.DefaultMaxChallenges
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

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | configuration from the environment                            |
// | #14    | PA_HOST_LISTEN, PA_HOST_DID                                   |
