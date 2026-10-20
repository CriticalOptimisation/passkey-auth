// Package ceremony runs the WebAuthn registration and authentication
// ceremonies: it issues options, and verifies responses with go-webauthn plus
// the service's own policy (exact origin, no cross-origin frames, UV required,
// counter regression rejected).
package ceremony

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/CriticalOptimisation/passkey-auth/internal/store"
)

// Error codes, as in docs/api.md.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeTicketInvalid      = "ticket_invalid"
	CodeChallengeInvalid   = "challenge_invalid"
	CodeCredentialUnknown  = "credential_unknown"
	CodeVerificationFailed = "verification_failed"
	CodeUnavailable        = "unavailable"
)

// Error is a refusal. Code goes to the client; Reason goes to the log only.
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code + ": " + e.Reason }

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// AssurancePasskey is the only profile until the attestation policy of #9.
const AssurancePasskey = "passkey"

// Sizes and limits of docs/api.md, in bytes unless stated.
const (
	TicketBytes     = 32 // random bytes of a registration ticket
	ChallengeBytes  = 32 // random bytes of a challenge
	UserHandleBytes = 64 // random bytes of a user handle
	MaxAccountBytes = 256
	MaxDisplayBytes = 256
	MinNonceBytes   = 16 // host nonce, once decoded
	MaxNonceBytes   = 64
)

// PurgeInterval is the least time between two purges of expired tickets and
// challenges; a purge runs when a challenge is issued.
const PurgeInterval = 30 * time.Second

// uuidDashes are the byte offsets of the dashes of an RFC 9562 UUID string
// (8-4-4-4-12 hexadecimal digits).
var uuidDashes = []int{4, 6, 8, 10}

// publicKey is the only credential type of WebAuthn.
const publicKey = string(protocol.PublicKeyCredentialType)

// Config is what the ceremonies need from the service configuration.
type Config struct {
	RPID          string
	RPName        string
	Origins       []string // normalised
	ChallengeTTL  time.Duration
	TicketTTL     time.Duration
	MaxChallenges int
	Now           func() time.Time
	Logger        *slog.Logger
}

// Result describes a verified ceremony, for the result token.
type Result struct {
	Account           string
	Origin            string
	CredentialID      []byte
	UserVerified      bool
	BackupEligible    bool
	BackupState       bool
	AAGUID            []byte
	AttestationFormat string // registration only
	Nonce             string // authentication only
}

// Ceremonies issues options and verifies responses.
type Ceremonies struct {
	cfg  Config
	st   store.Store
	wa   *webauthn.WebAuthn
	last atomic.Int64 // time of the last purge, Unix milliseconds
}

// credParams: ES256, EdDSA, RS256, in this order of preference.
var credParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// New returns the ceremonies for a configuration and a store.
func New(cfg Config, st store.Store) (*Ceremonies, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     cfg.Origins,
	})
	if err != nil {
		return nil, err
	}
	for _, o := range cfg.Origins {
		if !withinRPID(o, cfg.RPID) {
			cfg.Logger.Warn("origin outside the RP ID: it needs Related Origin Requests on the RP ID's domain", "origin", o, "rp_id", cfg.RPID)
		}
	}
	return &Ceremonies{cfg: cfg, st: st, wa: wa}, nil
}

// HashTicket is the SHA-256 of the ticket string. The ticket itself is never
// stored: only this hash is, as the lookup key of the ticket's row, and it
// cannot give the ticket back.
func HashTicket(ticket string) []byte {
	h := sha256.Sum256([]byte(ticket))
	return h[:]
}

// IssueTicket creates a registration ticket for account.
func (c *Ceremonies) IssueTicket(ctx context.Context, account, displayName string) (string, error) {
	if account == "" || len(account) > MaxAccountBytes {
		return "", refuse(CodeInvalidRequest, "account must be 1 to %d bytes", MaxAccountBytes)
	}
	if displayName == "" || len(displayName) > MaxDisplayBytes {
		return "", refuse(CodeInvalidRequest, "display name must be 1 to %d bytes", MaxDisplayBytes)
	}
	ticket := b64(random(TicketBytes))
	err := c.st.CreateTicket(ctx, store.Ticket{
		Hash: HashTicket(ticket), Account: account, DisplayName: displayName,
		ExpiresAt: c.cfg.Now().Add(c.cfg.TicketTTL),
	})
	return ticket, err
}

// newChallenge purges expired rows now and then, enforces the cap on live
// challenges, and stores a fresh challenge.
func (c *Ceremonies) newChallenge(ctx context.Context, ch store.Challenge) ([]byte, error) {
	now := c.cfg.Now()
	if last := c.last.Load(); now.UnixMilli()-last > PurgeInterval.Milliseconds() || now.UnixMilli() < last {
		c.last.Store(now.UnixMilli())
		if err := c.st.Purge(ctx, now); err != nil {
			return nil, err
		}
	}
	n, err := c.st.LiveChallenges(ctx, now)
	if err != nil {
		return nil, err
	}
	if n >= c.cfg.MaxChallenges {
		return nil, refuse(CodeUnavailable, "%d live challenges, cap %d", n, c.cfg.MaxChallenges)
	}
	ch.Value = random(ChallengeBytes)
	ch.ExpiresAt = now.Add(c.cfg.ChallengeTTL)
	if err := c.st.PutChallenge(ctx, ch); err != nil {
		return nil, err
	}
	return ch.Value, nil
}

type descriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// RegistrationOptions consumes a ticket and returns the creation options.
func (c *Ceremonies) RegistrationOptions(ctx context.Context, ticket string) ([]byte, error) {
	t, err := c.st.ConsumeTicket(ctx, HashTicket(ticket))
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(CodeTicketInvalid, "unknown or used ticket")
	} else if err != nil {
		return nil, err
	}
	if !c.cfg.Now().Before(t.ExpiresAt) {
		return nil, refuse(CodeTicketInvalid, "expired ticket")
	}
	handle, err := c.st.EnsureUser(ctx, t.Account, random(UserHandleBytes), c.cfg.Now())
	if err != nil {
		return nil, err
	}
	existing, err := c.st.CredentialsOf(ctx, handle)
	if err != nil {
		return nil, err
	}
	exclude := []descriptor{}
	for _, cr := range existing {
		exclude = append(exclude, descriptor{Type: publicKey, ID: b64(cr.ID), Transports: cr.Transports})
	}
	challenge, err := c.newChallenge(ctx, store.Challenge{Kind: store.KindRegistration, Account: t.Account, UserHandle: handle})
	if err != nil {
		return nil, err
	}
	params := []map[string]any{}
	for _, p := range credParams {
		params = append(params, map[string]any{"type": publicKey, "alg": p.Algorithm})
	}
	return json.Marshal(map[string]any{"publicKey": map[string]any{
		"rp":                 map[string]string{"id": c.cfg.RPID, "name": c.cfg.RPName},
		"user":               map[string]string{"id": b64(handle), "name": t.DisplayName, "displayName": t.DisplayName},
		"challenge":          b64(challenge),
		"pubKeyCredParams":   params,
		"timeout":            c.cfg.ChallengeTTL.Milliseconds(),
		"excludeCredentials": exclude,
		"authenticatorSelection": map[string]any{
			"residentKey":        protocol.ResidentKeyRequirementRequired,
			"requireResidentKey": true,
			"userVerification":   protocol.VerificationRequired,
		},
		"attestation": protocol.PreferDirectAttestation,
	}})
}

// AuthenticationOptions returns the request options for a host nonce.
func (c *Ceremonies) AuthenticationOptions(ctx context.Context, nonce string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) < MinNonceBytes || len(raw) > MaxNonceBytes {
		return nil, refuse(CodeInvalidRequest, "nonce must be base64url of %d to %d bytes", MinNonceBytes, MaxNonceBytes)
	}
	challenge, err := c.newChallenge(ctx, store.Challenge{Kind: store.KindAuthentication, Nonce: nonce})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge":        b64(challenge),
		"timeout":          c.cfg.ChallengeTTL.Milliseconds(),
		"rpId":             c.cfg.RPID,
		"allowCredentials": []descriptor{},
		"userVerification": protocol.VerificationRequired,
	}})
}

// takeChallenge checks the client data before any cryptography: exact origin,
// no cross-origin frame, then the single-use challenge of the right kind.
func (c *Ceremonies) takeChallenge(ctx context.Context, cd protocol.CollectedClientData, kind store.Kind) (store.Challenge, error) {
	value, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(value) == 0 {
		return store.Challenge{}, refuse(CodeChallengeInvalid, "malformed challenge")
	}
	ch, err := c.st.TakeChallenge(ctx, value)
	if errors.Is(err, store.ErrNotFound) {
		return ch, refuse(CodeChallengeInvalid, "unknown or used challenge")
	} else if err != nil {
		return ch, err
	}
	if ch.Kind != kind {
		return ch, refuse(CodeChallengeInvalid, "challenge issued for %s, used for %s", ch.Kind, kind)
	}
	if !c.cfg.Now().Before(ch.ExpiresAt) {
		return ch, refuse(CodeChallengeInvalid, "expired challenge")
	}
	if !slices.Contains(c.cfg.Origins, cd.Origin) {
		return ch, refuse(CodeVerificationFailed, "origin %q not allowed", cd.Origin)
	}
	if cd.CrossOrigin || cd.TopOrigin != "" {
		return ch, refuse(CodeVerificationFailed, "ceremony in a cross-origin frame (top origin %q)", cd.TopOrigin)
	}
	return ch, nil
}

func (c *Ceremonies) session(challenge, userHandle []byte) webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:        b64(challenge),
		RelyingPartyID:   c.cfg.RPID,
		UserID:           userHandle,
		UserVerification: protocol.VerificationRequired,
		CredParams:       credParams,
	}
}

// VerifyRegistration verifies a RegistrationResponseJSON and stores the
// credential.
func (c *Ceremonies) VerifyRegistration(ctx context.Context, body []byte) (Result, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return Result{}, refuse(CodeVerificationFailed, "parse: %v", detail(err))
	}
	cd := parsed.Response.CollectedClientData
	ch, err := c.takeChallenge(ctx, cd, store.KindRegistration)
	if err != nil {
		return Result{}, err
	}
	u := &user{id: ch.UserHandle, name: ch.Account}
	cred, err := c.wa.CreateCredential(u, c.session(ch.Value, ch.UserHandle), parsed)
	if err != nil {
		return Result{}, refuse(CodeVerificationFailed, "registration: %v", detail(err))
	}
	if !cred.Flags.UserVerified {
		return Result{}, refuse(CodeVerificationFailed, "user not verified")
	}
	now := c.cfg.Now()
	var transports []string
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	err = c.st.AddCredential(ctx, store.Credential{
		ID: cred.ID, UserHandle: ch.UserHandle, PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount, Transports: transports, AAGUID: cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		AttestationFormat: cred.AttestationFormat, CreatedAt: now, LastUsedAt: now,
	})
	if errors.Is(err, store.ErrConflict) {
		return Result{}, refuse(CodeVerificationFailed, "credential ID already registered")
	} else if errors.Is(err, store.ErrNotFound) {
		return Result{}, refuse(CodeChallengeInvalid, "account deleted during the ceremony")
	} else if err != nil {
		return Result{}, err
	}
	return Result{
		Account: ch.Account, Origin: cd.Origin, CredentialID: cred.ID, UserVerified: true,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		AAGUID: cred.Authenticator.AAGUID, AttestationFormat: cred.AttestationFormat,
	}, nil
}

// VerifyAuthentication verifies an AuthenticationResponseJSON.
func (c *Ceremonies) VerifyAuthentication(ctx context.Context, body []byte) (Result, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return Result{}, refuse(CodeVerificationFailed, "parse: %v", detail(err))
	}
	cd := parsed.Response.CollectedClientData
	ch, err := c.takeChallenge(ctx, cd, store.KindAuthentication)
	if err != nil {
		return Result{}, err
	}
	stored, err := c.st.Credential(ctx, parsed.RawID)
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, refuse(CodeCredentialUnknown, "unknown credential")
	} else if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(stored.UserHandle, parsed.Response.UserHandle) {
		return Result{}, refuse(CodeCredentialUnknown, "credential does not belong to this user handle")
	}
	account, err := c.st.Account(ctx, stored.UserHandle)
	if err != nil {
		return Result{}, err
	}
	u := &user{id: stored.UserHandle, name: account, creds: []webauthn.Credential{{
		ID: stored.ID, PublicKey: stored.PublicKey, AttestationFormat: stored.AttestationFormat,
		Flags:         webauthn.CredentialFlags{BackupEligible: stored.BackupEligible, BackupState: stored.BackupState},
		Authenticator: webauthn.Authenticator{AAGUID: stored.AAGUID, SignCount: stored.SignCount},
	}}}
	cred, err := c.wa.ValidateDiscoverableLogin(func(_, _ []byte) (webauthn.User, error) { return u, nil },
		c.session(ch.Value, nil), parsed)
	if err != nil {
		return Result{}, refuse(CodeVerificationFailed, "authentication: %v", detail(err))
	}
	flags := parsed.Response.AuthenticatorData.Flags
	if !flags.HasUserVerified() {
		return Result{}, refuse(CodeVerificationFailed, "user not verified")
	}
	count := parsed.Response.AuthenticatorData.Counter
	if stored.SignCount > 0 && count <= stored.SignCount {
		return Result{}, refuse(CodeVerificationFailed, "signature counter went from %d to %d: possible clone", stored.SignCount, count)
	}
	err = c.st.RecordUse(ctx, stored.ID, stored.SignCount, count, flags.HasBackupState(), c.cfg.Now())
	if errors.Is(err, store.ErrConflict) {
		return Result{}, refuse(CodeVerificationFailed, "concurrent use of the credential")
	} else if err != nil {
		return Result{}, err
	}
	return Result{
		Account: account, Origin: cd.Origin, CredentialID: cred.ID, UserVerified: true,
		BackupEligible: flags.HasBackupEligible(), BackupState: flags.HasBackupState(),
		AAGUID: stored.AAGUID, Nonce: ch.Nonce,
	}, nil
}

// user adapts a stored account to go-webauthn.
type user struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.name }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// UUID formats an AAGUID; all zeros when absent.
func UUID(b []byte) string {
	if len(b) != store.AAGUIDBytes {
		b = make([]byte, store.AAGUIDBytes)
	}
	const hex = "0123456789abcdef"
	var sb strings.Builder
	for i, x := range b {
		if slices.Contains(uuidDashes, i) {
			sb.WriteByte('-')
		}
		sb.WriteByte(hex[x>>4])
		sb.WriteByte(hex[x&0xf])
	}
	return sb.String()
}

// detail extracts go-webauthn's developer information for the log.
func detail(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return strings.TrimSpace(pe.Details + " " + pe.DevInfo)
	}
	return err.Error()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | options and verification of both ceremonies                   |
