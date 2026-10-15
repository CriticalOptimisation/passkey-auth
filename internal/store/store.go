// Package store defines the persistence the service needs: registration
// tickets, ceremony challenges, user handles and credentials. It holds public
// material only (see docs/security.md).
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound: no such ticket, challenge, account or credential.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict: a duplicate key, or a row changed since it was read.
	ErrConflict = errors.New("store: conflict")
)

// Kind is the ceremony a challenge was issued for.
type Kind string

const (
	KindRegistration   Kind = "registration"
	KindAuthentication Kind = "authentication"
)

// Ticket is a one-time registration ticket. Only its SHA-256 hash is stored.
type Ticket struct {
	Hash        []byte
	Account     string
	DisplayName string
	ExpiresAt   time.Time
}

// Challenge is a single-use ceremony challenge and the context to finish it.
type Challenge struct {
	Value     []byte
	Kind      Kind
	ExpiresAt time.Time
	// Registration only.
	Account    string
	UserHandle []byte
	// Authentication only.
	Nonce string
}

// Credential is a registered public key credential.
type Credential struct {
	ID                []byte
	UserHandle        []byte
	PublicKey         []byte // COSE_Key
	SignCount         uint32
	Transports        []string
	AAGUID            []byte
	BackupEligible    bool
	BackupState       bool
	AttestationFormat string
	CreatedAt         time.Time
	LastUsedAt        time.Time
}

// Store is implemented by every storage backend; storetest holds the
// contract tests.
type Store interface {
	CreateTicket(ctx context.Context, t Ticket) error
	// ConsumeTicket deletes the ticket and returns it, expired or not.
	ConsumeTicket(ctx context.Context, hash []byte) (Ticket, error)

	PutChallenge(ctx context.Context, c Challenge) error
	// TakeChallenge deletes the challenge and returns it, expired or not, in
	// one atomic step: of two concurrent callers, one gets ErrNotFound.
	TakeChallenge(ctx context.Context, value []byte) (Challenge, error)
	// LiveChallenges counts the challenges that expire after now.
	LiveChallenges(ctx context.Context, now time.Time) (int, error)
	// Purge deletes the tickets and challenges that expired before now.
	Purge(ctx context.Context, now time.Time) error

	// EnsureUser returns the user handle of account, recording candidate as
	// its handle if the account has none yet.
	EnsureUser(ctx context.Context, account string, candidate []byte, now time.Time) ([]byte, error)
	// Account returns the account of a user handle.
	Account(ctx context.Context, userHandle []byte) (string, error)

	// AddCredential fails with ErrConflict if the credential ID exists.
	AddCredential(ctx context.Context, c Credential) error
	Credential(ctx context.Context, id []byte) (Credential, error)
	CredentialsOf(ctx context.Context, userHandle []byte) ([]Credential, error)
	// RecordUse stores the new counter and backup state, provided the counter
	// still holds the value read before the ceremony; otherwise ErrConflict.
	RecordUse(ctx context.Context, id []byte, oldCount, newCount uint32, backupState bool, at time.Time) error

	Close() error
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | storage contract and domain types                             |
