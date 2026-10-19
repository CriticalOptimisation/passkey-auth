// Package sqlite implements store.Store on a single SQLite file.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: no cgo, static binary

	"github.com/CriticalOptimisation/passkey-auth/internal/store"
)

//go:embed schema.sql
var schema string

// Store is a store.Store backed by SQLite.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// busyTimeoutMS is how long, in milliseconds, a statement waits for a lock
// held by another connection to the same file before it fails.
const busyTimeoutMS = 5000

// maxOpenConns: see Open.
const maxOpenConns = 1

// Open opens or creates the database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	// The path goes into a file: URI, where %, ? and # are special.
	escaped := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)",
		escaped, busyTimeoutMS)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writes, which SQLite does anyway, and makes
	// DELETE ... RETURNING the single atomic step the store contract needs.
	db.SetMaxOpenConns(maxOpenConns)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close checkpoints the write-ahead log and closes the database.
func (s *Store) Close() error {
	_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return s.db.Close()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v) }

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (s *Store) CreateTicket(ctx context.Context, t store.Ticket) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tickets (hash, account, display_name, expires_at) VALUES (?, ?, ?, ?)`,
		t.Hash, t.Account, t.DisplayName, ms(t.ExpiresAt))
	return conflict(err)
}

func (s *Store) ConsumeTicket(ctx context.Context, hash []byte) (store.Ticket, error) {
	t := store.Ticket{Hash: hash}
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM tickets WHERE hash = ? RETURNING account, display_name, expires_at`, hash).
		Scan(&t.Account, &t.DisplayName, &exp)
	t.ExpiresAt = fromMS(exp)
	return t, notFound(err)
}

func (s *Store) PutChallenge(ctx context.Context, c store.Challenge) error {
	handle := c.UserHandle
	if handle == nil {
		handle = []byte{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO challenges (value, kind, expires_at, account, user_handle, nonce) VALUES (?, ?, ?, ?, ?, ?)`,
		c.Value, string(c.Kind), ms(c.ExpiresAt), c.Account, handle, c.Nonce)
	return conflict(err)
}

func (s *Store) TakeChallenge(ctx context.Context, value []byte) (store.Challenge, error) {
	c := store.Challenge{Value: value}
	var kind string
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM challenges WHERE value = ? RETURNING kind, expires_at, account, user_handle, nonce`, value).
		Scan(&kind, &exp, &c.Account, &c.UserHandle, &c.Nonce)
	c.Kind, c.ExpiresAt = store.Kind(kind), fromMS(exp)
	return c, notFound(err)
}

func (s *Store) LiveChallenges(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM challenges WHERE expires_at > ?`, ms(now)).Scan(&n)
	return n, err
}

func (s *Store) Purge(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at <= ?`, ms(now)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM tickets WHERE expires_at <= ?`, ms(now))
	return err
}

func (s *Store) EnsureUser(ctx context.Context, account string, candidate []byte, now time.Time) ([]byte, error) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO users (account, user_handle, created_at) VALUES (?, ?, ?) ON CONFLICT (account) DO NOTHING`,
		account, candidate, ms(now)); err != nil {
		return nil, err
	}
	var handle []byte
	err := s.db.QueryRowContext(ctx, `SELECT user_handle FROM users WHERE account = ?`, account).Scan(&handle)
	return handle, notFound(err)
}

func (s *Store) Account(ctx context.Context, userHandle []byte) (string, error) {
	var account string
	err := s.db.QueryRowContext(ctx, `SELECT account FROM users WHERE user_handle = ?`, userHandle).Scan(&account)
	return account, notFound(err)
}

func (s *Store) AddCredential(ctx context.Context, c store.Credential) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO credentials
		(id, user_handle, public_key, sign_count, transports, aaguid, backup_eligible, backup_state, attestation_format, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserHandle, c.PublicKey, int64(c.SignCount), strings.Join(c.Transports, ","), aaguid(c.AAGUID),
		b2i(c.BackupEligible), b2i(c.BackupState), c.AttestationFormat, ms(c.CreatedAt), ms(c.LastUsedAt))
	return conflict(err)
}

const credentialColumns = `id, user_handle, public_key, sign_count, transports, aaguid, backup_eligible, backup_state, attestation_format, created_at, last_used_at`

func scanCredential(row interface{ Scan(...any) error }) (store.Credential, error) {
	var c store.Credential
	var count, created, used, be, bs int64
	var transports string
	err := row.Scan(&c.ID, &c.UserHandle, &c.PublicKey, &count, &transports, &c.AAGUID, &be, &bs, &c.AttestationFormat, &created, &used)
	if err != nil {
		return c, notFound(err)
	}
	c.SignCount = uint32(count)
	if transports != "" {
		c.Transports = strings.Split(transports, ",")
	}
	c.BackupEligible, c.BackupState = be != 0, bs != 0
	c.CreatedAt, c.LastUsedAt = fromMS(created), fromMS(used)
	return c, nil
}

func (s *Store) Credential(ctx context.Context, id []byte) (store.Credential, error) {
	return scanCredential(s.db.QueryRowContext(ctx, `SELECT `+credentialColumns+` FROM credentials WHERE id = ?`, id))
}

func (s *Store) CredentialsOf(ctx context.Context, userHandle []byte) ([]store.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialColumns+` FROM credentials WHERE user_handle = ? ORDER BY created_at, id`, userHandle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) RecordUse(ctx context.Context, id []byte, oldCount, newCount uint32, backupState bool, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credentials SET sign_count = ?, backup_state = ?, last_used_at = ? WHERE id = ? AND sign_count = ?`,
		int64(newCount), b2i(backupState), ms(at), id, int64(oldCount))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return store.ErrConflict
	}
	return nil
}

func aaguid(b []byte) []byte {
	if len(b) == 0 {
		return make([]byte, store.AAGUIDBytes)
	}
	return b
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func conflict(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	}
	return err
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | SQLite implementation of the store                            |
