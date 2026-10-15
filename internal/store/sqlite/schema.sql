-- passkey-auth schema. Public material only: see docs/security.md.
CREATE TABLE IF NOT EXISTS users (
	account     TEXT    PRIMARY KEY,
	user_handle BLOB    NOT NULL UNIQUE,
	created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS credentials (
	id                 BLOB    PRIMARY KEY,
	user_handle        BLOB    NOT NULL REFERENCES users (user_handle),
	public_key         BLOB    NOT NULL,
	sign_count         INTEGER NOT NULL,
	transports         TEXT    NOT NULL,
	aaguid             BLOB    NOT NULL,
	backup_eligible    INTEGER NOT NULL,
	backup_state       INTEGER NOT NULL,
	attestation_format TEXT    NOT NULL,
	created_at         INTEGER NOT NULL,
	last_used_at       INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS credentials_by_user ON credentials (user_handle);

-- Tickets are stored by their SHA-256 hash only.
CREATE TABLE IF NOT EXISTS tickets (
	hash         BLOB    PRIMARY KEY,
	account      TEXT    NOT NULL,
	display_name TEXT    NOT NULL,
	expires_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS tickets_by_expiry ON tickets (expires_at);

CREATE TABLE IF NOT EXISTS challenges (
	value       BLOB    PRIMARY KEY,
	kind        TEXT    NOT NULL,
	expires_at  INTEGER NOT NULL,
	account     TEXT    NOT NULL,
	user_handle BLOB    NOT NULL,
	nonce       TEXT    NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS challenges_by_expiry ON challenges (expires_at);
