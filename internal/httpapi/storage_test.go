package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

// The database holds public material only: no signing key, no authenticator
// private key, no usable registration ticket.
func TestDatabaseHoldsPublicMaterialOnly(t *testing.T) {
	e := newEnv(t)
	roaming := testauthn.New(testauthn.Roaming, origin)
	platform := testauthn.New(testauthn.Platform, origin)
	e.register(roaming, "account-1")
	e.register(platform, "account-2")
	mustOK(t, e.assertion(roaming, newNonce(), testauthn.Overrides{}))
	mustOK(t, e.assertion(platform, newNonce(), testauthn.Overrides{}))
	pending := e.ticket("account-3", "Pending") // issued, never used

	e.closeDB()
	var db []byte
	for _, suffix := range []string{"", "-wal", "-journal"} {
		b, err := os.ReadFile(e.dbPath + suffix)
		if err == nil {
			db = append(db, b...)
		} else if suffix == "" {
			t.Fatal(err)
		}
	}
	if len(db) == 0 {
		t.Fatal("empty database")
	}

	secrets := map[string][]byte{
		"signing key seed":    e.key.Seed(),
		"signing private key": e.key,
		"pending ticket":      []byte(pending),
	}
	for i, k := range append(roaming.PrivateKeyBytes(), platform.PrivateKeyBytes()...) {
		secrets["authenticator private key "+string(rune('A'+i))] = k
	}
	for name, s := range secrets {
		for _, form := range [][]byte{s, []byte(base64.RawURLEncoding.EncodeToString(s)), []byte(base64.StdEncoding.EncodeToString(s)), []byte(hex.EncodeToString(s))} {
			if bytes.Contains(db, form) {
				t.Errorf("database contains the %s", name)
			}
		}
	}

	// Sanity check: the public material is there.
	id := roaming.Latest().ID
	if !bytes.Contains(db, id) && !bytes.Contains(db, []byte(testauthn.B64(id))) {
		t.Error("credential ID not found: the scan reads the wrong file")
	}
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | database holds public material only                           |
