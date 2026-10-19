// Package storetest is the contract every store.Store backend must pass.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/store"
)

// Run runs the contract against stores returned by open, one per subtest.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000)

	t.Run("ticket is single-use", func(t *testing.T) {
		s := open(t)
		tk := store.Ticket{Hash: []byte("h1"), Account: "a", DisplayName: "A", ExpiresAt: now.Add(time.Minute)}
		if err := s.CreateTicket(ctx, tk); err != nil {
			t.Fatal(err)
		}
		got, err := s.ConsumeTicket(ctx, tk.Hash)
		if err != nil || got.Account != "a" || got.DisplayName != "A" || !got.ExpiresAt.Equal(tk.ExpiresAt) {
			t.Fatalf("consume: %+v, %v", got, err)
		}
		if _, err := s.ConsumeTicket(ctx, tk.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second consume: %v, want ErrNotFound", err)
		}
		if err := s.CreateTicket(ctx, tk); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateTicket(ctx, tk); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate ticket: %v, want ErrConflict", err)
		}
	})

	t.Run("challenge is taken once under concurrency", func(t *testing.T) {
		s := open(t)
		c := store.Challenge{Value: []byte("c1"), Kind: store.KindAuthentication, ExpiresAt: now.Add(time.Minute), Nonce: "n"}
		if err := s.PutChallenge(ctx, c); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		won := 0
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.TakeChallenge(ctx, c.Value)
				if err == nil {
					mu.Lock()
					won++
					mu.Unlock()
					if got.Kind != store.KindAuthentication || got.Nonce != "n" {
						t.Errorf("taken: %+v", got)
					}
				} else if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("take: %v", err)
				}
			}()
		}
		wg.Wait()
		if won != 1 {
			t.Fatalf("%d takers won, want 1", won)
		}
	})

	t.Run("registration challenge keeps its context", func(t *testing.T) {
		s := open(t)
		c := store.Challenge{Value: []byte("c2"), Kind: store.KindRegistration, ExpiresAt: now, Account: "a", UserHandle: []byte{1, 2, 3}}
		if err := s.PutChallenge(ctx, c); err != nil {
			t.Fatal(err)
		}
		got, err := s.TakeChallenge(ctx, c.Value)
		if err != nil || got.Account != "a" || !bytes.Equal(got.UserHandle, c.UserHandle) || got.Kind != store.KindRegistration {
			t.Fatalf("taken: %+v, %v", got, err)
		}
	})

	t.Run("expired rows are counted out and purged", func(t *testing.T) {
		s := open(t)
		for i, exp := range []time.Time{now.Add(-time.Second), now, now.Add(time.Second)} {
			if err := s.PutChallenge(ctx, store.Challenge{Value: []byte{byte(i)}, Kind: store.KindAuthentication, ExpiresAt: exp}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CreateTicket(ctx, store.Ticket{Hash: []byte("old"), Account: "a", DisplayName: "A", ExpiresAt: now.Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
		if n, err := s.LiveChallenges(ctx, now); err != nil || n != 1 {
			t.Fatalf("live = %d, %v; want 1", n, err)
		}
		if err := s.Purge(ctx, now); err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if _, err := s.TakeChallenge(ctx, []byte{byte(i)}); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("expired challenge %d survived the purge", i)
			}
		}
		if _, err := s.TakeChallenge(ctx, []byte{2}); err != nil {
			t.Errorf("live challenge purged: %v", err)
		}
		if _, err := s.ConsumeTicket(ctx, []byte("old")); !errors.Is(err, store.ErrNotFound) {
			t.Error("expired ticket survived the purge")
		}
	})

	t.Run("user handle is stable per account", func(t *testing.T) {
		s := open(t)
		h1, err := s.EnsureUser(ctx, "a", []byte("first"), now)
		if err != nil || string(h1) != "first" {
			t.Fatalf("first: %q, %v", h1, err)
		}
		h2, err := s.EnsureUser(ctx, "a", []byte("second"), now)
		if err != nil || string(h2) != "first" {
			t.Fatalf("second: %q, %v; want the first handle", h2, err)
		}
		if acc, err := s.Account(ctx, h1); err != nil || acc != "a" {
			t.Fatalf("account: %q, %v", acc, err)
		}
		if _, err := s.Account(ctx, []byte("nobody")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown handle: %v", err)
		}
	})

	t.Run("credentials round-trip and record use", func(t *testing.T) {
		s := open(t)
		h, err := s.EnsureUser(ctx, "a", []byte("handle"), now)
		if err != nil {
			t.Fatal(err)
		}
		c := store.Credential{ID: []byte("cred"), UserHandle: h, PublicKey: []byte("cose"), SignCount: 3,
			Transports: []string{"usb", "nfc"}, AAGUID: bytes.Repeat([]byte{7}, 16), BackupEligible: true,
			AttestationFormat: "packed", CreatedAt: now, LastUsedAt: now}
		if err := s.AddCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := s.AddCredential(ctx, c); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate credential: %v, want ErrConflict", err)
		}
		got, err := s.Credential(ctx, c.ID)
		if err != nil || got.SignCount != 3 || len(got.Transports) != 2 || !got.BackupEligible || got.BackupState ||
			got.AttestationFormat != "packed" || !bytes.Equal(got.AAGUID, c.AAGUID) || !got.CreatedAt.Equal(now) {
			t.Fatalf("credential: %+v, %v", got, err)
		}
		later := now.Add(time.Hour)
		if err := s.RecordUse(ctx, c.ID, 3, 4, true, later); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordUse(ctx, c.ID, 3, 5, true, later); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale counter: %v, want ErrConflict", err)
		}
		got, _ = s.Credential(ctx, c.ID)
		if got.SignCount != 4 || !got.BackupState || !got.LastUsedAt.Equal(later) {
			t.Fatalf("after use: %+v", got)
		}
		list, err := s.CredentialsOf(ctx, h)
		if err != nil || len(list) != 1 {
			t.Fatalf("credentials of: %d, %v", len(list), err)
		}
		if _, err := s.Credential(ctx, []byte("none")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown credential: %v", err)
		}
	})
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | contract tests for any store backend                          |
