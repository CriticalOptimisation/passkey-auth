package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/store"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/sqlite"
	"github.com/CriticalOptimisation/passkey-auth/internal/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

// Paths with characters that are special in a file: URI open the right file.
func TestPathWithURICharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a%61?b#c.db")
	s, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "a%61?b#c.db"))
	if len(matches) != 1 {
		t.Fatalf("database not created at %s", path)
	}
}

// Reopening keeps the data.
func TestReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	s, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureUser(ctx, "a", []byte("h"), time.UnixMilli(1_800_000_000_000)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if acc, err := s.Account(ctx, []byte("h")); err != nil || acc != "a" {
		t.Fatalf("after reopen: %q, %v", acc, err)
	}
}
