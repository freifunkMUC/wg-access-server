package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenStorage(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "tokens.db"),
		"postgres": os.Getenv("WG_TEST_POSTGRES_URI"),
		"mysql":    os.Getenv("WG_TEST_MYSQL_URI"),
	}

	for name, uri := range backends {
		if uri == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			owner := "token-owner-" + name
			other := "token-other-" + name
			t.Cleanup(func() {
				_ = s.DeleteTokensForOwner(owner)
				_ = s.DeleteTokensForOwner(other)
			})

			// whole seconds: MySQL stores no fractions
			created := time.Now().Truncate(time.Second)
			expires := created.Add(time.Hour)
			token := &APIToken{
				ID: "id-" + name, Owner: owner, Name: "backup script",
				Hash: testKey("hash-" + name), Identity: `{"Subject":"` + owner + `"}`,
				CreatedAt: created, ExpiresAt: &expires,
			}
			if err := s.SaveToken(token); err != nil {
				t.Fatal(err)
			}
			if err := s.SaveToken(&APIToken{
				ID: "other-" + name, Owner: other, Name: "ci",
				Hash: testKey("other-" + name), CreatedAt: created,
			}); err != nil {
				t.Fatal(err)
			}

			found, err := s.GetTokenByHash(token.Hash)
			if err != nil {
				t.Fatal(err)
			}
			if found.ID != token.ID || found.Owner != owner || found.Identity != token.Identity {
				t.Errorf("found %+v, want %+v", found, token)
			}
			if found.ExpiresAt == nil || !found.ExpiresAt.Equal(expires) {
				t.Errorf("expires at %v, want %v", found.ExpiresAt, expires)
			}
			if found.LastUsedAt != nil {
				t.Errorf("a new token was used at %v", found.LastUsedAt)
			}

			if _, err := s.GetTokenByHash(testKey("unknown")); !errors.Is(err, ErrTokenNotFound) {
				t.Errorf("unknown hash: err = %v, want ErrTokenNotFound", err)
			}

			// the same hash twice would make a secret ambiguous
			if err := s.SaveToken(&APIToken{
				ID: "dup-" + name, Owner: owner, Name: "dup", Hash: token.Hash, CreatedAt: created,
			}); err == nil {
				t.Error("a second token with the same hash was stored")
			}

			used := created.Add(time.Minute)
			if err := s.TouchToken(token.ID, used); err != nil {
				t.Fatal(err)
			}
			if found, _ := s.GetToken(token.ID); found == nil || found.LastUsedAt == nil || !found.LastUsedAt.Equal(used) {
				t.Errorf("last used at %v, want %v", found, used)
			}

			if mine, _ := s.ListTokens(owner); len(mine) != 1 {
				t.Errorf("owner has %d tokens, want 1", len(mine))
			}
			if all, _ := s.ListTokens(""); len(all) < 2 {
				t.Errorf("listing all tokens returned %d, want at least 2", len(all))
			}

			if err := s.DeleteToken(token.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteToken(token.ID); !errors.Is(err, ErrTokenNotFound) {
				t.Errorf("deleting twice: err = %v, want ErrTokenNotFound", err)
			}
			if _, err := s.GetTokenByHash(token.Hash); !errors.Is(err, ErrTokenNotFound) {
				t.Errorf("a revoked token is still found: %v", err)
			}

			if err := s.DeleteTokensForOwner(other); err != nil {
				t.Fatal(err)
			}
			if left, _ := s.ListTokens(other); len(left) != 0 {
				t.Errorf("%d tokens of the user are left", len(left))
			}
		})
	}
}
