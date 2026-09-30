package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// A deleted user's passkeys go with them: kept, they would be the second
// factor of whoever is added under the same name later.
func TestDeletingAUserDeletesTheirPasskeys(t *testing.T) {
	backends := map[string]string{
		"memory":  "memory://",
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "passkeys.db"),
	}
	for name, uri := range backends {
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			for _, owner := range []string{"alice", "bob"} {
				if err := s.SaveUser(&User{Subject: owner, Provider: "simple", Name: owner}); err != nil {
					t.Fatal(err)
				}
				if err := s.AddPasskey(&Passkey{ID: "key-of-" + owner, Owner: owner, Name: "key", Data: []byte("{}"), CreatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}

			if err := s.DeleteUser("alice"); err != nil {
				t.Fatal(err)
			}

			if left, err := s.ListPasskeys("alice"); err != nil || len(left) != 0 {
				t.Errorf("alice's passkeys after deleting her: %v, %v", left, err)
			}
			if left, err := s.ListPasskeys("bob"); err != nil || len(left) != 1 {
				t.Errorf("bob's passkeys after deleting alice: %v, %v", left, err)
			}
		})
	}
}
