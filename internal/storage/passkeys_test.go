package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A person has several passkeys - one to carry, one in a drawer - so the
// storage keeps them per person and hands back the newest first.
func TestPasskeys(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "passkeys.db"),
		"postgres": freshPostgres(t),
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

			owner := "passkey-owner-" + name
			other := "passkey-other-" + name
			t.Cleanup(func() {
				for _, id := range []string{owner + "-1", owner + "-2", other + "-1"} {
					_ = s.DeletePasskey(owner, id)
					_ = s.DeletePasskey(other, id)
				}
				_ = s.DeleteUser(owner)
			})

			older := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
			newer := time.Now().UTC().Truncate(time.Second)
			for _, passkey := range []*Passkey{
				{ID: owner + "-1", Owner: owner, Name: "A key", Data: []byte(`{"id":"one"}`), CreatedAt: older},
				{ID: owner + "-2", Owner: owner, Name: "My phone", Data: []byte(`{"id":"two"}`), CreatedAt: newer},
				{ID: other + "-1", Owner: other, Name: "Not theirs", Data: []byte(`{"id":"three"}`), CreatedAt: newer},
			} {
				if err := s.AddPasskey(passkey); err != nil {
					t.Fatal(err)
				}
			}

			listed, err := s.ListPasskeys(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 2 {
				t.Fatalf("listed %d passkeys, want two", len(listed))
			}
			if listed[0].ID != owner+"-2" {
				t.Errorf("first is %q, want the newest", listed[0].ID)
			}
			if string(listed[0].Data) != `{"id":"two"}` {
				t.Errorf("data = %q, want what was stored", listed[0].Data)
			}

			// a sign-in writes the credential back with its new count and a
			// time, which has to survive
			used := time.Now().UTC().Truncate(time.Second)
			stored, err := s.GetPasskey(owner + "-2")
			if err != nil {
				t.Fatal(err)
			}
			stored.Data = []byte(`{"id":"two","signCount":7}`)
			stored.LastUsedAt = &used
			if err := s.UpdatePasskey(stored); err != nil {
				t.Fatal(err)
			}
			if stored, err = s.GetPasskey(owner + "-2"); err != nil {
				t.Fatal(err)
			}
			if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(used) {
				t.Errorf("last used = %v, want %v", stored.LastUsedAt, used)
			}
			if string(stored.Data) != `{"id":"two","signCount":7}` {
				t.Errorf("data = %q, want the credential as it was written back", stored.Data)
			}
			// ... and nothing was added by writing it again
			if listed, _ = s.ListPasskeys(owner); len(listed) != 2 {
				t.Errorf("%d passkeys after writing one back, want two", len(listed))
			}

			// a credential id somebody already has is refused, whoever asks:
			// an authenticator picks its own ids, so this is what stops one
			// person taking another's passkey away
			err = s.AddPasskey(&Passkey{
				ID: owner + "-2", Owner: other, Name: "taken over", Data: []byte(`{"id":"x"}`),
				CreatedAt: time.Now().UTC(),
			})
			if !errors.Is(err, ErrPasskeyExists) {
				t.Errorf("err = %v, want ErrPasskeyExists", err)
			}
			if taken, err := s.GetPasskey(owner + "-2"); err != nil {
				t.Fatal(err)
			} else if taken.Owner != owner || taken.Name != "My phone" {
				t.Errorf("the passkey changed hands: %+v", taken)
			}

			// ... and writing one back is owner-scoped as well
			if err := s.UpdatePasskey(&Passkey{
				ID: owner + "-2", Owner: other, Name: "taken over", Data: []byte(`{"id":"x"}`),
			}); !errors.Is(err, ErrPasskeyNotFound) {
				t.Errorf("err = %v, want ErrPasskeyNotFound", err)
			}
			if taken, err := s.GetPasskey(owner + "-2"); err != nil {
				t.Fatal(err)
			} else if taken.Owner != owner || taken.Name != "My phone" {
				t.Errorf("the passkey was written by somebody else: %+v", taken)
			}

			// somebody else's is not theirs to delete
			if err := s.DeletePasskey(owner, other+"-1"); !errors.Is(err, ErrPasskeyNotFound) {
				t.Errorf("err = %v, want ErrPasskeyNotFound", err)
			}
			if _, err := s.GetPasskey(other + "-1"); err != nil {
				t.Error("somebody else's passkey was deleted")
			}

			if err := s.DeletePasskey(owner, owner+"-1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetPasskey(owner + "-1"); !errors.Is(err, ErrPasskeyNotFound) {
				t.Errorf("err = %v, want ErrPasskeyNotFound after deleting it", err)
			}
		})
	}
}

// An authenticator picks its own credential id, so whoever registers picks
// what is written. Taking an id that somebody else holds would take their
// passkey - and with it their second factor - away from them.
func TestAPasskeyCannotBeTakenFromSomebodyElse(t *testing.T) {
	s := NewMemoryStorage()
	id := "the-credential-id"

	if err := s.AddPasskey(&Passkey{
		ID: id, Owner: "bob", Name: "bob's key", Data: []byte(`{"id":"b"}`), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	err := s.AddPasskey(&Passkey{
		ID: id, Owner: "alice", Name: "alice's key", Data: []byte(`{"id":"a"}`), CreatedAt: time.Now(),
	})
	if !errors.Is(err, ErrPasskeyExists) {
		t.Fatalf("err = %v, want ErrPasskeyExists", err)
	}

	bobs, err := s.ListPasskeys("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(bobs) != 1 || bobs[0].Name != "bob's key" {
		t.Errorf("bob's passkeys = %+v, want the one he registered", bobs)
	}
	if alices, _ := s.ListPasskeys("alice"); len(alices) != 0 {
		t.Errorf("alice has %d passkeys, want none", len(alices))
	}

	// ... and writing one back is no way round it either
	if err := s.UpdatePasskey(&Passkey{
		ID: id, Owner: "alice", Name: "alice's key", Data: []byte(`{"id":"a"}`),
	}); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("err = %v, want ErrPasskeyNotFound", err)
	}
	if bobs, _ = s.ListPasskeys("bob"); len(bobs) != 1 || bobs[0].Name != "bob's key" {
		t.Errorf("bob's passkeys = %+v, want his own", bobs)
	}
}

// The challenge lives on the user row, and a login has to leave it alone.
func TestWebauthnChallenge(t *testing.T) {
	s := NewMemoryStorage()
	if err := s.SaveUser(&User{Subject: "alice", Provider: "simple"}); err != nil {
		t.Fatal(err)
	}

	until := time.Now().Add(5 * time.Minute).UTC()
	if err := s.SetWebauthnChallenge("alice", `{"challenge":"abc"}`, &until); err != nil {
		t.Fatal(err)
	}

	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.WebauthnChallenge != `{"challenge":"abc"}` || user.WebauthnChallengeUntil == nil {
		t.Fatalf("user = %+v, want the challenge", user)
	}

	// clearing it is how an answered exchange is closed
	if err := s.SetWebauthnChallenge("alice", "", nil); err != nil {
		t.Fatal(err)
	}
	if user, err = s.GetUser("alice"); err != nil {
		t.Fatal(err)
	}
	if user.WebauthnChallenge != "" || user.WebauthnChallengeUntil != nil {
		t.Errorf("user = %+v, want no challenge", user)
	}

	// and somebody who never signed in has nowhere to keep one
	if err := s.SetWebauthnChallenge("nobody", "x", &until); err == nil {
		t.Error("a challenge was kept for a user that does not exist")
	}
}
