package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A session has to survive a restart and be readable by every replica: it is
// what a request carries instead of an identity.
func TestSessionStorage(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "sessions.db"),
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

			owner := "sessions-test-" + name
			t.Cleanup(func() { _, _ = s.DeleteSessionsForOwner(owner) })

			created := time.Now().UTC().Truncate(time.Second)
			session := &Session{
				ID: owner + "-1", Owner: owner, Hash: owner + "-hash-1",
				Identity: `{"Subject":"alice"}`, UserAgent: "a browser", RemoteAddr: "198.51.100.7",
				CreatedAt: created, ExpiresAt: created.Add(time.Hour), LastSeenAt: created,
			}
			if err := s.SaveSession(session); err != nil {
				t.Fatal(err)
			}

			stored, err := s.GetSessionByHash(session.Hash)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Owner != owner || stored.Identity != session.Identity || stored.UserAgent != "a browser" {
				t.Errorf("stored session = %+v, want %+v", stored, session)
			}
			if stored.Expired(created) {
				t.Error("a session that has an hour left is reported as expired")
			}
			if !stored.Expired(created.Add(time.Hour)) {
				t.Error("a session is not reported as expired at its expiry")
			}

			// a hash nobody knows is not an error, it is an answer
			if _, err := s.GetSessionByHash("no-such-hash"); err == nil {
				t.Error("a hash that names no session was found")
			}

			if err := s.TouchSession(session.ID, created.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if stored, err = s.GetSessionByHash(session.Hash); err != nil {
				t.Fatal(err)
			} else if !stored.LastSeenAt.UTC().After(created) {
				t.Errorf("last seen = %v, want it moved forward", stored.LastSeenAt)
			}

			// a second session of the same person, and one of somebody else
			second := *session
			second.ID, second.Hash, second.CreatedAt = owner+"-2", owner+"-hash-2", created.Add(time.Minute)
			if err := s.SaveSession(&second); err != nil {
				t.Fatal(err)
			}
			other := *session
			other.ID, other.Hash, other.Owner = owner+"-other", owner+"-hash-other", owner+"-somebody-else"
			if err := s.SaveSession(&other); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = s.DeleteSessionsForOwner(other.Owner) })

			listed, err := s.ListSessions(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 2 || listed[0].ID != second.ID {
				t.Errorf("listed %d sessions, want two with the newest first: %+v", len(listed), listed)
			}

			if err := s.DeleteSession(session.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetSessionByHash(session.Hash); err == nil {
				t.Error("the session still exists after being deleted")
			}

			// one session of this owner is already gone, so this reports the
			// one that is left - not everything that ever was
			ended, err := s.DeleteSessionsForOwner(owner)
			if err != nil {
				t.Fatal(err)
			}
			if ended != 1 {
				t.Errorf("ended %d sessions, want the one that was left", ended)
			}
			if listed, err = s.ListSessions(owner); err != nil {
				t.Fatal(err)
			} else if len(listed) != 0 {
				t.Errorf("%d sessions of the user are left", len(listed))
			}
			if _, err := s.GetSessionByHash(other.Hash); err != nil {
				t.Errorf("somebody else's session was deleted: %v", err)
			}
		})
	}
}

// Sessions nobody can use any more must not pile up forever.
func TestDeleteExpiredSessions(t *testing.T) {
	s := NewMemoryStorage()
	now := time.Now()

	for i, expires := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour)} {
		if err := s.SaveSession(&Session{
			ID: string(rune('a' + i)), Owner: "alice", Hash: string(rune('a' + i)),
			CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: expires,
		}); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.DeleteExpiredSessions(now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed %d sessions, want the one that expired", removed)
	}
	if listed, _ := s.ListSessions("alice"); len(listed) != 1 {
		t.Errorf("%d sessions left, want the one that has not expired", len(listed))
	}
}
