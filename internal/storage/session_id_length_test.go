package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The id the application actually writes is a UUID string, which is 36
// characters. The tests above used short ids of their own making, so the
// column was never asked to hold a real one.
func TestSessionIDOfTheShapeTheApplicationWrites(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "sessions.db"),
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

			id := uuid.NewString()
			if len(id) != 36 {
				t.Fatalf("a uuid string is %d characters, expected 36", len(id))
			}
			now := time.Now().UTC().Truncate(time.Second)
			err = s.SaveSession(&Session{
				ID: id, Owner: "alice", Hash: "hash-" + name,
				Identity: `{"subject":"alice"}`, CreatedAt: now,
				ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
			})
			if err != nil {
				t.Fatalf("a session with a real id could not be stored: %v", err)
			}
			t.Cleanup(func() { _ = s.DeleteSession(id) })

			got, err := s.GetSessionByHash("hash-" + name)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != id {
				t.Errorf("id = %q, want %q - it was stored truncated", got.ID, id)
			}
		})
	}
}

// An installation that is already running has the narrow column and rows in
// it. The widening has to take both over: the sessions that are there keep
// working, and a new one of the real length fits.
func TestUpgradeWidensTheSessionID(t *testing.T) {
	for backend, uri := range freshDatabases(t) {
		t.Run(backend, func(t *testing.T) {
			db := openRaw(t, uri)

			// the world as it was before this fix: every migration up to and
			// including 0011, which is where the column was varchar(32)
			old := migrations[:len(migrations)-1]
			if old[len(old)-1].id != "0011_totp_last_step" {
				t.Fatalf("the migration before the widening is %q, not 0011 - this test needs updating", old[len(old)-1].id)
			}
			if err := runMigrations(db, old); err != nil {
				t.Fatal(err)
			}

			// a session such an installation would hold: an id that still
			// fitted, because nothing longer could be written
			now := time.Now().UTC().Truncate(time.Second)
			short := "0123456789abcdef0123456789abcdef"
			if err := db.Create(&sessionV1{
				ID: short, Owner: "alice", Hash: "old-hash",
				Identity: `{"subject":"alice"}`, CreatedAt: now,
				ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
			}).Error; err != nil {
				t.Fatal(err)
			}

			// ... and now the upgrade
			if err := runMigrations(db, migrations); err != nil {
				t.Fatalf("the widening failed: %v", err)
			}

			// the session that was there is untouched
			kept := &Session{}
			if err := db.Where("id = ?", short).First(kept).Error; err != nil {
				t.Fatalf("the session from before the upgrade is gone: %v", err)
			}
			if kept.Owner != "alice" || kept.Hash != "old-hash" {
				t.Errorf("session = %+v, want alice's as it was", kept)
			}

			// ... and a full-length id fits now
			full := uuid.NewString()
			if err := db.Create(&Session{
				ID: full, Owner: "alice", Hash: "new-hash",
				Identity: `{"subject":"alice"}`, CreatedAt: now,
				ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
			}).Error; err != nil {
				t.Fatalf("a full-length id still does not fit after the upgrade: %v", err)
			}
		})
	}
}
