package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seedDevices(t *testing.T, s Storage, owner string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := s.Save(&Device{
			Owner: owner, Name: name, PublicKey: testKey(owner + name),
			Address: "10.44.0.2/32", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeleteForOwner(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "delete.db"),
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

			owner := "delete-owner-" + name
			other := "delete-other-" + name
			t.Cleanup(func() {
				_, _ = s.DeleteForOwner(owner)
				_, _ = s.DeleteForOwner(other)
			})

			events := &collector{}
			s.OnDelete(events.record)

			seedDevices(t, s, owner, "laptop", "phone", "tablet")
			seedDevices(t, s, other, "desktop")

			deleted, err := s.DeleteForOwner(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(deleted) != 3 {
				t.Errorf("reported %d deleted devices, want 3", len(deleted))
			}

			if left, _ := s.List(owner); len(left) != 0 {
				t.Errorf("%d devices of the user are still stored", len(left))
			}
			if left, _ := s.List(other); len(left) != 1 {
				t.Errorf("another user's devices were touched: %d left, want 1", len(left))
			}

			// every removed device has to be reported, that is how the
			// WireGuard peers go away
			deadline := time.Now().Add(5 * time.Second)
			for len(events.names()) < 3 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if got := events.names(); len(got) != 3 {
				t.Errorf("got %d delete events (%q), want 3", len(got), got)
			}
		})
	}
}

func TestDeleteForOwnerWithoutDevices(t *testing.T) {
	s := NewMemoryStorage()
	deleted, err := s.DeleteForOwner("nobody")
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Errorf("reported %d deleted devices, want none", len(deleted))
	}
}

// The promise is all or nothing. A delete that fails halfway through must
// leave the user with every device - and must not report any of them as gone,
// because that would tear down WireGuard peers for devices that still exist.
func TestDeleteForOwnerRollsBack(t *testing.T) {
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}

	s, err := NewStorage(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner := "delete-rollback"
	t.Cleanup(func() { _, _ = s.DeleteForOwner(owner) })
	seedDevices(t, s, owner, "laptop", "boom", "tablet")

	// a trigger that refuses to let one of them go
	db, err := s.(*SQLStorage).sqlDB()
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE OR REPLACE FUNCTION wg_test_refuse_delete() RETURNS TRIGGER AS $$
		 BEGIN IF OLD.name = 'boom' THEN RAISE EXCEPTION 'refusing to delete %', OLD.name; END IF; RETURN OLD; END; $$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS wg_test_refuse_delete ON devices`,
		`CREATE TRIGGER wg_test_refuse_delete BEFORE DELETE ON devices FOR EACH ROW EXECUTE PROCEDURE wg_test_refuse_delete()`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS wg_test_refuse_delete ON devices`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS wg_test_refuse_delete()`)
	})

	events := &collector{}
	s.OnDelete(events.record)

	if _, err := s.DeleteForOwner(owner); err == nil {
		t.Fatal("the deletion succeeded although one device could not be deleted")
	}

	left, err := s.List(owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 3 {
		t.Errorf("%d devices left, want all 3 - the transaction did not roll back", len(left))
	}

	// events travel through the database, so give them a moment to not arrive
	time.Sleep(500 * time.Millisecond)
	if got := events.names(); len(got) != 0 {
		t.Errorf("got %d delete events (%q) for devices that are still there", len(got), got)
	}
}
