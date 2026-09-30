package websessions

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// Signing in has to work on the storage backends people actually run, not
// only on the in-memory one the rest of these tests use. The id Create
// generates is a UUID string - 36 characters - and the column it goes into
// was varchar(32) until migration 0012: every session was refused on
// Postgres and MySQL, so nobody could sign in at all, while memory and
// SQLite stayed green because neither enforces a column width.
//
// This test exists to make the real generator meet a real column. An id that
// outgrows the column again fails here rather than in a deployment.
func TestSigningInOnEveryBackend(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "sessions.db"),
		"postgres": freshDatabase(t, "pgx", os.Getenv("WG_TEST_POSTGRES_URI")),
		"mysql":    freshDatabase(t, "mysql", os.Getenv("WG_TEST_MYSQL_URI")),
	}

	for name, uri := range backends {
		if uri == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := storage.NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			owner := "alice-" + name
			m := New(s, time.Hour)
			id := signIn(t, m, owner)

			// the session is really there, and really names her
			identity, err := m.Identity(id)
			if err != nil {
				t.Fatalf("the session just created cannot be read back: %v", err)
			}
			if identity.Subject != owner {
				t.Errorf("identity = %+v, want %s", identity, owner)
			}

			// ... and the id it was stored under was not cut short
			listed, err := m.List(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 {
				t.Fatalf("%d sessions listed, want the one just created", len(listed))
			}
			if len(listed[0].ID) != 36 {
				t.Errorf("the stored id is %d characters (%q), want the full 36", len(listed[0].ID), listed[0].ID)
			}
		})
	}
}

// freshDatabase gives the run its own database, so migrations are applied
// from nothing every time - including the widening this fix adds. It mirrors
// the helper the storage tests use.
func freshDatabase(t *testing.T, driver string, uri string) string {
	t.Helper()
	if uri == "" {
		return ""
	}

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}

	dsn := uri
	if driver == "mysql" {
		password, _ := u.User.Password()
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/", u.User.Username(), password, u.Host)
	}
	admin, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	name := fmt.Sprintf("wgtest_websessions_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		drop := "DROP DATABASE " + name
		if driver == "pgx" {
			drop += " WITH (FORCE)"
		}
		if _, err := admin.Exec(drop); err != nil {
			t.Logf("failed to drop the test database %s: %v", name, err)
		}
	})

	fresh := *u
	fresh.Path = "/" + name
	return fresh.String()
}
