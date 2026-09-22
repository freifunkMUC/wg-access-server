package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// freshDatabases returns a URI per backend for an empty database of its own,
// dropped again when the test ends. Postgres and MySQL need a server
// (WG_TEST_POSTGRES_URI, WG_TEST_MYSQL_URI) and are left out without one.
func freshDatabases(t *testing.T) map[string]string {
	t.Helper()
	name := fmt.Sprintf("wgtest_%d", time.Now().UnixNano())
	uris := map[string]string{
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "fresh.db"),
	}
	if uri := os.Getenv("WG_TEST_POSTGRES_URI"); uri != "" {
		uris["postgres"] = createDatabase(t, "pgx", uri, name)
	}
	if uri := os.Getenv("WG_TEST_MYSQL_URI"); uri != "" {
		uris["mysql"] = createDatabase(t, "mysql", uri, name)
	}
	return uris
}

func createDatabase(t *testing.T, driver string, uri string, name string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}

	var dsn string
	if driver == "mysql" {
		password, _ := u.User.Password()
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/", u.User.Username(), password, u.Host)
	} else {
		dsn = uri
	}
	admin, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

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

func openStorage(t *testing.T, uri string) *SQLStorage {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSqlStorage(u)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// statementLog records every statement gorm runs.
type statementLog struct {
	gormlogger.Interface
	mu         sync.Mutex
	statements []string
}

func (l *statementLog) LogMode(gormlogger.LogLevel) gormlogger.Interface { return l }

func (l *statementLog) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	statement, _ := fc()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statements = append(l.statements, statement)
}

var schemaChange = regexp.MustCompile(`(?i)^\s*(CREATE|ALTER|DROP|RENAME)\b`)

// The migrations and the models must describe the same schema: a model that
// gained a field without a migration would find no column for it. After all
// migrations, gorm must see nothing left to change about the models.
func TestMigrationsMatchTheModels(t *testing.T) {
	for backend, uri := range freshDatabases(t) {
		t.Run(backend, func(t *testing.T) {
			s := openStorage(t, uri)

			log := &statementLog{Interface: gormlogger.Discard}
			if err := s.db.Session(&gorm.Session{Logger: log}).AutoMigrate(&Device{}, &APIToken{}); err != nil {
				t.Fatal(err)
			}
			for _, statement := range log.statements {
				if schemaChange.MatchString(statement) {
					t.Errorf("the models differ from what the migrations created - add a migration for:\n%s", statement)
				}
			}
		})
	}
}

// An installation from before migrations existed has the tables but no
// record of how they came about. It must be taken over as it is.
func TestUpgradeFromBeforeMigrations(t *testing.T) {
	for backend, uri := range freshDatabases(t) {
		t.Run(backend, func(t *testing.T) {
			// what the previous version did on every start
			old := openRaw(t, uri)
			if err := old.AutoMigrate(&deviceV1{}); err != nil {
				t.Fatal(err)
			}
			created := time.Now().Truncate(time.Second)
			if err := old.Create(&deviceV1{
				Owner: "alice", Name: "laptop", PublicKey: testKey("upgrade"),
				Address: "10.44.0.2/32", CreatedAt: created,
			}).Error; err != nil {
				t.Fatal(err)
			}

			s := openStorage(t, uri)

			device, err := s.Get("alice", "laptop")
			if err != nil {
				t.Fatalf("the device did not survive the upgrade: %v", err)
			}
			if device.Address != "10.44.0.2/32" || !device.CreatedAt.Equal(created) {
				t.Errorf("device = %+v, want it unchanged", device)
			}
			if ids := appliedMigrations(t, s.db); strings.Join(ids, ",") != "0001_devices,0002_api_tokens" {
				t.Errorf("applied = %v, want every migration", ids)
			}
		})
	}
}

// Starting a second time finds nothing to do.
func TestMigrationsRunOnce(t *testing.T) {
	db := openRaw(t, "sqlite3://"+filepath.Join(t.TempDir(), "once.db"))
	calls := 0
	list := []migration{{id: "0001_count", apply: func(*gorm.DB) error { calls++; return nil }}}

	for range 3 {
		if err := runMigrations(db, list); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("the migration ran %d times, want once", calls)
	}
}

// A migration that fails is not recorded, so the next start tries again - and
// the ones after it do not run on a schema that is not what they expect.
func TestFailedMigrationIsNotRecorded(t *testing.T) {
	db := openRaw(t, "sqlite3://"+filepath.Join(t.TempDir(), "failed.db"))
	laterRan := false
	list := []migration{
		{id: "0001_ok", apply: func(*gorm.DB) error { return nil }},
		{id: "0002_broken", apply: func(*gorm.DB) error { return errors.New("boom") }},
		{id: "0003_later", apply: func(*gorm.DB) error { laterRan = true; return nil }},
	}

	err := runMigrations(db, list)
	if err == nil || !strings.Contains(err.Error(), "0002_broken") {
		t.Fatalf("err = %v, want the failing migration named", err)
	}
	if laterRan {
		t.Error("a migration ran after one that failed")
	}
	if ids := appliedMigrations(t, db); strings.Join(ids, ",") != "0001_ok" {
		t.Errorf("applied = %v, want only 0001_ok", ids)
	}
}

// A database a newer version has migrated may no longer fit this version's
// models. Refusing to start is better than writing rows that do not fit.
func TestRefusesADatabaseFromANewerVersion(t *testing.T) {
	uri := "sqlite3://" + filepath.Join(t.TempDir(), "newer.db")
	if err := openStorage(t, uri).Close(); err != nil {
		t.Fatal(err)
	}

	db := openRaw(t, uri)
	if err := db.Create(&schemaMigration{ID: "9999_from_the_future", AppliedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(uri)
	err := NewSqlStorage(u).Open()
	if err == nil || !strings.Contains(err.Error(), "9999_from_the_future") || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("err = %v, want a refusal naming the unknown migration", err)
	}
}

// Replicas sharing a database start at the same time during a rollout. Only
// one at a time may change the schema - migrate, and on Postgres replace the
// triggers the watcher relies on. Without the lock this fails with "table
// already exists", "trigger already exists" or a deadlock.
func TestConcurrentStartsMigrateOnce(t *testing.T) {
	for backend, uri := range freshDatabases(t) {
		if backend == "sqlite3" {
			continue // a single-instance backend
		}
		t.Run(backend, func(t *testing.T) {
			u, _ := url.Parse(uri)
			const replicas = 6
			errs := make(chan error, replicas)
			var wg sync.WaitGroup
			for range replicas {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := NewSqlStorage(u)
					err := s.Open()
					if err == nil {
						err = s.Close()
					}
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Errorf("a replica failed to start: %v", err)
				}
			}

			if ids := appliedMigrations(t, openRaw(t, uri)); len(ids) != len(migrations) {
				t.Errorf("applied = %v, want each migration once", ids)
			}
		})
	}
}

// openRaw opens the database without running the migrations.
func openRaw(t *testing.T, uri string) *gorm.DB {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSqlStorage(u)
	dialector, err := s.dialector()
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if raw, err := db.DB(); err == nil {
			_ = raw.Close()
		}
	})
	return db
}

func appliedMigrations(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var applied []schemaMigration
	if err := db.Order("id").Find(&applied).Error; err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, a := range applied {
		ids = append(ids, a.ID)
	}
	return ids
}
