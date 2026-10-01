package storage

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// The statements gorm logs at debug level must not carry the values: they
// include preshared keys.
func TestSQLDebugLogHasNoValues(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()
	level := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(level)

	s, err := NewStorage("sqlite3://" + filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := s.Save(&Device{Owner: "alice", Name: "laptop", PublicKey: "public", PresharedKey: secret, Address: "10.44.0.2/32"}); err != nil {
		t.Fatal(err)
	}

	logged := false
	for _, entry := range hook.AllEntries() {
		if entry.Data["module"] == "gorm" {
			logged = true
		}
		if strings.Contains(entry.Message, secret) {
			t.Fatalf("the debug log carries the preshared key: %s", entry.Message)
		}
		for field, value := range entry.Data {
			if strings.Contains(fmt.Sprint(value), secret) {
				t.Fatalf("the debug log carries the preshared key in %q", field)
			}
		}
	}
	if !logged {
		t.Fatal("gorm logged no statement, so the test checked nothing")
	}
}

// A password with spaces, quotes or backslashes must reach Postgres as it is.
func TestPostgresConnectionStringQuotesValues(t *testing.T) {
	for _, password := range []string{"a b", "it's", `back\slash`, "x' host=evil", "=="} {
		u := &url.URL{Scheme: "postgres", User: url.UserPassword("wg user", password), Host: "localhost:5432", Path: "/wgas", RawQuery: "sslmode=disable"}
		config, err := pq.NewConfig(pgconn(u))
		if err != nil {
			t.Fatalf("password %q: %v", password, err)
		}
		if config.Password != password || config.User != "wg user" || config.Host != "localhost" || config.Database != "wgas" {
			t.Errorf("password %q became user=%q password=%q host=%q db=%q", password, config.User, config.Password, config.Host, config.Database)
		}
	}

	// without a port, the default applies as before
	u := &url.URL{Scheme: "postgres", User: url.UserPassword("wgas", "secret"), Host: "db.example.com", Path: "/wgas"}
	config, err := pq.NewConfig(pgconn(u))
	if err != nil {
		t.Fatal(err)
	}
	if config.Port != 5432 || config.Host != "db.example.com" {
		t.Errorf("without a port: host=%q port=%d, want db.example.com:5432", config.Host, config.Port)
	}
}
