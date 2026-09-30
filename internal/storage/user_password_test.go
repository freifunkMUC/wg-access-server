package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A password somebody set for themselves lives next to the rest of what is
// known about them - and must survive their next sign-in, which rewrites that
// row with what their provider said.
func TestUserPassword(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "password.db"),
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

			subject := "password-user-" + name
			t.Cleanup(func() { _ = s.DeleteUser(subject) })

			if err := s.SaveUser(&User{
				Subject: subject, Provider: "simple", Name: "Alice", LastLogin: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			user, err := s.GetUser(subject)
			if err != nil {
				t.Fatal(err)
			}
			if user.PasswordHash != "" || user.PasswordFrom != "" {
				t.Errorf("a new user already has a password: %+v", user)
			}

			if err := s.SetUserPassword(subject, "the-hash", "the-configured-entry"); err != nil {
				t.Fatal(err)
			}
			if user, err = s.GetUser(subject); err != nil {
				t.Fatal(err)
			}
			if user.PasswordHash != "the-hash" || user.PasswordFrom != "the-configured-entry" {
				t.Errorf("user = %+v, want the password that was set", user)
			}

			// signing in again writes the row from what the provider said,
			// which carries no password
			if err := s.SaveUser(&User{
				Subject: subject, Provider: "simple", Name: "Alice Example", LastLogin: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}
			if user, err = s.GetUser(subject); err != nil {
				t.Fatal(err)
			}
			if user.PasswordHash != "the-hash" {
				t.Error("signing in again forgot the password the user had set")
			}
			if user.Name != "Alice Example" {
				t.Errorf("name = %q, want what the provider said at the last login", user.Name)
			}

			// an empty hash hands them back to the configuration
			if err := s.SetUserPassword(subject, "", ""); err != nil {
				t.Fatal(err)
			}
			if user, err = s.GetUser(subject); err != nil {
				t.Fatal(err)
			}
			if user.PasswordHash != "" || user.PasswordFrom != "" {
				t.Errorf("user = %+v, want no password", user)
			}
		})
	}
}

// A password for somebody who never signed in has nowhere to go: the row is
// the user, and writing one would invent an account.
func TestUserPasswordForSomebodyUnknown(t *testing.T) {
	s := NewMemoryStorage()
	if err := s.SetUserPassword("nobody", "hash", "entry"); err == nil {
		t.Error("a password was stored for a user that does not exist")
	}
}
