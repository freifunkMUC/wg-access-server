package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// What the server remembers about somebody has to survive a restart, on every
// backend that claims to persist anything: the firewall rules and the device
// list are built when nobody is signed in.
func TestUserStorage(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "users.db"),
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

			subject := "users-test-" + name
			t.Cleanup(func() { _ = s.DeleteUser(subject) })

			// told apart from a database that cannot be read: a sign-in
			// is checked against the user, and an error that says nothing
			// must not let it through
			if _, err := s.GetUser(subject); !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("GetUser of somebody who never signed in = %v, want %v", err, ErrUserNotFound)
			}

			// the seconds are what every backend keeps: MySQL stores no
			// fraction, and the driver is configured not to add one
			login := time.Now().UTC().Truncate(time.Second)
			user := &User{
				Subject: subject, Provider: "oidc",
				Name: "Alice Example", Email: "alice@example.com",
				Policies: "contractors, staff", LastLogin: login,
			}
			if err := s.SaveUser(user); err != nil {
				t.Fatal(err)
			}

			stored, err := s.GetUser(subject)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Name != user.Name || stored.Email != user.Email || stored.Provider != user.Provider {
				t.Errorf("stored user = %+v, want %+v", stored, user)
			}
			if policies := stored.PolicyList(); len(policies) != 2 || policies[0] != "contractors" || policies[1] != "staff" {
				t.Errorf("policies = %v, want contractors and staff", policies)
			}
			if !stored.LastLogin.UTC().Equal(login) {
				t.Errorf("last login = %v, want %v", stored.LastLogin.UTC(), login)
			}

			// signing in again replaces what was there, it does not fail on
			// the key and it does not add a second row
			// ... and a sign-in that puts somebody in no policy any more has
			// to clear the column, not leave the old one standing
			second := login.Add(time.Hour)
			if err := s.SaveUser(&User{
				Subject: subject, Provider: "oidc",
				Name: "Alice Elsewhere", Email: "alice@example.com", LastLogin: second,
			}); err != nil {
				t.Fatal(err)
			}
			stored, err = s.GetUser(subject)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Name != "Alice Elsewhere" || !stored.LastLogin.UTC().Equal(second) {
				t.Errorf("the second sign-in did not replace the first: %+v", stored)
			}
			if policies := stored.PolicyList(); len(policies) != 0 {
				t.Errorf("policies = %v, want them gone after a sign-in without any", policies)
			}

			var found int
			users, err := s.Users()
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range users {
				if u.Subject == subject {
					found++
				}
			}
			if found != 1 {
				t.Errorf("the user is listed %d times, want once", found)
			}

			if err := s.DeleteUser(subject); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetUser(subject); err == nil {
				t.Error("the user is still there after being deleted")
			}
			// deleting somebody who is not there is not an error: whoever
			// deletes a user cannot know whether they ever signed in
			if err := s.DeleteUser(subject); err != nil {
				t.Errorf("deleting a user that is gone failed: %v", err)
			}
		})
	}
}
