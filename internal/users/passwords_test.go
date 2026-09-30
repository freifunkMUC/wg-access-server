package users

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// htpasswd entries, as an admin writes them into the config file
func entry(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func matches(configured string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(configured), []byte(password)) == nil
}

// passwords returns the changer over a storage that already knows the user,
// together with that storage.
func passwords(t *testing.T, configured string) (*Passwords, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	if err := s.SaveUser(&storage.User{Subject: "alice", Provider: "simple", Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	return NewPasswords(s, func(subject string) (string, bool) {
		if subject == "alice" {
			return configured, true
		}
		return "", false
	}, matches), s
}

func TestChangingThePassword(t *testing.T) {
	configured := entry(t, "the-configured-one")
	p, s := passwords(t, configured)

	if err := p.Change("alice", "the-configured-one", "a-longer-new-one"); err != nil {
		t.Fatal(err)
	}

	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	// stored as a hash, and against the entry it was set from
	if user.PasswordHash == "" || user.PasswordHash == "a-longer-new-one" {
		t.Errorf("password hash = %q, want a hash of the new password", user.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("a-longer-new-one")) != nil {
		t.Error("the stored hash does not match the new password")
	}
	if user.PasswordFrom != configured {
		t.Errorf("password from = %q, want the configured entry", user.PasswordFrom)
	}

	// ... and from now on that is the password
	if err := p.Change("alice", "a-longer-new-one", "another-new-one"); err != nil {
		t.Errorf("the new password is not the password: %v", err)
	}
	// the configured one no longer is
	if err := p.Change("alice", "the-configured-one", "yet-another-one"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("err = %v, want ErrWrongPassword: the configured password still works", err)
	}
}

func TestChangingNeedsTheCurrentPassword(t *testing.T) {
	p, s := passwords(t, entry(t, "the-configured-one"))

	if err := p.Change("alice", "not-it", "a-longer-new-one"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}

	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "" {
		t.Error("a refused change stored a password anyway")
	}
}

// Somebody the configuration does not list has no password here - an OIDC
// user, or a name that is not in the config file at all.
func TestChangingForSomebodyWithNoPasswordHere(t *testing.T) {
	p, _ := passwords(t, entry(t, "the-configured-one"))

	if err := p.Change("bob", "whatever", "a-longer-new-one"); !errors.Is(err, ErrNoPasswordHere) {
		t.Fatalf("err = %v, want ErrNoPasswordHere", err)
	}
}

// The config file is where an admin takes a password back: change the entry
// there, and what the user set stops counting. Without this an admin could
// hand out a password and never revoke it.
func TestAnAdminChangingTheConfigTakesThePasswordBack(t *testing.T) {
	first := entry(t, "the-configured-one")
	p, s := passwords(t, first)

	if err := p.Change("alice", "the-configured-one", "a-longer-new-one"); err != nil {
		t.Fatal(err)
	}

	// the admin edits the config file: a different entry for the same user
	second := entry(t, "what-the-admin-set-now")
	changed := NewPasswords(s, func(string) (string, bool) { return second, true }, matches)

	if err := changed.Change("alice", "a-longer-new-one", "something-else-now"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("err = %v, want ErrWrongPassword: the stored password outlived the config change", err)
	}
	if err := changed.Change("alice", "what-the-admin-set-now", "something-else-now"); err != nil {
		t.Errorf("the configured password does not work after the change: %v", err)
	}
}

// Signing in writes the user row again. A password the user set has to
// survive that, or it would last until their next login.
func TestSigningInAgainKeepsTheStoredPassword(t *testing.T) {
	p, s := passwords(t, entry(t, "the-configured-one"))
	if err := p.Change("alice", "the-configured-one", "a-longer-new-one"); err != nil {
		t.Fatal(err)
	}

	// what recordLogin does on every sign-in
	if err := s.SaveUser(&storage.User{Subject: "alice", Provider: "simple", Name: "alice"}); err != nil {
		t.Fatal(err)
	}

	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash == "" {
		t.Fatal("signing in again forgot the password")
	}
	if err := p.Change("alice", "a-longer-new-one", "another-new-one"); err != nil {
		t.Errorf("the password no longer works after signing in again: %v", err)
	}
}
