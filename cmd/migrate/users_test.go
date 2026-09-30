package migrate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// Moving to another backend must keep what people set for themselves: a
// password of their own, their second factor and their passkeys. Without
// them everybody signs in with the configured password alone afterwards.
func TestCopyAllKeepsTheUsers(t *testing.T) {
	src := openForTest(t, "memory://")
	destURI := "sqlite3://" + filepath.Join(t.TempDir(), "dest.db")
	dest := openForTest(t, destURI)

	enabled := time.Now().UTC().Truncate(time.Second)
	if err := src.SaveUser(&storage.User{Subject: "alice", Provider: "simple", Name: "alice", LastLogin: enabled}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetUserPassword("alice", "$2a$10$own-password-hash", "$2a$10$configured"); err != nil {
		t.Fatal(err)
	}
	state := storage.TOTPState{Secret: "JBSWY3DPEHPK3PXP", EnabledAt: &enabled, Recovery: "h1,h2", LastStep: 42}
	if err := src.SetUserTOTP("alice", state); err != nil {
		t.Fatal(err)
	}
	if err := src.AddPasskey(&storage.Passkey{ID: "cred", Owner: "alice", Name: "key", Data: []byte("{}"), CreatedAt: enabled}); err != nil {
		t.Fatal(err)
	}

	// twice, the way somebody runs it again after a failure
	for i := 0; i < 2; i++ {
		if err := copyAll(src, dest); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	user, err := dest.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "$2a$10$own-password-hash" || user.PasswordFrom != "$2a$10$configured" {
		t.Errorf("password = %q from %q", user.PasswordHash, user.PasswordFrom)
	}
	if !user.TwoFactorEnabled() || user.TotpSecret != state.Secret || user.TotpRecovery != state.Recovery || user.TotpLastStep != state.LastStep {
		t.Errorf("second factor = %+v", user.TOTP())
	}
	passkeys, err := dest.ListPasskeys("alice")
	if err != nil || len(passkeys) != 1 {
		t.Errorf("passkeys = %v, %v", passkeys, err)
	}
}
