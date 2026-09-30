package users

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// twoFactor returns the second factor over a storage that knows alice, whose
// configured password is the one below.
func twoFactor(t *testing.T) (*TwoFactor, storage.Storage) {
	t.Helper()
	p, s := passwords(t, entry(t, "the-configured-one"))
	return NewTwoFactor(s, p, "wg-access-server"), s
}

// enrol does what the UI does: start, read the secret, confirm with a code.
func enrol(t *testing.T, tf *TwoFactor, subject string) []string {
	t.Helper()
	secret, uri, err := tf.Start(subject, subject+"@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, secret) {
		t.Fatalf("the URI does not carry the secret: %q", uri)
	}

	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := tf.Confirm(subject, code)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func TestEnrollingAndSigningInWithACode(t *testing.T) {
	tf, s := twoFactor(t)

	if tf.Enabled("alice") {
		t.Fatal("a fresh account already has a second factor")
	}

	// starting alone does not turn it on: somebody who walks away from the
	// QR code must not be locked out
	secret, _, err := tf.Start("alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tf.Enabled("alice") {
		t.Error("an unconfirmed enrolment asks for codes")
	}

	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := tf.Confirm("alice", code)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodes {
		t.Errorf("%d recovery codes, want %d", len(codes), recoveryCodes)
	}
	if !tf.Enabled("alice") {
		t.Fatal("the second factor is not on after confirming it")
	}

	// the code from the app signs in
	if !tf.Check("alice", code) {
		t.Error("the code from the app was refused")
	}
	if tf.Check("alice", "000000") {
		t.Error("a made-up code was accepted")
	}

	// the secret is stored as the app needs it, the recovery codes are not
	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.TotpSecret != secret {
		t.Error("the stored secret is not the one the app got")
	}
	for _, shown := range codes {
		if strings.Contains(user.TotpRecovery, normalizeRecoveryCode(shown)) {
			t.Error("a recovery code is stored as it was shown, not hashed")
		}
	}
}

// A code is good for three time steps, which is a window an attacker who
// caught one can use as well. RFC 6238 asks that a code signs somebody in
// once, and only once.
func TestACodeSignsInOnlyOnce(t *testing.T) {
	tf, _ := twoFactor(t)
	secret, _, err := tf.Start("alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tf.Confirm("alice", code); err != nil {
		t.Fatal(err)
	}

	if !tf.Check("alice", code) {
		t.Fatal("the code from the app was refused")
	}
	if tf.Check("alice", code) {
		t.Error("the same code signed in a second time")
	}

	// ... and the step before it, which the clock skew window would
	// otherwise still take
	earlier, err := TOTPCode(secret, time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if earlier != code && tf.Check("alice", earlier) {
		t.Error("the code for the step before the one just used was accepted")
	}

	// the next one works, or nobody could ever sign in again
	next, err := TOTPCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next != code && !tf.Check("alice", next) {
		t.Error("the next code was refused")
	}
}

func TestConfirmingNeedsTheRightCode(t *testing.T) {
	tf, _ := twoFactor(t)
	if _, _, err := tf.Start("alice", "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := tf.Confirm("alice", "000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("err = %v, want ErrWrongCode", err)
	}
	if tf.Enabled("alice") {
		t.Error("a wrong code turned the second factor on")
	}
}

// Starting again while one is set up would be a way to replace somebody's
// second factor from an unlocked browser without knowing their password.
func TestStartingAgainWhileItIsOnIsRefused(t *testing.T) {
	tf, _ := twoFactor(t)
	enrol(t, tf, "alice")

	if _, _, err := tf.Start("alice", "alice@example.com"); !errors.Is(err, ErrTwoFactorSet) {
		t.Fatalf("err = %v, want ErrTwoFactorSet", err)
	}
	if !tf.Enabled("alice") {
		t.Error("the refused start took the second factor away")
	}
}

// Starting twice before confirming hands out a new secret, and the old one
// stops working: an enrolment somebody abandoned must not be finishable.
func TestStartingAgainBeforeConfirmingReplacesTheSecret(t *testing.T) {
	tf, _ := twoFactor(t)

	first, _, err := tf.Start("alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := tf.Start("alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("the second enrolment reused the secret")
	}

	old, err := TOTPCode(first, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tf.Confirm("alice", old); !errors.Is(err, ErrWrongCode) {
		t.Errorf("err = %v, want ErrWrongCode: the abandoned secret still works", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	tf, _ := twoFactor(t)
	codes := enrol(t, tf, "alice")

	if left := tf.RecoveryCodesLeft("alice"); left != recoveryCodes {
		t.Errorf("%d recovery codes left, want %d", left, recoveryCodes)
	}

	// one signs in, and is used up by it
	if !tf.Check("alice", codes[0]) {
		t.Fatal("a recovery code was refused")
	}
	if tf.Check("alice", codes[0]) {
		t.Error("a recovery code worked twice")
	}
	if left := tf.RecoveryCodesLeft("alice"); left != recoveryCodes-1 {
		t.Errorf("%d recovery codes left, want %d", left, recoveryCodes-1)
	}

	// the others are untouched, however they are typed
	if !tf.Check("alice", strings.ToLower(codes[1])) {
		t.Error("a recovery code in lower case was refused")
	}
	if !tf.Check("alice", strings.ReplaceAll(codes[2], "-", "")) {
		t.Error("a recovery code without its dashes was refused")
	}
	if left := tf.RecoveryCodesLeft("alice"); left != recoveryCodes-3 {
		t.Errorf("%d recovery codes left, want %d", left, recoveryCodes-3)
	}

	if tf.Check("alice", "NOTA-REAL-CODE-ATALL") {
		t.Error("a made-up recovery code was accepted")
	}
}

// Turning it off asks for the password, or an unlocked browser would be
// enough to take somebody's second factor away.
func TestDisablingNeedsThePassword(t *testing.T) {
	tf, _ := twoFactor(t)
	enrol(t, tf, "alice")

	if err := tf.Disable("alice", "not-the-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
	if !tf.Enabled("alice") {
		t.Fatal("a wrong password took the second factor away")
	}

	if err := tf.Disable("alice", "the-configured-one"); err != nil {
		t.Fatal(err)
	}
	if tf.Enabled("alice") {
		t.Error("the second factor is still on after turning it off")
	}
	if left := tf.RecoveryCodesLeft("alice"); left != 0 {
		t.Errorf("%d recovery codes left after turning it off, want none", left)
	}
}

// An admin helps somebody whose phone is gone. It needs no password - it is
// as much trust as handing out a new one.
func TestAnAdminCanResetIt(t *testing.T) {
	tf, _ := twoFactor(t)
	codes := enrol(t, tf, "alice")

	if err := tf.Reset("alice"); err != nil {
		t.Fatal(err)
	}
	if tf.Enabled("alice") {
		t.Error("the second factor survived the reset")
	}
	// and the old recovery codes are gone with it
	if tf.Check("alice", codes[0]) {
		t.Error("a recovery code from before the reset still works")
	}

	if err := tf.Reset("alice"); !errors.Is(err, ErrNoTwoFactor) {
		t.Errorf("err = %v, want ErrNoTwoFactor for somebody without one", err)
	}
}

// Signing in writes the user row again; the second factor has to survive it,
// or it would last until the next login.
func TestSigningInAgainKeepsTheSecondFactor(t *testing.T) {
	tf, s := twoFactor(t)
	enrol(t, tf, "alice")

	if err := s.SaveUser(&storage.User{Subject: "alice", Provider: "simple", Name: "alice"}); err != nil {
		t.Fatal(err)
	}

	if !tf.Enabled("alice") {
		t.Error("signing in again forgot the second factor")
	}
}

// Somebody the configuration does not list has nothing here to set up.
func TestEnrollingSomebodyUnknown(t *testing.T) {
	tf, _ := twoFactor(t)
	if _, _, err := tf.Start("nobody", "nobody@example.com"); !errors.Is(err, ErrNoPasswordHere) {
		t.Errorf("err = %v, want ErrNoPasswordHere", err)
	}
	if tf.Enabled("nobody") {
		t.Error("somebody unknown has a second factor")
	}
	if tf.Check("nobody", "000000") {
		t.Error("a code was accepted for somebody unknown")
	}
}

// The password check that guards turning it off is the same one the sign-in
// uses, so a password the user set for themselves counts.
func TestDisablingWithAPasswordTheUserSet(t *testing.T) {
	p, s := passwords(t, entry(t, "the-configured-one"))
	tf := NewTwoFactor(s, p, "wg-access-server")
	enrol(t, tf, "alice")

	if err := p.Change("alice", "the-configured-one", "what-alice-chose"); err != nil {
		t.Fatal(err)
	}

	if err := tf.Disable("alice", "the-configured-one"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("err = %v, want ErrWrongPassword: the old password still turns it off", err)
	}
	if err := tf.Disable("alice", "what-alice-chose"); err != nil {
		t.Errorf("the password the user set does not turn it off: %v", err)
	}
}

// A hash is what is stored; nothing here can produce the codes again.
func TestRecoveryCodesAreHashedNotEncrypted(t *testing.T) {
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	for i, code := range codes {
		if hashes[i] == normalizeRecoveryCode(code) {
			t.Fatal("a recovery code is stored as it is")
		}
		if hashRecoveryCode(code) != hashes[i] {
			t.Error("the stored hash is not the hash of the code")
		}
		if len(hashes[i]) != 64 {
			t.Errorf("hash = %d characters, want 64 (sha256, hex)", len(hashes[i]))
		}
	}

	// ... and no two are the same
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			t.Fatal("the same recovery code was handed out twice")
		}
		seen[code] = true
	}
}

// bcrypt for the password, sha256 for the codes: this pins that the two are
// not confused, since a slow hash per recovery code would be ten per attempt.
func TestTheDifferenceBetweenPasswordsAndRecoveryCodes(t *testing.T) {
	if _, err := bcrypt.Cost([]byte(hashRecoveryCode("ABCD-EFGH"))); err == nil {
		t.Error("recovery codes are bcrypt hashed, which makes checking them slow")
	}
}
