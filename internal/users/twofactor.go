package users

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

var (
	// ErrNoTwoFactor is asking about a second factor of somebody who has
	// none, or finishing an enrolment nobody started.
	ErrNoTwoFactor = errors.New("this account has no second factor")
	// ErrTwoFactorSet is starting an enrolment for somebody who already has
	// one. Turning it off first is deliberate: it is the step that asks for
	// the password.
	ErrTwoFactorSet = errors.New("this account already has a second factor")
	// ErrWrongCode is a code that is not the code.
	ErrWrongCode = errors.New("wrong code")
)

// recoveryCodes is how many are handed out at once, and how long each is.
// Ten is what fits on a sticky note; twenty base32 characters is 100 bits,
// which nobody guesses.
const (
	recoveryCodes      = 10
	recoveryCodeBytes  = 13
	recoveryCodeGroups = 4
)

// TwoFactor is the second factor of the built-in sign-in: a code from an
// authenticator app, and the recovery codes for when the phone is gone.
//
// The secret is kept as the app needs it - a shared secret cannot be hashed,
// or neither side could compute the same code. It is worth no less protection
// than the device keys in the same database. The recovery codes are hashed:
// they are long random strings, so a fast hash is enough, and a slow one
// would make checking ten of them per attempt a way to hold the server up.
type TwoFactor struct {
	storage   storage.UserStorage
	passwords *Passwords
	issuer    string
	now       func() time.Time
}

func NewTwoFactor(s storage.UserStorage, passwords *Passwords, issuer string) *TwoFactor {
	return &TwoFactor{storage: s, passwords: passwords, issuer: issuer, now: time.Now}
}

// Enabled says whether this person is asked for a code when they sign in.
func (t *TwoFactor) Enabled(subject string) bool {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil {
		return false
	}
	return user.TwoFactorEnabled()
}

// Start begins an enrolment: a fresh secret, and the URI the QR code holds.
// Nothing is asked of the user yet - the secret only counts once they have
// proved with a code that their app has it too.
func (t *TwoFactor) Start(subject string, account string) (secret string, uri string, err error) {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil {
		return "", "", ErrNoPasswordHere
	}
	if user.TwoFactorEnabled() {
		return "", "", ErrTwoFactorSet
	}

	secret, err = NewTOTPSecret()
	if err != nil {
		return "", "", err
	}

	// Stored unconfirmed, and it replaces any earlier unconfirmed one: an
	// enrolment somebody abandoned must not be finishable later.
	if err := t.storage.SetUserTOTP(subject, storage.TOTPState{Secret: secret}); err != nil {
		return "", "", fmt.Errorf("failed to store the new second factor: %w", err)
	}

	return secret, TOTPURI(t.issuer, account, secret), nil
}

// Confirm finishes an enrolment with a code from the app, and returns the
// recovery codes. They are shown once: what is kept here cannot produce them
// again.
func (t *TwoFactor) Confirm(subject string, code string) ([]string, error) {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil {
		return nil, ErrNoPasswordHere
	}
	if user.TwoFactorEnabled() {
		return nil, ErrTwoFactorSet
	}
	if user.TotpSecret == "" {
		return nil, ErrNoTwoFactor
	}
	if !CheckTOTP(user.TotpSecret, code, t.now()) {
		return nil, ErrWrongCode
	}

	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}

	enabled := t.now().UTC()
	if err := t.storage.SetUserTOTP(subject, storage.TOTPState{
		Secret:    user.TotpSecret,
		EnabledAt: &enabled,
		Recovery:  strings.Join(hashes, ","),
	}); err != nil {
		return nil, fmt.Errorf("failed to store the second factor: %w", err)
	}

	return codes, nil
}

// Check is the sign-in asking whether a code is right: one from the app, or
// one of the recovery codes, which is used up by being right.
func (t *TwoFactor) Check(subject string, given string) bool {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil || !user.TwoFactorEnabled() {
		return false
	}

	if CheckTOTP(user.TotpSecret, given, t.now()) {
		return true
	}

	left, used := useRecoveryCode(user.TotpRecovery, given)
	if !used {
		return false
	}
	state := user.TOTP()
	state.Recovery = left
	if err := t.storage.SetUserTOTP(subject, state); err != nil {
		// The code was right, but it would stay usable. Refusing the sign-in
		// is the safe way to be wrong here.
		return false
	}
	return true
}

// Disable turns the second factor off. It asks for the password: somebody who
// walked up to an unlocked browser must not be able to take it away.
func (t *TwoFactor) Disable(subject string, password string) error {
	if t.passwords == nil {
		return ErrNoPasswordHere
	}
	if err := t.passwords.Verify(subject, password); err != nil {
		return err
	}
	return t.clear(subject)
}

// Reset takes the second factor away without a password, for an admin helping
// somebody whose phone is gone. Their password alone signs them in again, so
// it is as much trust as handing out a password.
func (t *TwoFactor) Reset(subject string) error {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil {
		return ErrNoPasswordHere
	}
	if !user.TwoFactorEnabled() && user.TotpSecret == "" {
		return ErrNoTwoFactor
	}
	return t.clear(subject)
}

func (t *TwoFactor) clear(subject string) error {
	if err := t.storage.SetUserTOTP(subject, storage.TOTPState{}); err != nil {
		return fmt.Errorf("failed to remove the second factor: %w", err)
	}
	return nil
}

// RecoveryCodesLeft is how many are still unused, which is what the UI shows.
func (t *TwoFactor) RecoveryCodesLeft(subject string) int {
	user, err := t.storage.GetUser(subject)
	if err != nil || user == nil {
		return 0
	}
	return len(splitCodes(user.TotpRecovery))
}

// newRecoveryCodes returns the codes to show once and the hashes to keep.
func newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 0, recoveryCodes)
	hashes := make([]string, 0, recoveryCodes)
	for range recoveryCodes {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("failed to generate recovery codes: %w", err)
		}
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		codes = append(codes, group(code))
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// group writes a code as "ABCD-EFGH-..." so it can be read out loud and typed
// without losing the place. The dashes are not part of the code.
func group(code string) string {
	parts := []string{}
	for i := 0; i < len(code); i += recoveryCodeGroups {
		end := min(i+recoveryCodeGroups, len(code))
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}

// hashRecoveryCode is SHA-256 of the code as it was generated: upper case,
// without the dashes that are only there to read it by.
func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// useRecoveryCode returns the codes that are left and whether one was used.
// Every stored code is compared, so how long this takes says nothing about
// which one matched or whether any did.
func useRecoveryCode(stored string, given string) (string, bool) {
	wanted := hashRecoveryCode(given)
	left := []string{}
	used := false
	for _, hash := range splitCodes(stored) {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(wanted)) == 1 {
			used = true
			continue
		}
		left = append(left, hash)
	}
	if !used {
		return stored, false
	}
	return strings.Join(left, ","), true
}

func splitCodes(stored string) []string {
	codes := []string{}
	for _, code := range strings.Split(stored, ",") {
		if code = strings.TrimSpace(code); code != "" {
			codes = append(codes, code)
		}
	}
	return codes
}
