package users

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords, RFC 6238, as every authenticator app
// implements them: HMAC-SHA1 over the number of 30 second steps since the
// epoch, truncated to six digits.
//
// Written out here rather than taken from a library: it is forty lines, the
// test vectors from the RFC say whether they are the right forty, and a
// dependency that computes an HMAC is a dependency to keep an eye on for as
// long as it is in the file.
const (
	totpStep    = 30 * time.Second
	totpDigits  = 6
	totpWindow  = 1 // one step either side, for clocks that disagree a little
	secretBytes = 20
)

// base32 without padding, which is what authenticator apps expect in the URI.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a secret for one person, base32 encoded.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate a two-factor secret: %w", err)
	}
	return totpEncoding.EncodeToString(buf), nil
}

// TOTPURI is what the QR code holds: the otpauth URI an authenticator app
// reads to add the account.
func TOTPURI(issuer string, account string, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{
		"secret": {secret},
		"issuer": {issuer},
		// named although they are the defaults: an app that assumes other
		// ones would otherwise produce codes this server never accepts
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(totpDigits)},
		"period":    {fmt.Sprint(int(totpStep.Seconds()))},
	}
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// TOTPCode is the code for one point in time, zero-padded to six digits.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("the two-factor secret is not base32: %w", err)
	}
	return code(key, uint64(at.Unix())/uint64(totpStep.Seconds()), totpDigits), nil
}

// CheckTOTP says whether a code is the one for now, or for the step just
// before or after it - phones and servers rarely agree on the second.
func CheckTOTP(secret string, given string, now time.Time) bool {
	_, ok := CheckTOTPStep(secret, given, now)
	return ok
}

// CheckTOTPStep is CheckTOTP, and says which time step the code was for. The
// caller remembers it: a code is good for three steps, so without refusing
// everything up to the last accepted one, the same code signs in again for as
// long as its window lasts. RFC 6238 asks for exactly this.
//
// The comparison is constant time, and the code is compared as a string, so a
// code with leading zeros is not quietly turned into a smaller number.
func CheckTOTPStep(secret string, given string, now time.Time) (int64, bool) {
	given = strings.TrimSpace(given)
	if len(given) != totpDigits {
		return 0, false
	}
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}

	step := uint64(now.Unix()) / uint64(totpStep.Seconds())
	matched := int64(0)
	ok := false
	for i := -totpWindow; i <= totpWindow; i++ {
		counter := step + uint64(i) //nolint:gosec // wraps only for times before 1970
		// every step is checked, so that how long this takes says nothing
		// about which one matched
		if subtle.ConstantTimeCompare([]byte(code(key, counter, totpDigits)), []byte(given)) == 1 {
			ok = true
			matched = int64(counter) //nolint:gosec // same
		}
	}
	return matched, ok
}

// code is the HOTP truncation of RFC 4226, which TOTP counts steps for.
func code(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, truncated%mod)
}
