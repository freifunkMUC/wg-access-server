package users

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// The test vectors of RFC 6238, appendix B: the SHA-1 column, computed from
// the seed "12345678901234567890". They say whether this implementation is
// the one every authenticator app also implements - which is the whole
// question, since the app is not ours.
//
// The RFC prints eight digits; the six a phone shows are its last six.
func TestRFC6238Vectors(t *testing.T) {
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))

	for _, tc := range []struct {
		seconds int64
		want    string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		at := time.Unix(tc.seconds, 0).UTC()

		eight, err := TOTPCode(secret, at)
		if err != nil {
			t.Fatal(err)
		}
		_ = eight

		// the same counter, eight digits, straight from the RFC
		key, err := totpEncoding.DecodeString(secret)
		if err != nil {
			t.Fatal(err)
		}
		got := code(key, uint64(tc.seconds)/30, 8)
		if got != tc.want {
			t.Errorf("at %d: code = %s, want %s", tc.seconds, got, tc.want)
		}

		// ... and what this server checks is its last six
		six, err := TOTPCode(secret, at)
		if err != nil {
			t.Fatal(err)
		}
		if six != tc.want[2:] {
			t.Errorf("at %d: six-digit code = %s, want %s", tc.seconds, six, tc.want[2:])
		}
		if !CheckTOTP(secret, six, at) {
			t.Errorf("at %d: the code this server computes is not accepted by it", tc.seconds)
		}
	}
}

// A phone and a server rarely agree on the second, so the step before and
// after count - and the one after that does not, or a code would live for
// minutes.
func TestCheckTOTPAcceptsTheNeighbouringSteps(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)

	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		codeAt, err := TOTPCode(secret, now.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if !CheckTOTP(secret, codeAt, now) {
			t.Errorf("the code for %s from now was refused", offset)
		}
	}

	for _, offset := range []time.Duration{-90 * time.Second, 90 * time.Second, time.Hour} {
		codeAt, err := TOTPCode(secret, now.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if CheckTOTP(secret, codeAt, now) {
			t.Errorf("the code for %s from now was accepted", offset)
		}
	}
}

func TestCheckTOTPRefusesWhatIsNotACode(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	real, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, given := range []string{"", "12345", "1234567", "abcdef", real + "0", "0" + real, " "} {
		if CheckTOTP(secret, given, now) {
			t.Errorf("%q was accepted as a code", given)
		}
	}

	// a code somebody typed with spaces around it is still their code
	if !CheckTOTP(secret, " "+real+" ", now) {
		t.Error("a code with spaces around it was refused")
	}

	// a secret that is not base32 cannot produce codes, and must not panic
	if CheckTOTP("not base32!", real, now) {
		t.Error("a broken secret accepted a code")
	}
}

// Two people must not share a secret, and a secret has to be long enough to
// be worth the HMAC: 20 bytes is what RFC 4226 asks for.
func TestNewTOTPSecret(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		secret, err := NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[secret] {
			t.Fatal("the same secret was generated twice")
		}
		seen[secret] = true

		raw, err := totpEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("the secret is not base32: %v", err)
		}
		if len(raw) != secretBytes {
			t.Errorf("secret = %d bytes, want %d", len(raw), secretBytes)
		}
		if strings.ContainsAny(secret, "=") {
			t.Error("the secret carries base32 padding, which apps do not expect")
		}
	}
}

// The URI is what the QR code holds. An app reads the secret and the account
// out of it, so the parts have to be where it looks for them.
func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("wg-access-server", "alice@example.com", "JBSWY3DPEHPK3PXP")

	for _, want := range []string{
		"otpauth://totp/",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=wg-access-server",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri = %q, want it to contain %q", uri, want)
		}
	}

	// the label carries issuer and account, escaped - an @ in a name must not
	// end the path
	if !strings.Contains(uri, "wg-access-server:alice@example.com") &&
		!strings.Contains(uri, "wg-access-server%3Aalice@example.com") {
		t.Errorf("uri = %q, want the issuer and the account in the label", uri)
	}
}

// base32 with padding is what a naive implementation writes; apps choke on it.
func TestTheSecretEncodingIsUnpadded(t *testing.T) {
	if totpEncoding == base32.StdEncoding {
		t.Error("the secret is encoded with padding")
	}
}
