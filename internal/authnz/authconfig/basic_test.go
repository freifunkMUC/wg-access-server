package authconfig

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const testPassword = "correct horse battery staple"

// testHash hashes password with bcrypt. Generated instead of pasted in as a
// literal: a hash is random base64-ish text and sooner or later contains
// something the spell checker reports as a typo.
func testHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func TestParseHtpassword(t *testing.T) {
	hash := testHash(t, testPassword)

	tests := []struct {
		name     string
		entry    string
		username string
		hash     string
		ok       bool
	}{
		{name: "username and hash", entry: "alice:" + hash, username: "alice", hash: hash, ok: true},
		{name: "hash containing colons", entry: "alice:{SHA}a:b", username: "alice", hash: "{SHA}a:b", ok: true},
		{name: "no colon", entry: "alice", ok: false},
		{name: "empty hash", entry: "alice:", ok: false},
		{name: "empty username", entry: ":" + hash, ok: false},
		{name: "empty entry", entry: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, hash, ok := parsehtpassword(tt.entry)
			if ok != tt.ok {
				t.Fatalf("parsehtpassword(%q) ok = %v, want %v", tt.entry, ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if username != tt.username || hash != tt.hash {
				t.Errorf("parsehtpassword(%q) = (%q, %q), want (%q, %q)", tt.entry, username, hash, tt.username, tt.hash)
			}
		})
	}
}

// A user entry without a colon used to index past the end of the split result
// and panic on every login attempt.
func TestCheckCredsMalformedEntry(t *testing.T) {
	users := []string{"malformed-entry-without-a-colon", "alice:" + testHash(t, testPassword)}

	if !checkCreds(users, "alice", testPassword) {
		t.Error("a valid user after a malformed entry must still be able to log in")
	}
	if checkCreds(users, "malformed-entry-without-a-colon", "") {
		t.Error("a malformed entry must never authenticate anyone")
	}
	if checkCreds(users, "alice", "wrong password") {
		t.Error("a wrong password must not authenticate")
	}
}
