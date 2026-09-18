package authconfig

import "testing"

// bcrypt hash of "correct horse battery staple", cost 4 to keep the test fast
const testHash = "$2a$04$1GFdp9fn4fMjbPGnvDXAdORiwZIJmlRFzwhcHqCPtDlYuoK105KE."

func TestParseHtpassword(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		username string
		hash     string
		ok       bool
	}{
		{name: "username and hash", entry: "alice:" + testHash, username: "alice", hash: testHash, ok: true},
		{name: "hash containing colons", entry: "alice:{SHA}a:b", username: "alice", hash: "{SHA}a:b", ok: true},
		{name: "no colon", entry: "alice", ok: false},
		{name: "empty hash", entry: "alice:", ok: false},
		{name: "empty username", entry: ":" + testHash, ok: false},
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
	users := []string{"malformed-entry-without-a-colon", "alice:" + testHash}

	if !checkCreds(users, "alice", "correct horse battery staple") {
		t.Error("a valid user after a malformed entry must still be able to log in")
	}
	if checkCreds(users, "malformed-entry-without-a-colon", "") {
		t.Error("a malformed entry must never authenticate anyone")
	}
	if checkCreds(users, "alice", "wrong password") {
		t.Error("a wrong password must not authenticate")
	}
}
