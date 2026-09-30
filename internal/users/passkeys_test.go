package users

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func testPasskeys(t *testing.T) (*Passkeys, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	if err := s.SaveUser(&storage.User{Subject: "alice", Provider: "simple", Name: "Alice Example"}); err != nil {
		t.Fatal(err)
	}
	return NewPasskeys(s, RelyingPartyFromHost("vpn.example.com", true)), s
}

func request() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://vpn.example.com/api", nil)
	r.Host = "vpn.example.com"
	return r
}

// The options the browser is handed have to name this site and carry a
// challenge; without either the browser refuses, and the person sees nothing
// but a dialog that closes again.
func TestBeginRegistration(t *testing.T) {
	passkeys, s := testPasskeys(t)

	raw, err := passkeys.BeginRegistration(request(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	options := struct {
		PublicKey struct {
			Challenge          string                                 `json:"challenge"`
			RP                 struct{ ID, Name string }              `json:"rp"`
			User               struct{ ID, Name, DisplayName string } `json:"user"`
			ExcludeCredentials []struct{ ID string }                  `json:"excludeCredentials"`
		} `json:"publicKey"`
	}{}
	if err := json.Unmarshal(raw, &options); err != nil {
		t.Fatalf("the options are not JSON the browser can read: %v", err)
	}
	if options.PublicKey.Challenge == "" {
		t.Error("no challenge was sent")
	}
	if options.PublicKey.RP.ID != "vpn.example.com" {
		t.Errorf("relying party = %q, want the configured host", options.PublicKey.RP.ID)
	}
	if options.PublicKey.User.Name != "alice" || options.PublicKey.User.DisplayName != "Alice Example" {
		t.Errorf("user = %+v, want alice", options.PublicKey.User)
	}

	// the challenge is kept for the answer, and only for a while
	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.WebauthnChallenge == "" || user.WebauthnChallengeUntil == nil {
		t.Fatal("the challenge was not kept")
	}
	if !user.WebauthnChallengeUntil.After(time.Now()) {
		t.Error("the challenge is already expired")
	}
	if user.WebauthnChallengeUntil.After(time.Now().Add(time.Hour)) {
		t.Error("the challenge is kept for an hour")
	}
}

// An answer without a challenge, or long after it, is not an answer.
func TestFinishingWithoutAChallenge(t *testing.T) {
	passkeys, s := testPasskeys(t)

	err := passkeys.FinishLogin(request(), "alice", []byte("{}"))
	if !errors.Is(err, ErrNoChallenge) {
		t.Errorf("err = %v, want ErrNoChallenge", err)
	}

	// one that has expired counts for as little
	if _, err := passkeys.BeginRegistration(request(), "alice"); err != nil {
		t.Fatal(err)
	}
	long := time.Now().Add(-time.Hour)
	user, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetWebauthnChallenge("alice", user.WebauthnChallenge, &long); err != nil {
		t.Fatal(err)
	}

	if _, err := passkeys.FinishRegistration(request(), "alice", "a key", []byte("{}")); !errors.Is(err, ErrNoChallenge) {
		t.Errorf("err = %v, want ErrNoChallenge for an expired challenge", err)
	}
}

// A person with no passkey is not asked for one, and cannot start a sign-in
// with one either.
func TestSigningInWithoutAPasskey(t *testing.T) {
	passkeys, _ := testPasskeys(t)

	if passkeys.Has("alice") {
		t.Error("somebody without a passkey has one")
	}
	if _, err := passkeys.BeginLogin(request(), "alice"); !errors.Is(err, ErrNoPasskey) {
		t.Errorf("err = %v, want ErrNoPasskey", err)
	}
}

func TestListingAndRemoving(t *testing.T) {
	passkeys, s := testPasskeys(t)

	older := time.Now().Add(-time.Hour).UTC()
	for _, passkey := range []*storage.Passkey{
		{ID: "one", Owner: "alice", Name: "A key", Data: []byte("{}"), CreatedAt: older},
		{ID: "two", Owner: "alice", Name: "My phone", Data: []byte("{}"), CreatedAt: time.Now().UTC()},
		{ID: "three", Owner: "bob", Name: "Not hers", Data: []byte("{}"), CreatedAt: time.Now().UTC()},
	} {
		if err := s.SavePasskey(passkey); err != nil {
			t.Fatal(err)
		}
	}

	if !passkeys.Has("alice") {
		t.Error("alice has no passkey although two are stored")
	}

	listed, err := passkeys.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("listed %d passkeys, want alice's two", len(listed))
	}
	// newest first, as the UI shows them
	if listed[0].ID != "two" {
		t.Errorf("first is %q, want the newest", listed[0].ID)
	}

	// somebody else's is not hers to remove, and is reported as missing
	if err := passkeys.Delete("alice", "three"); !errors.Is(err, ErrNoPasskey) {
		t.Errorf("err = %v, want ErrNoPasskey", err)
	}
	if _, err := s.GetPasskey("three"); err != nil {
		t.Error("somebody else's passkey was removed")
	}

	if err := passkeys.Delete("alice", "one"); err != nil {
		t.Fatal(err)
	}
	if listed, _ = passkeys.List("alice"); len(listed) != 1 {
		t.Errorf("%d passkeys left, want one", len(listed))
	}
}

// The credentials handed to the library come out of the stored rows; a row
// that cannot be read is skipped rather than taking the sign-in down.
func TestTheUserTheLibrarySees(t *testing.T) {
	_, s := testPasskeys(t)
	stored, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}

	user := &passkeyUser{stored: stored, passkeys: []*storage.Passkey{
		{ID: "broken", Owner: "alice", Data: []byte("this is not json")},
	}}

	if got := user.WebAuthnCredentials(); len(got) != 0 {
		t.Errorf("%d credentials from a broken row, want none", len(got))
	}
	if user.WebAuthnName() != "alice" || user.WebAuthnDisplayName() != "Alice Example" {
		t.Error("the library is told the wrong name")
	}

	// the handle is stable and is not the username: a name can be given to
	// somebody else later, and a credential must not follow it
	id := user.WebAuthnID()
	if len(id) != 32 {
		t.Errorf("the user handle is %d bytes, want 32", len(id))
	}
	if strings.Contains(string(id), "alice") {
		t.Error("the user handle carries the username")
	}
	other := &passkeyUser{stored: &storage.User{Subject: "alice"}}
	if string(other.WebAuthnID()) != string(id) {
		t.Error("the user handle is not stable")
	}
}

// Which site this is has to be the name people type, not whatever reached the
// server: behind a reverse proxy the Host header is the proxy's business.
func TestRelyingPartyFromHost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		httpsOnly  bool
		host       string
		tls        bool
		wantID     string
		wantOrigin string
	}{
		{
			name: "configured host, https", configured: "vpn.example.com", httpsOnly: true,
			host: "10.0.0.1:8443", wantID: "vpn.example.com", wantOrigin: "https://vpn.example.com:8443",
		},
		{
			name: "no configured host falls back to the request", configured: "", httpsOnly: true,
			host: "vpn.example.com", wantID: "vpn.example.com", wantOrigin: "https://vpn.example.com",
		},
		{
			name: "a configured host with a port keeps it", configured: "vpn.example.com:8443", httpsOnly: true,
			host: "vpn.example.com:8443", wantID: "vpn.example.com", wantOrigin: "https://vpn.example.com:8443",
		},
		{
			name: "plain http is named as such", configured: "localhost", httpsOnly: false,
			host: "localhost:8000", wantID: "localhost", wantOrigin: "http://localhost:8000",
		},
		{
			name: "http, but the request came over TLS", configured: "localhost", httpsOnly: false,
			host: "localhost:8443", tls: true, wantID: "localhost", wantOrigin: "https://localhost:8443",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tc.host
			r.TLS = nil
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}

			id, origin := RelyingPartyFromHost(tc.configured, tc.httpsOnly)(r)
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if origin != tc.wantOrigin {
				t.Errorf("origin = %q, want %q", origin, tc.wantOrigin)
			}
		})
	}

	// without a host there is nothing to bind a passkey to, and that is an
	// error rather than a guess
	id, _ := RelyingPartyFromHost("", true)(nil)
	if id != "" {
		t.Errorf("id = %q, want nothing without a host", id)
	}
}

// A name is what tells one passkey from another; an empty one would leave a
// row nobody can identify.
func TestPasskeyName(t *testing.T) {
	if got := passkeyName("  "); got != "Passkey" {
		t.Errorf("name = %q, want a default", got)
	}
	if got := passkeyName("  My phone "); got != "My phone" {
		t.Errorf("name = %q, want it trimmed", got)
	}
	if got := passkeyName(strings.Repeat("x", 200)); len(got) != maxPasskeyName {
		t.Errorf("name is %d characters, want it cut to %d", len(got), maxPasskeyName)
	}
}
