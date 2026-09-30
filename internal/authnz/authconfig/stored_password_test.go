package authconfig

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

// storedPasswords is what the server hands the providers: a user's own
// password and the configured entry it was set against.
type storedPasswords map[string][2]string

func (s storedPasswords) UserPassword(subject string) (string, string) {
	entry := s[subject]
	return entry[0], entry[1]
}

func runtimeWith(passwords storedPasswords) *authruntime.ProviderRuntime {
	runtime := authruntime.NewProviderRuntime(nil, nil)
	runtime.UsePasswords(passwords)
	return runtime
}

func bcryptOf(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

// The password a user set for themselves is their password - the configured
// one stops working, or changing it would change nothing.
func TestAPasswordTheUserSetReplacesTheConfiguredOne(t *testing.T) {
	configured := testHash(t, testPassword)
	users := []string{"alice:" + configured}
	runtime := runtimeWith(storedPasswords{"alice": {bcryptOf(t, "what-alice-chose"), configured}})

	if !checkCreds(users, "alice", "what-alice-chose", runtime) {
		t.Error("the password the user set does not work")
	}
	if checkCreds(users, "alice", testPassword, runtime) {
		t.Error("the configured password still works after the user set their own")
	}
	if checkCreds(users, "alice", "neither of them", runtime) {
		t.Error("a wrong password works")
	}
}

// An admin editing the config file takes a stored password back, otherwise a
// password handed out once could never be revoked.
func TestAChangedConfigEntryBeatsTheStoredPassword(t *testing.T) {
	// the entry the password was set against is not the entry now
	stored := storedPasswords{"alice": {bcryptOf(t, "what-alice-chose"), testHash(t, "the-old-configured-one")}}
	users := []string{"alice:" + testHash(t, testPassword)}
	runtime := runtimeWith(stored)

	if checkCreds(users, "alice", "what-alice-chose", runtime) {
		t.Error("the stored password outlived the config entry it was set against")
	}
	if !checkCreds(users, "alice", testPassword, runtime) {
		t.Error("the configured password does not work")
	}
}

// The configuration decides who may sign in at all. A stored password for
// somebody it does not list must not let them in.
func TestAStoredPasswordDoesNotCreateAnAccount(t *testing.T) {
	runtime := runtimeWith(storedPasswords{"mallory": {bcryptOf(t, "let-me-in"), "whatever"}})
	users := []string{"alice:" + testHash(t, testPassword)}

	if checkCreds(users, "mallory", "let-me-in", runtime) {
		t.Error("a stored password let somebody in that the configuration does not list")
	}
}

// Without a store - no storage, nobody has set anything - the configured
// entry is what counts, as it did before any of this.
func TestWithoutAStoreTheConfigurationDecides(t *testing.T) {
	users := []string{"alice:" + testHash(t, testPassword)}

	for _, runtime := range []*authruntime.ProviderRuntime{nil, authruntime.NewProviderRuntime(nil, nil)} {
		if !checkCreds(users, "alice", testPassword, runtime) {
			t.Error("the configured password does not work")
		}
		if checkCreds(users, "alice", "wrong", runtime) {
			t.Error("a wrong password works")
		}
	}
}

// ConfiguredEntry is what the password change looks the user up with. It has
// to find them wherever they are configured, and nowhere else.
func TestConfiguredEntry(t *testing.T) {
	alice := testHash(t, testPassword)
	bob := testHash(t, "bobs-password")
	config := AuthConfig{
		ProviderConfig: ProviderConfig{Simple: &SimpleAuthConfig{Users: []string{"alice:" + alice}}},
		Multiple: map[string]*ProviderConfig{
			"other": {Basic: &BasicAuthConfig{Users: []string{"bob:" + bob}}},
		},
	}

	if entry, ok := config.ConfiguredEntry("alice"); !ok || entry != alice {
		t.Errorf("alice: (%q, %v), want her entry", entry, ok)
	}
	if entry, ok := config.ConfiguredEntry("bob"); !ok || entry != bob {
		t.Errorf("bob: (%q, %v), want his entry", entry, ok)
	}
	if _, ok := config.ConfiguredEntry("carol"); ok {
		t.Error("somebody the configuration does not list was found")
	}
	if count := config.ConfiguredEntries(); count != 2 {
		t.Errorf("ConfiguredEntries() = %d, want 2", count)
	}
}

func TestHasPassword(t *testing.T) {
	for provider, want := range map[string]bool{
		SimpleAuthProvider: true,
		BasicAuthProvider:  true,
		"oidc":             false,
		"gitlab":           false,
		"":                 false,
	} {
		if got := HasPassword(provider); got != want {
			t.Errorf("HasPassword(%q) = %v, want %v", provider, got, want)
		}
	}
}
