package serve

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
)

// adminConfig builds the smallest config ReadConfig accepts without calling
// logrus.Fatal: memory storage means it may generate its own WireGuard key.
func adminConfig(t *testing.T, users []string) *servecmd {
	t.Helper()
	cmd := &servecmd{}
	cmd.AppConfig.Storage = "memory://"
	// as kingpin's defaults would have it, so ReadConfig does not stop
	// because no listener is enabled
	cmd.AppConfig.HttpEnabled = true
	cmd.AppConfig.AdminUsername = "admin"
	cmd.AppConfig.AdminPassword = "hunter2"
	cmd.AppConfig.Auth.Simple = &authconfig.SimpleAuthConfig{Users: users}
	return cmd
}

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

func warnings(hook *test.Hook) []string {
	var out []string
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel {
			out = append(out, entry.Message)
		}
	}
	return out
}

// checkCreds stops at the first entry whose username matches, and the admin
// entry is appended behind the configured ones. An operator who configures
// both must be told that their admin password does nothing.
func TestReadConfigWarnsWhenAdminUsernameIsAlreadyTaken(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	adminConfig(t, []string{"admin:" + testHash(t, "hunter2")}).ReadConfig()

	var found bool
	for _, message := range warnings(hook) {
		if strings.Contains(message, "auth.simple") && strings.Contains(message, "admin") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the shadowed admin entry, got warnings: %q", warnings(hook))
	}
}

func TestReadConfigDoesNotWarnForOtherUsers(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	adminConfig(t, []string{"alice:" + testHash(t, "hunter2")}).ReadConfig()

	for _, message := range warnings(hook) {
		if strings.Contains(message, "auth.simple") {
			t.Errorf("unexpected warning for an unrelated user: %q", message)
		}
	}
}

func TestWarnIfUserExistsIgnoresMalformedEntries(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	warnIfUserExists([]string{"admin-without-a-colon", "adminx:hash"}, "admin", "auth.simple")

	if got := warnings(hook); len(got) != 0 {
		t.Errorf("got warnings %q, want none: neither entry is a user called 'admin'", got)
	}
}
