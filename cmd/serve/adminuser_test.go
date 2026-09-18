package serve

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
)

// adminConfig builds the smallest config ReadConfig accepts without calling
// logrus.Fatal: memory storage means it may generate its own WireGuard key.
func adminConfig(t *testing.T, users []string) *servecmd {
	t.Helper()
	cmd := &servecmd{}
	cmd.AppConfig.Storage = "memory://"
	cmd.AppConfig.AdminUsername = "admin"
	cmd.AppConfig.AdminPassword = "hunter2"
	cmd.AppConfig.Auth.Simple = &authconfig.SimpleAuthConfig{Users: users}
	return cmd
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

	adminConfig(t, []string{"admin:$2a$04$1GFdp9fn4fMjbPGnvDXAdORiwZIJmlRFzwhcHqCPtDlYuoK105KE."}).ReadConfig()

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

	adminConfig(t, []string{"alice:$2a$04$1GFdp9fn4fMjbPGnvDXAdORiwZIJmlRFzwhcHqCPtDlYuoK105KE."}).ReadConfig()

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
