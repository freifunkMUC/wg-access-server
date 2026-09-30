package serve

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
)

// relyingPartyWarning is what the warning is recognised by, whatever else the
// sentence says.
const relyingPartyWarning = "vpn.externalHost is not set"

func hasRelyingPartyWarning(hook *test.Hook) bool {
	for _, message := range warnings(hook) {
		if strings.Contains(message, relyingPartyWarning) {
			return true
		}
	}
	return false
}

func TestReadConfigWarnsWithoutExternalHost(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	adminConfig(t, []string{"alice:" + testHash(t, "hunter2")}).ReadConfig()

	if !hasRelyingPartyWarning(hook) {
		t.Errorf("no warning about the unset external host, got warnings: %q", warnings(hook))
	}
}

// The admin entry is appended to the user list inside ReadConfig, so a config
// that names only an admin password still offers passkeys. The warning has to
// be decided after that, not before it.
func TestReadConfigWarnsForTheAdminUserAlone(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	cmd := adminConfig(t, nil)
	cmd.AppConfig.Auth.Simple = nil

	cmd.ReadConfig()

	if !hasRelyingPartyWarning(hook) {
		t.Errorf("no warning although the admin can register a passkey, got warnings: %q", warnings(hook))
	}
}

func TestReadConfigIsQuietWithAnExternalHost(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	cmd := adminConfig(t, []string{"alice:" + testHash(t, "hunter2")})
	cmd.AppConfig.ExternalHost = "vpn.example.com"

	cmd.ReadConfig()

	if hasRelyingPartyWarning(hook) {
		t.Errorf("warned although the external host is configured: %q", warnings(hook))
	}
}

// With no built-in provider nobody registers a passkey here: the identity
// provider's own credentials are its business, and the warning would be noise.
func TestReadConfigIsQuietWithoutABuiltInProvider(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	cmd := &servecmd{}
	cmd.AppConfig.Storage = "memory://"
	cmd.AppConfig.HttpEnabled = true
	cmd.AppConfig.Auth.OIDC = &authconfig.OIDCConfig{
		Name:         "test",
		Issuer:       "https://issuer.example.com",
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://vpn.example.com/callback",
	}

	cmd.ReadConfig()

	if hasRelyingPartyWarning(hook) {
		t.Errorf("warned although no built-in provider is configured: %q", warnings(hook))
	}
}
