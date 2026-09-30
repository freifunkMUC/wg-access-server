package serve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/sirupsen/logrus/hooks/test"
)

// The config file is read last and wins. That is the documented intent, but a
// deployment that sets the admin account in the environment and also names it
// in the file gets the file's - and the account it thought it configured does
// not exist. Saying so at startup is the whole point of this warning.
func TestReadConfigWarnsWhenTheFileOverridesTheEnvironment(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	t.Setenv("WG_ADMIN_USERNAME", "wireguardadmin")
	t.Setenv("WG_ADMIN_PASSWORD", "from-the-env")

	cmd := adminConfig(t, nil)
	cmd.AppConfig.Auth.Simple = nil
	cmd.ConfigFilePath = writeConfig(t, `
adminUsername: "admin"
adminPassword: "from-the-file"
`)

	cmd.ReadConfig()

	for _, want := range []string{"WG_ADMIN_USERNAME", "WG_ADMIN_PASSWORD"} {
		if !warnedAbout(hook, want) {
			t.Errorf("nothing warned that %s is overridden, got warnings: %q", want, warnings(hook))
		}
	}

	// the file really did win - which is what the warning is about
	if cmd.AppConfig.AdminUsername != "admin" {
		t.Errorf("admin username = %q, want the file's", cmd.AppConfig.AdminUsername)
	}
}

// A key the file does not set is not overridden, and a warning would be noise.
func TestReadConfigIsQuietWhenTheFileLeavesTheEnvironmentAlone(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	t.Setenv("WG_ADMIN_USERNAME", "wireguardadmin")

	cmd := adminConfig(t, nil)
	cmd.AppConfig.Auth.Simple = nil
	cmd.ConfigFilePath = writeConfig(t, "loglevel: info\n")

	cmd.ReadConfig()

	if warnedAbout(hook, "WG_ADMIN_USERNAME") {
		t.Errorf("warned although the file sets no admin username: %q", warnings(hook))
	}
}

// Without the environment variable there is nothing to override, however much
// the file configures.
func TestReadConfigIsQuietWithoutTheEnvironmentVariable(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	cmd := adminConfig(t, nil)
	cmd.AppConfig.Auth.Simple = nil
	cmd.ConfigFilePath = writeConfig(t, `
adminUsername: "admin"
adminPassword: "from-the-file"
`)

	cmd.ReadConfig()

	if warnedAbout(hook, "WG_ADMIN_USERNAME") {
		t.Errorf("warned although nothing was overridden: %q", warnings(hook))
	}
}

// The pairs are written out by hand, so nothing but a test keeps them honest:
// a renamed environment variable would otherwise leave a warning that names
// one nobody can set.
func TestEveryOverridePairNamesARealEnvironmentVariable(t *testing.T) {
	app := kingpin.New("wg-access-server", "")
	Register(app)

	// The flags hang off the "serve" command, not off the application.
	known := map[string]bool{}
	for _, command := range app.Model().Commands {
		for _, flag := range command.Flags {
			if flag.Envar != "" {
				known[flag.Envar] = true
			}
		}
	}
	if len(known) == 0 {
		t.Fatal("no flags with an environment variable were found - this test is looking in the wrong place")
	}

	for _, both := range fileOverridesEnv {
		if !known[both.envar] {
			t.Errorf("%s is paired with the config key '%s' but no flag reads it", both.envar, both.key)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func warnedAbout(hook *test.Hook, envar string) bool {
	for _, message := range warnings(hook) {
		if strings.Contains(message, envar) && strings.Contains(message, "has no effect") {
			return true
		}
	}
	return false
}

// A setting under the wrong heading is dropped in silence: externalHost
// belongs at the top level, and under 'wireguard:' it configures nothing at
// all while reading as though it did. This is the shape of a real report.
func TestReadConfigWarnsAboutASettingInTheWrongPlace(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	cmd := adminConfig(t, nil)
	cmd.AppConfig.Auth.Simple = nil
	cmd.ConfigFilePath = writeConfig(t, `
loglevel: info
wireguard:
  externalHost: "vpn.example.com"
`)

	cmd.ReadConfig()

	if !warnedAboutUnknownKey(hook) {
		t.Errorf("nothing warned about externalHost under wireguard, got warnings: %q", warnings(hook))
	}
}

// ... and the warning has to stay quiet for a file that uses every setting
// there is, or it would be noise nobody reads. The fixture is the one the
// config file test already keeps up to date.
func TestTheUnknownKeyWarningIsQuietForAFullConfig(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	full, err := os.ReadFile(filepath.Join("testdata", "full-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	warnAboutUnknownKeys(full)

	if warnedAboutUnknownKey(hook) {
		t.Errorf("a config using every setting was reported as unknown: %q", warnings(hook))
	}
}

func warnedAboutUnknownKey(hook *test.Hook) bool {
	for _, message := range warnings(hook) {
		if strings.Contains(message, "does not know") {
			return true
		}
	}
	return false
}

// The decoder's error quotes the offending line of the file, so the warning
// must carry the field name and nothing else. A key that does not exist often
// holds a secret anyway - somebody mistyping 'adminPassword', or reaching for
// a name from another tool - and that value must not reach the log.
func TestUnknownKeyWarningDoesNotLeakTheValue(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	warnAboutUnknownKeys([]byte("adminPassphrase: \"correct-horse-battery-staple\"\n"))

	if !warnedAboutUnknownKey(hook) {
		t.Fatalf("the misspelled key was not reported, got warnings: %q", warnings(hook))
	}
	for _, message := range warnings(hook) {
		if strings.Contains(message, "correct-horse-battery-staple") {
			t.Errorf("the warning carries the value of the misspelled key: %q", message)
		}
	}
}
