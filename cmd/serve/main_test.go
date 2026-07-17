package serve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// fatalPanic is the sentinel our test ExitFunc panics with so we can
// distinguish an intercepted logrus.Fatal from any other panic.
type fatalPanic struct{ code int }

// runReadConfig invokes cmd.ReadConfig while intercepting logrus.Fatal.
// logrus.Fatal logs and then calls the standard logger's ExitFunc (os.Exit
// by default), which would kill the test binary. We swap the ExitFunc for
// one that panics with a sentinel and recover it, and capture log output in
// a buffer so tests can assert on the fatal message.
//
// It returns the config (nil if Fatal fired), whether Fatal fired, and the
// captured log output. Tests using this helper must not run in parallel
// because it mutates the global standard logger.
func runReadConfig(t *testing.T, cmd *servecmd) (conf *config.AppConfig, fataled bool, logOutput string) {
	t.Helper()

	logger := logrus.StandardLogger()

	prevOut := logger.Out
	prevExit := logger.ExitFunc
	var buf bytes.Buffer
	logger.SetOutput(&buf)
	logger.ExitFunc = func(code int) { panic(fatalPanic{code: code}) }
	defer func() {
		logger.SetOutput(prevOut)
		logger.ExitFunc = prevExit
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(fatalPanic); !ok {
					panic(r) // not ours; re-raise
				}
				fataled = true
				conf = nil
			}
		}()
		conf = cmd.ReadConfig()
	}()

	return conf, fataled, buf.String()
}

func TestReadConfigFatalsOnUnreadableConfigFile(t *testing.T) {
	cmd := &servecmd{
		ConfigFilePath: filepath.Join(t.TempDir(), "does-not-exist.yaml"),
	}

	conf, fataled, logOutput := runReadConfig(t, cmd)

	if !fataled {
		t.Fatal("expected logrus.Fatal when the config file cannot be read, but ReadConfig returned normally")
	}
	if conf != nil {
		t.Errorf("expected no config to be returned on fatal, got %+v", conf)
	}
	if !strings.Contains(logOutput, "failed to read configuration file") {
		t.Errorf("expected fatal log to contain %q, got: %s", "failed to read configuration file", logOutput)
	}
}

func TestReadConfigFatalsOnInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: [not, a, number\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := &servecmd{ConfigFilePath: path}

	_, fataled, logOutput := runReadConfig(t, cmd)

	if !fataled {
		t.Fatal("expected logrus.Fatal on invalid YAML, but ReadConfig returned normally")
	}
	if !strings.Contains(logOutput, "failed to bind configuration file") {
		t.Errorf("expected fatal log to contain %q, got: %s", "failed to bind configuration file", logOutput)
	}
}

func TestReadConfigReadsValidConfigFile(t *testing.T) {
	// ReadConfig performs additional validation after unmarshalling: it
	// Fatals if no auth is configured and AdminPassword is empty, and it
	// Fatals if WireGuard.PrivateKey is empty while Storage is not
	// memory://. Provide adminPassword and memory:// storage so the happy
	// path completes without needing root, netlink, or a wireguard device.
	yamlContent := "" +
		"port: 12345\n" +
		"adminUsername: tester\n" +
		"adminPassword: secret\n" +
		"storage: memory://\n"

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := &servecmd{ConfigFilePath: path}

	conf, fataled, logOutput := runReadConfig(t, cmd)

	if fataled {
		t.Fatalf("expected no fatal for a valid config file, got fatal with log: %s", logOutput)
	}
	if conf == nil {
		t.Fatal("expected a non-nil AppConfig")
	}
	if conf.Port != 12345 {
		t.Errorf("expected Port from config file to be 12345, got %d", conf.Port)
	}
	if conf.Storage != "memory://" {
		t.Errorf("expected Storage from config file to be memory://, got %q", conf.Storage)
	}
	// Post-unmarshal defaulting: a private key is generated for memory:// storage.
	if conf.WireGuard.PrivateKey == "" {
		t.Error("expected a WireGuard private key to be generated for memory:// storage")
	}
	// AdminPassword should have been turned into a simple-auth user entry.
	if conf.Auth.Simple == nil || len(conf.Auth.Simple.Users) != 1 {
		t.Error("expected simple auth to be configured for the admin user")
	} else if !strings.HasPrefix(conf.Auth.Simple.Users[0], "tester:") {
		t.Errorf("expected simple auth user entry for %q, got %q", "tester", conf.Auth.Simple.Users[0])
	}
}

func TestReadConfigEmptyPathUsesDefaults(t *testing.T) {
	// With an empty ConfigFilePath no file is read and no Fatal must fire.
	// The struct is built directly (kingpin defaults do not apply), so set
	// the minimum fields the post-unmarshal validation requires.
	cmd := &servecmd{}
	cmd.AppConfig.AdminPassword = "secret"
	cmd.AppConfig.Storage = "memory://"

	conf, fataled, logOutput := runReadConfig(t, cmd)

	if fataled {
		t.Fatalf("expected no fatal for empty ConfigFilePath, got fatal with log: %s", logOutput)
	}
	if conf == nil {
		t.Fatal("expected a non-nil AppConfig")
	}
	if conf.Port != 0 {
		t.Errorf("expected zero-value Port when no config file is given, got %d", conf.Port)
	}
}
