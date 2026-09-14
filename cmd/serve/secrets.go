package serve

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// secretSource describes a setting that may alternatively be read from a file,
// following the <VAR>_FILE convention of the Docker Official Images (postgres,
// mysql, ...). Docker and Kubernetes mount secrets as files, which keeps them out
// of the environment where they leak into process listings and debug output.
type secretSource struct {
	// value is the setting itself, already filled from the flag, the
	// environment or the config file.
	value *string
	// file is the path given through the _FILE flag or environment variable.
	file string
	// direct names every way to set the value directly, for error messages.
	direct string
	// fileEnv is the environment variable holding the path.
	fileEnv string
}

func (cmd *servecmd) secretSources() []secretSource {
	return []secretSource{
		{
			value:   &cmd.AppConfig.AdminPassword,
			file:    cmd.AdminPasswordFile,
			direct:  "WG_ADMIN_PASSWORD / --admin-password / adminPassword",
			fileEnv: "WG_ADMIN_PASSWORD_FILE",
		},
		{
			value:   &cmd.AppConfig.WireGuard.PrivateKey,
			file:    cmd.WireGuardPrivateKeyFile,
			direct:  "WG_WIREGUARD_PRIVATE_KEY / --wireguard-private-key / wireguard.privateKey",
			fileEnv: "WG_WIREGUARD_PRIVATE_KEY_FILE",
		},
	}
}

// loadSecretFiles resolves every _FILE setting. It runs after the config file
// has been read, so a value from any source counts as "set directly".
func (cmd *servecmd) loadSecretFiles() error {
	for _, source := range cmd.secretSources() {
		if err := source.load(); err != nil {
			return err
		}
	}
	return nil
}

func (s secretSource) load() error {
	if s.file == "" {
		return nil
	}
	// Refuse to pick a winner: a leftover direct value next to a secret file is
	// a misconfiguration, and silently preferring either hides it.
	if *s.value != "" {
		return fmt.Errorf("both %s and %s are set, but they are exclusive", s.direct, s.fileEnv)
	}
	secret, err := readSecretFile(s.file)
	if err != nil {
		return errors.Wrapf(err, "failed to read %s", s.fileEnv)
	}
	*s.value = secret
	return nil
}

// readSecretFile returns the content of a secret file without its trailing line
// break(s), matching how a shell reads $(< file). A trailing carriage return is
// dropped as well, so files edited on Windows work. Any other whitespace is
// kept, since it may be part of the secret.
func readSecretFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimRight(string(content), "\r\n")
	// An empty secret is never intended. For the WireGuard key it would be
	// especially harmful: with memory:// storage an empty key is silently
	// replaced by a random one, and every device would have to re-register.
	if secret == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}
