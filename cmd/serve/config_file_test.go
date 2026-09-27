package serve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// TestConfigFileIsReadInFull parses a configuration file that uses every
// section, so that a change to the parsing cannot quietly drop one.
func TestConfigFileIsReadInFull(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "full-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var conf config.AppConfig
	if err := yaml.Unmarshal(data, &conf); err != nil {
		t.Fatalf("the configuration was not accepted: %v", err)
	}

	for _, tc := range []struct {
		what string
		got  any
		want any
	}{
		{"loglevel", conf.LogLevel, "debug"},
		{"port", conf.Port, 8000},
		{"storage", conf.Storage, "postgresql://user:pass@localhost:5432/db?sslmode=disable"},
		{"grace period", conf.InactiveDeviceGracePeriod.String(), "720h0m0s"},
		{"wireguard interface", conf.WireGuard.Interface, "wg0"},
		{"post up hooks", len(conf.WireGuard.PostUp), 2},
		{"vpn cidr", conf.VPN.CIDR, "10.44.0.0/24"},
		{"firewall", conf.VPN.Firewall, "nftables"},
		{"dns upstreams", len(conf.DNS.Upstream), 2},
		{"dns domain", conf.DNS.Domain, "vpn.home.arpa."},
		// the yaml key of this one is spelled with a capital letter
		{"client keepalive", conf.ClientConfig.PersistentKeepalive, 25},
		{"metrics user", conf.Metrics.BasicAuth.Username, "prom"},
		{"metrics cap", conf.Metrics.MaxDeviceSeries, 500},
		{"https port", conf.HTTPS.Port, 8443},
		{"oidc issuer", conf.Auth.OIDC.Issuer, "https://id.example.com/realms/demo"},
		{"claim mappings", len(conf.Auth.OIDC.ClaimMapping), 2},
		{"github teams", len(conf.Auth.Github.Teams), 1},
		{"simple users", len(conf.Auth.Simple.Users), 1},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.what, tc.got, tc.want)
		}
	}
}

// TestEmptyConfigFileIsAccepted matters for the container image, which ships
// an empty /config.yaml so that a deployment configured through environment
// variables alone still starts.
func TestEmptyConfigFileIsAccepted(t *testing.T) {
	for name, doc := range map[string]string{"empty": "", "only comments": "# nothing configured here\n"} {
		t.Run(name, func(t *testing.T) {
			var conf config.AppConfig
			if err := yaml.Unmarshal([]byte(doc), &conf); err != nil {
				t.Fatalf("an empty configuration was refused: %v", err)
			}
			if conf.Port != 0 || conf.Storage != "" {
				t.Errorf("an empty configuration set something: %+v", conf)
			}
		})
	}
}

// TestDuplicateKeyIsRefused documents what happens to a configuration that
// says two different things about the same setting: it is refused, naming
// both lines, rather than one of them quietly winning.
func TestDuplicateKeyIsRefused(t *testing.T) {
	var conf config.AppConfig
	err := yaml.Unmarshal([]byte("port: 1\nport: 2\n"), &conf)
	if err == nil {
		t.Fatalf("the duplicate key was accepted, port = %d", conf.Port)
	}
	t.Logf("refused with: %v", err)
}

// TestConfigFileKeepsWhatItDoesNotMention covers how the configuration is
// layered: the flags and the environment are read into it first, and the file
// is laid over them. A file that mentions nothing - the empty one the
// container image ships - has to leave all of that alone.
func TestConfigFileKeepsWhatItDoesNotMention(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":         "",
		"only comments": "# nothing configured here\n",
		"explicit null": "~\n",
		"one setting":   "port: 9000\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := &servecmd{ConfigFilePath: path}
			// what the flags and the environment left behind
			cmd.AppConfig.AdminUsername = "admin"
			cmd.AppConfig.AdminPassword = "from-the-environment"
			cmd.AppConfig.Storage = "memory://"
			cmd.AppConfig.Port = 8000
			cmd.AppConfig.HttpEnabled = true
			cmd.AppConfig.WireGuard.Interface = "wg0"
			cmd.AppConfig.WireGuard.PrivateKey = "<the output of wg genkey>"

			conf, fataled, logOutput := runReadConfig(t, cmd)
			if fataled {
				t.Fatalf("reading the configuration failed: %s", logOutput)
			}
			if conf.Storage != "memory://" || !conf.HttpEnabled || conf.AdminUsername != "admin" ||
				conf.WireGuard.Interface != "wg0" {
				t.Errorf("the file cleared what it does not mention: %+v", conf)
			}
			want := 8000
			if doc == "port: 9000\n" {
				want = 9000
			}
			if conf.Port != want {
				t.Errorf("port = %d, want %d", conf.Port, want)
			}
		})
	}
}
