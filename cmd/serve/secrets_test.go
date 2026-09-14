package serve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadSecretFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{name: "no trailing newline", content: "hunter2", want: "hunter2"},
		{name: "one trailing newline", content: "hunter2\n", want: "hunter2"},
		{name: "several trailing newlines", content: "hunter2\n\n\n", want: "hunter2"},
		{name: "CRLF from a Windows editor", content: "hunter2\r\n", want: "hunter2"},
		{name: "spaces are part of the secret", content: "  hunter 2  \n", want: "  hunter 2  "},
		{name: "inner newlines are kept", content: "line1\nline2\n", want: "line1\nline2"},
		{name: "empty file", content: "", wantErr: true},
		{name: "only a newline", content: "\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSecretFile(writeSecret(t, tt.content))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("readSecretFile() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSecretFile() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("readSecretFile() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := readSecretFile(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("want an error for a missing file")
		}
	})
}

func TestLoadSecretFiles(t *testing.T) {
	t.Run("nothing configured leaves values alone", func(t *testing.T) {
		cmd := &servecmd{}
		cmd.AppConfig.AdminPassword = "direct"
		if err := cmd.loadSecretFiles(); err != nil {
			t.Fatal(err)
		}
		if cmd.AppConfig.AdminPassword != "direct" {
			t.Errorf("AdminPassword = %q, want it unchanged", cmd.AppConfig.AdminPassword)
		}
	})

	t.Run("files fill both secrets", func(t *testing.T) {
		cmd := &servecmd{
			AdminPasswordFile:       writeSecret(t, "hunter2\n"),
			WireGuardPrivateKeyFile: writeSecret(t, "cGxhY2Vob2xkZXIta2V5LW5vdC1yZWFsLWJhc2U2NA==\n"),
		}
		if err := cmd.loadSecretFiles(); err != nil {
			t.Fatal(err)
		}
		if cmd.AppConfig.AdminPassword != "hunter2" {
			t.Errorf("AdminPassword = %q", cmd.AppConfig.AdminPassword)
		}
		if cmd.AppConfig.WireGuard.PrivateKey != "cGxhY2Vob2xkZXIta2V5LW5vdC1yZWFsLWJhc2U2NA==" {
			t.Errorf("PrivateKey = %q", cmd.AppConfig.WireGuard.PrivateKey)
		}
	})

	// A direct value may come from the flag, the environment or the config file;
	// by the time loadSecretFiles runs they all look the same.
	t.Run("a direct value next to a file is rejected", func(t *testing.T) {
		cmd := &servecmd{AdminPasswordFile: writeSecret(t, "from-file")}
		cmd.AppConfig.AdminPassword = "from-env-or-config"

		err := cmd.loadSecretFiles()
		if err == nil {
			t.Fatal("want an error when both are set")
		}
		for _, want := range []string{"WG_ADMIN_PASSWORD_FILE", "exclusive"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
		if cmd.AppConfig.AdminPassword != "from-env-or-config" {
			t.Errorf("AdminPassword was changed to %q despite the error", cmd.AppConfig.AdminPassword)
		}
	})

	t.Run("an empty key file is an error, not a generated key", func(t *testing.T) {
		cmd := &servecmd{WireGuardPrivateKeyFile: writeSecret(t, "\n")}
		err := cmd.loadSecretFiles()
		if err == nil {
			t.Fatal("want an error for an empty key file")
		}
		if !strings.Contains(err.Error(), "WG_WIREGUARD_PRIVATE_KEY_FILE") {
			t.Errorf("error %q does not name the variable", err)
		}
	})

	t.Run("the error never contains the secret", func(t *testing.T) {
		cmd := &servecmd{AdminPasswordFile: writeSecret(t, "super-secret-value")}
		cmd.AppConfig.AdminPassword = "another-secret-value"
		err := cmd.loadSecretFiles()
		if err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(err.Error(), "secret-value") {
			t.Errorf("error leaks a secret: %q", err)
		}
	})
}
