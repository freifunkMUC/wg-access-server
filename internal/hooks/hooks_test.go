package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("wireguard:\n  postUp: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// Whoever can write the config file decides what the server runs as root, so
// the file has to be writable by its owner only.
func TestVerifyConfigFile(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr string
	}{
		{name: "owner only", mode: 0o600},
		{name: "readable by everyone", mode: 0o644},
		{name: "group writable", mode: 0o620, wantErr: "writable by group or others"},
		{name: "world writable", mode: 0o606, wantErr: "writable by group or others"},
		{name: "writable by everyone", mode: 0o666, wantErr: "writable by group or others"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyConfigFile(configFile(t, tt.mode))

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyConfigFile with mode %04o = %v, want no error", tt.mode, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyConfigFile accepted mode %04o", tt.mode)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyConfigFileWithoutAFile(t *testing.T) {
	if err := VerifyConfigFile(""); err == nil {
		t.Error("commands were accepted without a config file")
	}
	if err := VerifyConfigFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing config file was accepted")
	}
}

func TestRunExecutesEveryCommandInOrder(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")

	err := Run(PostUp, "wg0", []string{
		"echo first >> " + log,
		"echo second >> " + log,
	})
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(content); got != "first\nsecond\n" {
		t.Errorf("commands wrote %q, want %q", got, "first\nsecond\n")
	}
}

// %i is what an operator knows from wg-quick.
func TestRunSubstitutesTheInterfaceName(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")

	if err := Run(PostUp, "wg42", []string{"echo %i $WG_INTERFACE > " + out}); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(out)
	if got := strings.TrimSpace(string(content)); got != "wg42 wg42" {
		t.Errorf("command saw %q, want %q", got, "wg42 wg42")
	}
}

// A command that fails leaves the network half configured, so the rest must
// not run and the caller has to hear about it.
func TestRunStopsAtTheFirstFailure(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")

	err := Run(PreUp, "wg0", []string{"exit 3", "echo ran > " + out})
	if err == nil {
		t.Fatal("a failing command was ignored")
	}
	if !strings.Contains(err.Error(), "preUp") {
		t.Errorf("error %q does not name the phase", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("the command after the failing one still ran")
	}
}

func TestRunWithoutCommands(t *testing.T) {
	if err := Run(PostDown, "wg0", nil); err != nil {
		t.Errorf("running no commands returned %v", err)
	}
}
