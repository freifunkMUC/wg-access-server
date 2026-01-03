package serve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/freifunkMUC/wg-access-server/internal/config"
)

func TestDockerSecretsIntegration(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "docker-secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test secret files
	adminPasswordFile := filepath.Join(tmpDir, "admin_password")
	wgKeyFile := filepath.Join(tmpDir, "wg_private_key")

	adminPassword := "test-admin-password-123"
	wgKey := "OFZJj+DRxCtXWJd8LR7fP4gLQ1LgwH7j7WH1fLHOCmw="

	if err := os.WriteFile(adminPasswordFile, []byte(adminPassword+"\n"), 0600); err != nil {
		t.Fatalf("Failed to write admin password file: %v", err)
	}
	if err := os.WriteFile(wgKeyFile, []byte(wgKey+"\n"), 0600); err != nil {
		t.Fatalf("Failed to write wireguard key file: %v", err)
	}

	// Test 1: Admin password file only
	t.Run("AdminPasswordFile", func(t *testing.T) {
		cmd := &servecmd{
			AdminPasswordFile: adminPasswordFile,
			AppConfig:         config.AppConfig{
				Storage: "memory://", // Required for auto-generated key
			},
		}

		conf := cmd.ReadConfig()
		if conf.AdminPassword != adminPassword {
			t.Errorf("Expected admin password %q, got %q", adminPassword, conf.AdminPassword)
		}
	})

	// Test 2: Wireguard private key file only
	t.Run("WireguardPrivateKeyFile", func(t *testing.T) {
		cmd := &servecmd{
			WireguardPrivateKeyFile: wgKeyFile,
			AppConfig: config.AppConfig{
				AdminPassword: "dummy", // Required to pass validation
			},
		}

		conf := cmd.ReadConfig()
		if conf.WireGuard.PrivateKey != wgKey {
			t.Errorf("Expected wireguard key %q, got %q", wgKey, conf.WireGuard.PrivateKey)
		}
	})

	// Test 3: Both files
	t.Run("BothFiles", func(t *testing.T) {
		cmd := &servecmd{
			AdminPasswordFile:       adminPasswordFile,
			WireguardPrivateKeyFile: wgKeyFile,
			AppConfig:               config.AppConfig{},
		}

		conf := cmd.ReadConfig()
		if conf.AdminPassword != adminPassword {
			t.Errorf("Expected admin password %q, got %q", adminPassword, conf.AdminPassword)
		}
		if conf.WireGuard.PrivateKey != wgKey {
			t.Errorf("Expected wireguard key %q, got %q", wgKey, conf.WireGuard.PrivateKey)
		}
	})

	// Test 4: File overrides direct value
	t.Run("FileOverridesDirectValue", func(t *testing.T) {
		directPassword := "direct-password"
		directKey := "direct-key"

		cmd := &servecmd{
			AdminPasswordFile:       adminPasswordFile,
			WireguardPrivateKeyFile: wgKeyFile,
			AppConfig: config.AppConfig{
				AdminPassword: directPassword,
			},
		}
		cmd.AppConfig.WireGuard.PrivateKey = directKey

		conf := cmd.ReadConfig()
		if conf.AdminPassword != adminPassword {
			t.Errorf("Expected file-based admin password %q to override direct value, got %q", adminPassword, conf.AdminPassword)
		}
		if conf.WireGuard.PrivateKey != wgKey {
			t.Errorf("Expected file-based wireguard key %q to override direct value, got %q", wgKey, conf.WireGuard.PrivateKey)
		}
	})
}

func TestRegisterFlags(t *testing.T) {
	app := kingpin.New("test-app", "Test application")
	cmd := Register(app)

	// Verify the struct has the new fields
	if cmd.AdminPasswordFile != "" {
		t.Error("AdminPasswordFile should be empty initially")
	}
	if cmd.WireguardPrivateKeyFile != "" {
		t.Error("WireguardPrivateKeyFile should be empty initially")
	}
}
