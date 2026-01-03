package scriptrunner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateScriptSecurity_EmptyPath(t *testing.T) {
	// Empty path should be valid (no script configured)
	err := ValidateScriptSecurity("")
	if err != nil {
		t.Errorf("Expected no error for empty path, got: %v", err)
	}
}

func TestValidateScriptSecurity_NonExistentFile(t *testing.T) {
	err := ValidateScriptSecurity("/nonexistent/script.sh")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestValidateScriptSecurity_ValidScript(t *testing.T) {
	// Create a temporary script file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	// Create the script
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Change ownership to root (will only work if test is run as root)
	// For non-root tests, we skip this
	if os.Getuid() == 0 {
		if err := os.Chown(scriptPath, 0, 0); err != nil {
			t.Fatalf("Failed to chown script: %v", err)
		}

		err := ValidateScriptSecurity(scriptPath)
		if err != nil {
			t.Errorf("Expected no error for valid script, got: %v", err)
		}
	} else {
		t.Skip("Skipping test that requires root permissions")
	}
}

func TestValidateScriptSecurity_OthersWritable(t *testing.T) {
	// Create a temporary script file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	// Create the script with world-writable permissions
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0777); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	if os.Getuid() == 0 {
		if err := os.Chown(scriptPath, 0, 0); err != nil {
			t.Fatalf("Failed to chown script: %v", err)
		}

		err := ValidateScriptSecurity(scriptPath)
		if err == nil {
			t.Error("Expected error for world-writable script")
		}
	} else {
		t.Skip("Skipping test that requires root permissions")
	}
}

func TestValidateScriptSecurity_GroupWritable(t *testing.T) {
	// Create a temporary script file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	// Create the script with group-writable permissions
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0770); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	if os.Getuid() == 0 {
		if err := os.Chown(scriptPath, 0, 0); err != nil {
			t.Fatalf("Failed to chown script: %v", err)
		}

		err := ValidateScriptSecurity(scriptPath)
		if err == nil {
			t.Error("Expected error for group-writable script")
		}
	} else {
		t.Skip("Skipping test that requires root permissions")
	}
}

func TestValidateScriptSecurity_NonRootGroup(t *testing.T) {
	// Create a temporary script file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	// Create the script
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	if os.Getuid() == 0 {
		// Set ownership to root user but non-root group (e.g., GID 1000)
		if err := os.Chown(scriptPath, 0, 1000); err != nil {
			t.Fatalf("Failed to chown script: %v", err)
		}

		err := ValidateScriptSecurity(scriptPath)
		if err == nil {
			t.Error("Expected error for non-root group")
		}
	} else {
		t.Skip("Skipping test that requires root permissions")
	}
}

func TestRunScript_EmptyPath(t *testing.T) {
	// Empty path should be valid (no script to run)
	err := RunScript("", "Test")
	if err != nil {
		t.Errorf("Expected no error for empty path, got: %v", err)
	}
}

func TestRunScript_ValidScript(t *testing.T) {
	// Create a temporary script file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	// Create a simple script that exits successfully
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\nexit 0"), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	if os.Getuid() == 0 {
		if err := os.Chown(scriptPath, 0, 0); err != nil {
			t.Fatalf("Failed to chown script: %v", err)
		}

		err := RunScript(scriptPath, "Test")
		if err != nil {
			t.Errorf("Expected no error for valid script, got: %v", err)
		}
	} else {
		t.Skip("Skipping test that requires root permissions")
	}
}
