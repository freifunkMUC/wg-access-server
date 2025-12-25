package serve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		content     string
		expected    string
		shouldError bool
	}{
		{
			name:        "simple password",
			content:     "mypassword123",
			expected:    "mypassword123",
			shouldError: false,
		},
		{
			name:        "password with newline",
			content:     "mypassword123\n",
			expected:    "mypassword123",
			shouldError: false,
		},
		{
			name:        "password with trailing spaces",
			content:     "mypassword123  \n",
			expected:    "mypassword123",
			shouldError: false,
		},
		{
			name:        "password with leading and trailing whitespace",
			content:     "  mypassword123  \n",
			expected:    "mypassword123",
			shouldError: false,
		},
		{
			name:        "empty file",
			content:     "",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "only whitespace",
			content:     "  \n\t\n  ",
			expected:    "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tmpDir, tt.name)
			if err := os.WriteFile(testFile, []byte(tt.content), 0600); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Read secret from file
			result, err := readSecretFromFile(testFile)

			// Check error condition
			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check result
			if result != tt.expected {
				t.Errorf("Expected %q but got %q", tt.expected, result)
			}
		})
	}
}

func TestReadSecretFromFile_NonExistent(t *testing.T) {
	_, err := readSecretFromFile("/tmp/non-existent-file-12345")
	if err == nil {
		t.Error("Expected error for non-existent file but got none")
	}
}

func TestReadSecretFromFile_EmptyPath(t *testing.T) {
	result, err := readSecretFromFile("")
	if err != nil {
		t.Errorf("Unexpected error for empty path: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string for empty path, got %q", result)
	}
}
