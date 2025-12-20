package scriptrunner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ValidateScriptSecurity checks that a script file meets security requirements:
// - The file must exist
// - The file must be owned by root (UID 0)
// - The file must not be writable by others
func ValidateScriptSecurity(scriptPath string) error {
	if scriptPath == "" {
		return nil // Empty path is valid (no script configured)
	}

	// Get absolute path
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve absolute path for script: %s", scriptPath)
	}

	// Check if file exists
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return errors.Wrapf(err, "failed to stat script file: %s", absPath)
	}

	// Ensure it's a regular file
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("script path is not a regular file: %s", absPath)
	}

	// Get file ownership and permissions
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get file system stats for script: %s", absPath)
	}

	// Check that the file is owned by root (UID 0)
	if stat.Uid != 0 {
		return fmt.Errorf("script file must be owned by root (UID 0), found UID %d: %s", stat.Uid, absPath)
	}

	// Check that others don't have write permission (check the 3rd bit from the right)
	mode := fileInfo.Mode()
	if mode.Perm()&0002 != 0 {
		return fmt.Errorf("script file must not be writable by others: %s (permissions: %s)", absPath, mode.Perm().String())
	}

	return nil
}

// RunScript executes a script file if it's configured and passes security validation.
// It logs the execution and any output from the script.
func RunScript(scriptPath string, scriptName string) error {
	if scriptPath == "" {
		return nil // No script configured, nothing to do
	}

	// Validate security before running
	if err := ValidateScriptSecurity(scriptPath); err != nil {
		return errors.Wrapf(err, "security validation failed for %s script", scriptName)
	}

	// Get absolute path for logging and execution
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve absolute path for %s script: %s", scriptName, scriptPath)
	}

	logrus.Infof("Running %s script: %s", scriptName, absPath)

	// Execute the script
	cmd := exec.Command(absPath)
	output, err := cmd.CombinedOutput()

	// Log the output regardless of success or failure
	if len(output) > 0 {
		logrus.Infof("%s script output: %s", scriptName, string(output))
	}

	if err != nil {
		return errors.Wrapf(err, "%s script execution failed: %s", scriptName, absPath)
	}

	logrus.Infof("%s script completed successfully", scriptName)
	return nil
}
