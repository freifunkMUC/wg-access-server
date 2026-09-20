// Package hooks runs the commands an operator configured for the lifecycle of
// the WireGuard interface, the way wg-quick's PreUp/PostUp/PreDown/PostDown do.
//
// These commands run as whatever user the server runs as - root in most
// deployments, because configuring the VPN network needs it. Anyone who can
// write the config file therefore decides what the server executes as root,
// which is why they are read from the config file only (never from flags or
// environment variables) and why the file's permissions are checked before a
// single command is run.
package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Phases of the interface lifecycle, used for logging.
const (
	PreUp    = "preUp"
	PostUp   = "postUp"
	PreDown  = "preDown"
	PostDown = "postDown"
)

// interfacePlaceholder is replaced with the name of the WireGuard interface,
// like %i in a wg-quick configuration.
const interfacePlaceholder = "%i"

// VerifyConfigFile reports whether commands from this config file may be run.
// It refuses as soon as somebody other than the file's owner can write it,
// and when the owner is neither root nor the user this process runs as -
// in both cases that person would get to choose what the server executes.
func VerifyConfigFile(path string) error {
	if path == "" {
		return errors.New("no config file: lifecycle commands can only be configured in one")
	}

	info, err := os.Stat(path)
	if err != nil {
		return errors.Wrap(err, "failed to read the config file permissions")
	}

	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return errors.Errorf("config file %s is writable by group or others (mode %04o)", path, mode)
	}

	owner, ok := fileOwner(info)
	if !ok {
		return errors.Errorf("failed to determine the owner of the config file %s", path)
	}
	if owner != 0 && owner != uint32(os.Geteuid()) {
		return errors.Errorf("config file %s is owned by uid %d, which is neither root nor the user running the server (uid %d)",
			path, owner, os.Geteuid())
	}

	return nil
}

// Run executes the commands of one phase in order, through a shell so that an
// operator can write what they would type. It stops at the first failure:
// a command that did not run leaves the network in a state nobody asked for.
func Run(phase string, iface string, commands []string) error {
	for _, command := range commands {
		command = strings.ReplaceAll(command, interfacePlaceholder, iface)
		logrus.Infof("Running %s command: %s", phase, command)

		cmd := exec.Command("sh", "-c", command)
		cmd.Env = append(os.Environ(), fmt.Sprintf("WG_INTERFACE=%s", iface))

		output, err := cmd.CombinedOutput()
		if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
			logrus.Infof("%s command output: %s", phase, trimmed)
		}
		if err != nil {
			return errors.Wrapf(err, "%s command failed: %s", phase, command)
		}
	}

	return nil
}
