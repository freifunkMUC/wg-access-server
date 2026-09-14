// Package resolvconf reads the nameservers the host is configured to use.
//
// This replaces github.com/docker/docker/libnetwork/resolvconf, which pulled
// the whole Moby module in for the two calls made here.
package resolvconf

import (
	"net/netip"
	"os"
	"strings"
)

const (
	// defaultPath is where resolv.conf lives on every supported system.
	defaultPath = "/etc/resolv.conf"
	// systemdPath is what systemd-resolved manages. See nameserversFrom.
	systemdPath = "/run/systemd/resolve/resolv.conf"
	// systemdStub is the loopback address systemd-resolved advertises in
	// /etc/resolv.conf instead of the real upstream servers.
	systemdStub = "127.0.0.53"
)

// Nameservers returns the nameservers configured on this host, in the order
// they appear in resolv.conf. It returns nil when the file cannot be read or
// lists no usable nameserver; callers are expected to fall back to a default.
func Nameservers() []string {
	return nameserversFrom(defaultPath, systemdPath)
}

func nameserversFrom(primary, systemd string) []string {
	nameservers := parseFile(primary)

	// When systemd-resolved is in charge it publishes only its own stub
	// resolver in /etc/resolv.conf. That address is useless as an upstream -
	// forwarding to it either loops back to ourselves or, in a container,
	// points at nothing - so read the file systemd-resolved actually manages.
	// If that file is unreadable we report no nameserver at all rather than
	// handing the stub to the caller.
	if len(nameservers) == 1 && nameservers[0] == systemdStub {
		return parseFile(systemd)
	}

	return nameservers
}

func parseFile(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseNameservers(content)
}

// parseNameservers extracts the nameserver entries from resolv.conf content,
// following resolv.conf(5): fields are whitespace separated, '#' and ';' start
// a comment line, and an entry that is not a valid IP address is ignored.
func parseNameservers(content []byte) []string {
	var nameservers []string

	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0][0] == '#' || fields[0][0] == ';' {
			continue
		}
		if fields[0] != "nameserver" || len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		// String() rather than the raw field, so addresses are normalised the
		// same way the previous implementation normalised them.
		nameservers = append(nameservers, addr.String())
	}

	return nameservers
}
