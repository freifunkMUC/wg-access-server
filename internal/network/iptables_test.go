package network

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inNetns marks the run that happens inside the network namespace.
const inNetns = "WG_TEST_IN_NETNS"

// netnsTest runs the test again in a network namespace of its own, where it
// can set up firewall rules without root and without touching the machine.
//
// It returns true in the inner run, where the body belongs. The CI sets
// WG_TEST_NFTABLES, so that a runner without the tools fails the test instead
// of skipping it unnoticed.
func netnsTest(t *testing.T, tools ...string) bool {
	t.Helper()
	if os.Getenv(inNetns) != "" {
		return true
	}

	skip := t.Skipf
	if os.Getenv("WG_TEST_NFTABLES") != "" {
		skip = t.Fatalf
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			skip("%s is not installed", tool)
		}
	}
	if err := exec.Command("unshare", "--net", "--map-root-user", "true").Run(); err != nil {
		skip("cannot create a network namespace: %v", err)
	}

	inner := exec.Command("unshare", "--net", "--map-root-user",
		os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v")
	inner.Env = append(os.Environ(), inNetns+"=1")
	out, err := inner.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Log(string(out))
	return false
}

// The rules the iptables backend sets up, in the order it sets them up: an
// accept for an allowed network only counts before the reject that follows.
func TestIPTablesRules(t *testing.T) {
	if !netnsTest(t, "iptables", "ip6tables") {
		return
	}

	err := ConfigureForwarding(ForwardingOptions{
		Firewall:        FirewallIPTables,
		GatewayIface:    "eth0",
		CIDR:            "10.44.0.0/24",
		CIDRv6:          "fd48:4c4:7aa9::/64",
		NAT44:           true,
		NAT66:           false,
		ClientIsolation: true,
		AllowedIPs:      []string{"192.168.1.0/24", "2001:db8::/32"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"-A FORWARD -j WG_ACCESS_SERVER_FORWARD",
		"-A WG_ACCESS_SERVER_FORWARD -s 10.44.0.0/24 -d 10.44.0.0/24 -j REJECT --reject-with icmp-port-unreachable",
		"-A WG_ACCESS_SERVER_FORWARD -s 10.44.0.0/24 -d 192.168.1.0/24 -j ACCEPT",
		"-A WG_ACCESS_SERVER_FORWARD -s 10.44.0.0/24 -j REJECT --reject-with icmp-port-unreachable",
	}, rules(t, "iptables-save", "filter"))

	assert.Equal(t, []string{
		"-A POSTROUTING -j WG_ACCESS_SERVER_POSTROUTING",
		"-A WG_ACCESS_SERVER_POSTROUTING -s 10.44.0.0/24 -o eth0 -j MASQUERADE",
	}, rules(t, "iptables-save", "nat"))

	// without NAT the answers come back to the clients' own addresses
	assert.Equal(t, []string{
		"-A FORWARD -j WG_ACCESS_SERVER_FORWARD",
		"-A WG_ACCESS_SERVER_FORWARD -s fd48:4c4:7aa9::/64 -d fd48:4c4:7aa9::/64 -j REJECT --reject-with icmp6-port-unreachable",
		"-A WG_ACCESS_SERVER_FORWARD -s fd48:4c4:7aa9::/64 -d 2001:db8::/32 -j ACCEPT",
		"-A WG_ACCESS_SERVER_FORWARD -s 2001:db8::/32 -d fd48:4c4:7aa9::/64 -j ACCEPT",
		"-A WG_ACCESS_SERVER_FORWARD -s fd48:4c4:7aa9::/64 -j REJECT --reject-with icmp6-port-unreachable",
	}, rules(t, "ip6tables-save", "filter"))

	// NAT66 is off, so nothing is masqueraded
	assert.Equal(t, []string{"-A POSTROUTING -j WG_ACCESS_SERVER_POSTROUTING"}, rules(t, "ip6tables-save", "nat"))
}

// Starting again replaces the rules of the previous start instead of adding
// to them - the allowed networks of a moment ago must stop applying.
func TestIPTablesRulesAreReplaced(t *testing.T) {
	if !netnsTest(t, "iptables", "ip6tables") {
		return
	}

	options := ForwardingOptions{
		Firewall: FirewallIPTables, GatewayIface: "eth0", CIDR: "10.44.0.0/24",
		NAT44: true, AllowedIPs: []string{"192.168.1.0/24"},
	}
	require.NoError(t, ConfigureForwarding(options))

	options.AllowedIPs = []string{"10.9.0.0/16"}
	require.NoError(t, ConfigureForwarding(options))

	assert.Equal(t, []string{
		"-A FORWARD -j WG_ACCESS_SERVER_FORWARD",
		"-A WG_ACCESS_SERVER_FORWARD -s 10.44.0.0/24 -d 10.9.0.0/16 -j ACCEPT",
		"-A WG_ACCESS_SERVER_FORWARD -s 10.44.0.0/24 -j REJECT --reject-with icmp-port-unreachable",
	}, rules(t, "iptables-save", "filter"))
}

// rules returns the rules of one table, in order.
func rules(t *testing.T, save string, table string) []string {
	t.Helper()
	out, err := exec.Command(save, "-t", table).Output()
	require.NoError(t, err)

	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A ") {
			found = append(found, strings.TrimSpace(line))
		}
	}
	return found
}
