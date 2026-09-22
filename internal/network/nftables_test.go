package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ruleset(t *testing.T, options ForwardingOptions) string {
	t.Helper()
	options, err := splitAllowedIPs(options)
	require.NoError(t, err)
	rules, err := nftablesRuleset(options)
	require.NoError(t, err)
	return rules
}

// The defaults: dual stack, everything allowed, NAT for both families.
func TestNftablesRulesetDefaults(t *testing.T) {
	rules := ruleset(t, ForwardingOptions{
		GatewayIface: "eth0",
		CIDR:         "10.44.0.0/24",
		CIDRv6:       "fd48:4c4:7aa9::/64",
		NAT44:        true,
		NAT66:        true,
		AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
	})

	assert.Equal(t, `table inet wg_access_server
delete table inet wg_access_server
table inet wg_access_server {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr 10.44.0.0/24 ip daddr 0.0.0.0/0 accept
		ip saddr 10.44.0.0/24 reject
		ip6 saddr fd48:4c4:7aa9::/64 ip6 daddr ::/0 accept
		ip6 saddr fd48:4c4:7aa9::/64 reject
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.44.0.0/24 oifname "eth0" masquerade
		ip6 saddr fd48:4c4:7aa9::/64 oifname "eth0" masquerade
	}
}
`, rules)
}

// Isolation first, then the allowed networks both ways because without NAT
// the answers are addressed to the clients, then the final reject.
func TestNftablesRulesetIsolatedWithoutNAT(t *testing.T) {
	rules := ruleset(t, ForwardingOptions{
		GatewayIface:    "eth0",
		CIDR:            "10.44.0.0/24",
		ClientIsolation: true,
		NAT44:           false,
		AllowedIPs:      []string{"192.168.1.0/24"},
	})

	assert.Contains(t, rules, `		ip saddr 10.44.0.0/24 ip daddr 10.44.0.0/24 reject
		ip saddr 10.44.0.0/24 ip daddr 192.168.1.0/24 accept
		ip saddr 192.168.1.0/24 ip daddr 10.44.0.0/24 accept
		ip saddr 10.44.0.0/24 reject
`)
	assert.NotContains(t, rules, "masquerade")
	assert.NotContains(t, rules, "ip6")
}

func TestNftablesRulesetIPv6Only(t *testing.T) {
	rules := ruleset(t, ForwardingOptions{
		GatewayIface: "eth0",
		CIDRv6:       "fd48:4c4:7aa9::/64",
		NAT66:        true,
		AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
	})

	assert.NotContains(t, rules, "ip saddr")
	assert.Contains(t, rules, `ip6 saddr fd48:4c4:7aa9::/64 oifname "eth0" masquerade`)
}

// An IPv4-mapped address in allowedIPs is an IPv4 network, as with iptables.
func TestNftablesRulesetMappedAddress(t *testing.T) {
	rules := ruleset(t, ForwardingOptions{
		CIDR:       "10.44.0.0/24",
		NAT44:      true,
		AllowedIPs: []string{"::ffff:192.168.1.0/120"},
	})

	assert.Contains(t, rules, "ip saddr 10.44.0.0/24 ip daddr 192.168.1.0/24 accept")
}

func TestNftablesRulesetNormalizesTheVPNNetwork(t *testing.T) {
	rules := ruleset(t, ForwardingOptions{CIDR: "10.44.0.1/24", AllowedIPs: []string{"0.0.0.0/0"}})

	assert.Contains(t, rules, "ip saddr 10.44.0.0/24 reject")
}

// The interface name ends up inside the ruleset. It must not be able to
// close the string and add rules of its own.
func TestNftablesRulesetRejectsBadInterfaceNames(t *testing.T) {
	for _, name := range []string{`eth0" accept; #`, "eth0 eth1", "an-interface-name-too-long", "eth0\n"} {
		options, err := splitAllowedIPs(ForwardingOptions{GatewayIface: name, CIDR: "10.44.0.0/24", NAT44: true})
		require.NoError(t, err)
		_, err = nftablesRuleset(options)
		assert.Error(t, err, "%q", name)
	}
}

func TestResolveFirewall(t *testing.T) {
	for _, tc := range []struct {
		firewall string
		disable  bool
		want     string
		fails    bool
	}{
		{"", false, FirewallIPTables, false},
		{"", true, FirewallNone, false},
		{"nftables", false, FirewallNftables, false},
		{"none", true, FirewallNone, false},
		{"nftables", true, "", true},
		{"nftabels", false, "", true},
	} {
		got, err := ResolveFirewall(tc.firewall, tc.disable)
		if tc.fails {
			assert.Error(t, err, "%+v", tc)
			continue
		}
		require.NoError(t, err, "%+v", tc)
		assert.Equal(t, tc.want, got, "%+v", tc)
	}
}

// Applies the ruleset to a kernel - in a network namespace of its own, which
// needs neither root nor touches the machine's firewall. Twice, because the
// second start must replace what the first one left.
//
// The CI sets WG_TEST_NFTABLES, so that a runner without nft or user
// namespaces fails the test instead of skipping it unnoticed.
func TestNftablesRulesetApplies(t *testing.T) {
	skip := t.Skipf
	if os.Getenv("WG_TEST_NFTABLES") != "" {
		skip = t.Fatalf
	}
	if _, err := exec.LookPath("nft"); err != nil {
		skip("nft is not installed")
	}
	if err := exec.Command("unshare", "--net", "--map-root-user", "true").Run(); err != nil {
		skip("cannot create a network namespace: %v", err)
	}

	first := ruleset(t, ForwardingOptions{
		GatewayIface: "eth0", CIDR: "10.44.0.0/24", CIDRv6: "fd48:4c4:7aa9::/64",
		NAT44: true, NAT66: true, ClientIsolation: true,
		AllowedIPs: []string{"0.0.0.0/0", "::/0"},
	})
	second := ruleset(t, ForwardingOptions{
		GatewayIface: "eth1", CIDR: "10.55.0.0/24",
		AllowedIPs: []string{"192.168.1.0/24"},
	})
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "first.nft"), []byte(first), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "second.nft"), []byte(second), 0o600))

	out, err := exec.Command("unshare", "--net", "--map-root-user", "sh", "-c",
		`nft -f "$1/first.nft" && nft -f "$1/first.nft" && nft -f "$1/second.nft" && nft list ruleset`,
		"sh", dir).CombinedOutput()
	require.NoError(t, err, string(out))

	listed := string(out)
	assert.Equal(t, 1, strings.Count(listed, "table inet wg_access_server"), listed)
	assert.Contains(t, listed, "ip saddr 10.55.0.0/24 ip daddr 192.168.1.0/24 accept")
	assert.Contains(t, listed, "ip saddr 192.168.1.0/24 ip daddr 10.55.0.0/24 accept")
	assert.Contains(t, listed, "reject with icmp port-unreachable")
	assert.NotContains(t, listed, "10.44.0.0", "the first start's rules are still there")
	assert.NotContains(t, listed, "xt ", "native rules only, no iptables compatibility")
}
