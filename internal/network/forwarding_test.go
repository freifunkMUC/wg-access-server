package network

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What reaches where, with packets instead of rule texts: two clients, a
// network behind the first one's device, and a LAN with a host the clients may
// reach and one they may not. Veth pairs stand in for the WireGuard peers.
//
// Each case starts from a fresh topology, checks that everything is reachable
// without a firewall - so that a blocked packet below is the firewall's doing -
// and then sends the same packets through the rules of one backend.
func TestForwardingPackets(t *testing.T) {
	if !netnsTest(t, "iptables", "ip6tables", "nft", "ip", "ping") {
		return
	}

	const (
		client     = "10.44.0.2"
		other      = "10.44.0.3"
		behind     = "192.168.5.7" // in the network behind client's device
		allowedLAN = "192.168.1.10"
		otherLAN   = "192.168.9.10"
	)
	base := ForwardingOptions{
		CIDR:            "10.44.0.0/24",
		ClientIsolation: true,
		AllowedIPs:      []string{"192.168.1.0/24"},
		Routed:          []string{"192.168.5.0/24"},
	}

	type probe struct {
		from, to string
		reaches  bool
	}
	everybody := []probe{
		{client, allowedLAN, true},
		{client, otherLAN, false},
		{client, other, false},
		// the network behind a device is its device: allowedIPs and
		// isolation apply
		{behind, allowedLAN, true},
		{behind, otherLAN, false},
		{behind, other, false},
		// every client may reach it, and the answers come back
		{other, behind, true},
	}

	staff := base
	staff.Policies = []Policy{
		{Name: "staff", AllowedIPs: []string{"192.168.9.0/24"}, Members: []string{client + "/32", "192.168.5.0/24"}},
	}
	staffProbes := []probe{
		{client, otherLAN, true},
		{client, allowedLAN, false},
		// the policy applies to the network behind the member's device
		{behind, otherLAN, true},
		{behind, allowedLAN, false},
		{behind, other, false},
		{other, behind, true},
	}

	for _, tc := range []struct {
		name     string
		options  ForwardingOptions
		firewall string
		probes   []probe
	}{
		{"iptables", base, FirewallIPTables, everybody},
		{"nftables", base, FirewallNftables, everybody},
		{"nftables policy", staff, FirewallNftables, staffProbes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			topology(t)
			for _, p := range tc.probes {
				require.True(t, pings(t, p.from, p.to), "without a firewall, %s should reach %s", p.from, p.to)
			}

			options := tc.options
			options.Firewall = tc.firewall
			require.NoError(t, ConfigureForwarding(options))
			for _, p := range tc.probes {
				assert.Equal(t, p.reaches, pings(t, p.from, p.to), "%s -> %s", p.from, p.to)
			}
		})
	}
}

// topology builds the network for TestForwardingPackets from scratch. This
// network namespace is the server; the clients and the LAN get namespaces of
// their own. Each client has its address as a /32 and the server as its only
// way out, as behind WireGuard - so that the clients reach each other through
// the server's forward chain and nowhere else.
func topology(t *testing.T) {
	t.Helper()
	sh(t, `
		# a namespace goes away in the background, its veth pair with it: delete
		# the pairs here, so that the names are free at once
		for dev in c0 o0 l0; do ip link del $dev 2>/dev/null; done
		for ns in client other lan; do ip netns del $ns 2>/dev/null; done
		nft delete table inet wg_access_server 2>/dev/null
		iptables -F FORWARD; iptables -F WG_ACCESS_SERVER_FORWARD 2>/dev/null; iptables -F WG_ACCESS_SERVER_CLIENTS 2>/dev/null
		true
	`)
	sh(t, `
		set -e
		# /run is not ours to write; a tmpfs of this mount namespace is
		[ -e /run/wg-access-server-test ] || { mount -t tmpfs none /run && mkdir /run/netns && touch /run/wg-access-server-test; }
		ip link set lo up
		sysctl -qw net.ipv4.ip_forward=1
		for c in client:c:10.44.0.2 other:o:10.44.0.3; do
			ns=${c%%:*}; rest=${c#*:}; dev=${rest%%:*}; addr=${rest#*:}
			ip netns add $ns
			ip link add ${dev}0 type veth peer name ${dev}1 netns $ns
			ip addr add 10.44.0.1/32 dev ${dev}0
			ip link set ${dev}0 up
			ip route add $addr/32 dev ${dev}0
			ip -n $ns link set lo up
			ip -n $ns addr add $addr/32 dev ${dev}1
			ip -n $ns link set ${dev}1 up
			ip -n $ns route add 10.44.0.1/32 dev ${dev}1
			ip -n $ns route add default via 10.44.0.1 dev ${dev}1
		done
		ip -n client addr add 192.168.5.7/32 dev c1
		ip route add 192.168.5.0/24 via 10.44.0.2 dev c0 onlink

		ip netns add lan
		ip link add l0 type veth peer name l1 netns lan
		ip addr add 192.168.1.1/24 dev l0
		ip addr add 192.168.9.1/24 dev l0
		ip link set l0 up
		ip -n lan link set lo up
		ip -n lan addr add 192.168.1.10/24 dev l1
		ip -n lan addr add 192.168.9.10/24 dev l1
		ip -n lan link set l1 up
		ip -n lan route add default via 192.168.1.1
	`)
}

// pings reports whether from gets an answer from to. from is one of the
// addresses of the client namespaces.
func pings(t *testing.T, from, to string) bool {
	t.Helper()
	ns := map[string]string{"10.44.0.2": "client", "192.168.5.7": "client", "10.44.0.3": "other"}[from]
	require.NotEmpty(t, ns, "no namespace has %s", from)
	return exec.Command("ip", "netns", "exec", ns, "ping", "-c1", "-W1", "-I", from, to).Run() == nil
}

func sh(t *testing.T, script string) {
	t.Helper()
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("%s\n%s", strings.TrimSpace(script), out))
}
