package network

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// nftTable holds every rule wg-access-server sets up with nftables. It is
// one table for IPv4 and IPv6 ("inet"), owned by wg-access-server alone, so
// it can be replaced as a whole without touching anybody else's rules.
const nftTable = "wg_access_server"

// interfaceName is what Linux accepts as an interface name. The name goes
// into the ruleset as text, so it must not be able to end the string.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,15}$`)

// nftablesRuleset returns the ruleset for options: what the iptables backend
// sets up, plus the access policies. It starts by declaring and
// deleting the table, so that applying it replaces whatever an earlier start
// left behind - in one transaction, with no moment without rules.
func nftablesRuleset(options ForwardingOptions) (string, error) {
	if options.GatewayIface != "" && !interfaceName.MatchString(options.GatewayIface) {
		return "", fmt.Errorf("invalid gateway interface name %q", options.GatewayIface)
	}

	var sets, forward, postrouting []string
	for _, f := range options.families() {
		prefix, err := netip.ParsePrefix(f.cidr)
		if err != nil {
			return "", fmt.Errorf("invalid VPN network %q: %w", f.cidr, err)
		}
		cidr := prefix.Masked().String()
		ip := f.keyword
		// what a client sends comes from its VPN address or from a network
		// behind its device
		clients := nftAddresses(append([]string{cidr}, f.routed...))

		// Answers from a network behind a device to a client that reached
		// into it. Everything else from there is a client's own traffic.
		if len(f.routed) > 0 {
			forward = append(forward, fmt.Sprintf("%s saddr %s ct state established,related accept", ip, nftAddresses(f.routed)))
		}

		if options.ClientIsolation {
			// reject traffic between devices
			forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s reject", ip, clients, ip, cidr))
		}

		policies, err := policiesOfFamily(options.Policies, f)
		if err != nil {
			return "", err
		}
		if len(policies) > 0 {
			// The server's own addresses, before anything a policy says:
			// that is where the DNS proxy answers, and a policy is about the
			// networks behind the server, not about the server itself.
			for _, address := range addressesOfFamily(options.ServerAddresses, f) {
				forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s accept", ip, clients, ip, address))
			}

			var members []string
			for _, policy := range policies {
				set := policySetName(policy.Name, f)
				sets = append(sets, nftSet(set, f, policy.Members))
				members = append(members, policy.Members...)

				for _, network := range policy.AllowedIPs {
					forward = append(forward, fmt.Sprintf("%s saddr @%s %s daddr %s accept", ip, set, ip, network))
				}
				if !f.nat {
					for _, network := range policy.AllowedIPs {
						forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr @%s accept", ip, network, ip, set))
					}
				}
			}

			// Whoever is in a policy is done here: falling through to the
			// rules below would give them what everybody else may reach,
			// which is the opposite of what a policy is for.
			all := policyMembersSetName(f)
			sets = append(sets, nftSet(all, f, members))
			forward = append(forward, fmt.Sprintf("%s saddr @%s reject", ip, all))
		}

		// accept client traffic to the allowed networks and to the ones
		// behind the devices
		for _, network := range f.destinations() {
			forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s accept", ip, clients, ip, network))
		}
		// without NAT, the answers come back to the clients' own addresses
		if !f.nat {
			for _, network := range f.allowed {
				forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s accept", ip, network, ip, clients))
			}
		}
		// and reject everything else the clients send
		forward = append(forward, fmt.Sprintf("%s saddr %s reject", ip, clients))

		if options.GatewayIface != "" && f.nat {
			postrouting = append(postrouting, fmt.Sprintf("%s saddr %s oifname %q masquerade", ip, cidr, options.GatewayIface))
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", nftTable)
	fmt.Fprintf(&b, "delete table inet %s\n", nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	for _, set := range sets {
		b.WriteString(set)
		b.WriteString("\n")
	}
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
	for _, rule := range forward {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, rule := range postrouting {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// nftAddresses writes networks as one match: a single one as it is, several
// as an anonymous set.
func nftAddresses(networks []string) string {
	if len(networks) == 1 {
		return networks[0]
	}
	return "{ " + strings.Join(networks, ", ") + " }"
}

// policySetName is the set holding the devices of one policy's members.
func policySetName(policy string, f family) string {
	return fmt.Sprintf("policy_%s_%s", policy, f.keyword)
}

// policyMembersSetName is the set holding the devices of everybody who is in
// any policy at all. It must not start with "policy_": a policy called
// "members" would get the same set, and nft merges two declarations of a set
// into one, so every member of any policy would reach that policy's networks.
func policyMembersSetName(f family) string {
	return fmt.Sprintf("members_%s", f.keyword)
}

// nftSet declares a set of addresses and networks: the devices of a policy's
// members and the networks behind them. An empty one is declared all the same
// - a policy nobody is in must exist as a set, or the rules naming it do not
// load. auto-merge lets elements overlap instead of failing the whole
// ruleset, should storage ever hold such routes.
func nftSet(name string, f family, addresses []string) string {
	kind := "ipv4_addr"
	if f.keyword == "ip6" {
		kind = "ipv6_addr"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, kind)
	if len(addresses) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(addresses, ", "))
	}
	b.WriteString("\t}\n")
	return b.String()
}

// policiesOfFamily reduces the policies to one address family: their networks
// and their members of that family, in the order they were given.
//
// A policy that names no networks of the family is kept all the same. Its
// members are still in it, and leaving it out would hand them whatever
// vpn.allowedIPs opens in that family - the opposite of a policy. Kept, it
// lets them reach the server there and nothing else.
func policiesOfFamily(policies []Policy, f family) ([]Policy, error) {
	reduced := make([]Policy, 0, len(policies))
	for _, policy := range policies {
		if !ValidPolicyName(policy.Name) {
			return nil, fmt.Errorf("invalid policy name %q", policy.Name)
		}

		networks, err := prefixesOfFamily(policy.AllowedIPs, f)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
		}
		reduced = append(reduced, Policy{
			Name:       policy.Name,
			AllowedIPs: networks,
			Members:    networksOfFamily(policy.Members, f),
		})
	}
	return reduced, nil
}

// prefixesOfFamily keeps the networks of one address family, as they were
// written.
func prefixesOfFamily(networks []string, f family) ([]string, error) {
	kept := make([]string, 0, len(networks))
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", network, err)
		}
		if prefix.Addr().Unmap().Is4() == (f.keyword == "ip") {
			kept = append(kept, prefix.Masked().String())
		}
	}
	return kept, nil
}

// networksOfFamily keeps the addresses and networks of one address family: a
// device's address as a bare address, a network behind it as a network.
// Unparsable entries are left out, like in addressesOfFamily.
func networksOfFamily(networks []string, f family) []string {
	kept := make([]string, 0, len(networks))
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(network))
		if err != nil {
			addr, err := netip.ParseAddr(strings.TrimSpace(network))
			if err != nil {
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		addr := prefix.Addr().Unmap()
		if addr.Is4() != (f.keyword == "ip") {
			continue
		}
		bits := prefix.Bits()
		if prefix.Addr().Is4In6() {
			// an IPv4 network written in IPv6
			if bits < 96 {
				continue
			}
			bits -= 96
		}
		if bits == addr.BitLen() {
			kept = append(kept, addr.String())
		} else {
			kept = append(kept, netip.PrefixFrom(addr, bits).Masked().String())
		}
	}
	return kept
}

// addressesOfFamily keeps the addresses of one address family, as bare
// addresses: a set holds addresses, and a device carries them as /32 and
// /128 prefixes.
func addressesOfFamily(addresses []string, f family) []string {
	kept := make([]string, 0, len(addresses))
	for _, address := range addresses {
		addr, err := netip.ParsePrefix(strings.TrimSpace(address))
		if err != nil {
			parsed, err := netip.ParseAddr(strings.TrimSpace(address))
			if err != nil {
				continue
			}
			addr = netip.PrefixFrom(parsed, parsed.BitLen())
		}
		if addr.Addr().Unmap().Is4() == (f.keyword == "ip") {
			kept = append(kept, addr.Addr().Unmap().String())
		}
	}
	return kept
}

func configureNftables(options ForwardingOptions) error {
	ruleset, err := nftablesRuleset(options)
	if err != nil {
		return err
	}
	logrus.Debugf("applying the nftables ruleset:\n%s", ruleset)
	return runNft(ruleset)
}

// runNft applies a ruleset as one transaction: all of it, or none.
func runNft(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply the nftables rules: %s: %w", strings.TrimSpace(output.String()), err)
	}
	return nil
}

// removeNftables drops the table a start with the nftables backend left
// behind. Best effort: without the nft binary there is nothing to remove.
func removeNftables() {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ruleset := fmt.Sprintf("table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	if err := runNft(ruleset); err != nil {
		logrus.Warn(fmt.Errorf("failed to remove the nftables rules of an earlier start: %w", err))
	}
}
