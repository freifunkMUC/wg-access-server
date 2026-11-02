package network

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
)

// ServerVPNIPs returns two netip.Prefix objects (for IPv4 + IPv6)
// with the Addr set to the server's IP addresses
// in these subnets, i.e. the first usable address
// The return values are the zero prefixes if the corresponding input is an empty string
func ServerVPNIPs(cidr, cidr6 string) (ipv4, ipv6 netip.Prefix, err error) {
	if cidr != "" {
		vpnprefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		addr := vpnprefix.Masked().Addr().Next()
		ipv4 = netip.PrefixFrom(addr, vpnprefix.Bits())
	}
	if cidr6 != "" {
		vpnprefix, err := netip.ParsePrefix(cidr6)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		addr := vpnprefix.Masked().Addr().Next()
		ipv6 = netip.PrefixFrom(addr, vpnprefix.Bits())
	}
	return ipv4, ipv6, nil
}

// StringJoinIPNets joins the string representations of a and b using ", "
func StringJoinIPNets(a, b netip.Prefix) string {
	if a.IsValid() && b.IsValid() {
		return strings.Join([]string{a.String(), b.String()}, ", ")
	} else if a.IsValid() {
		return a.String()
	} else if b.IsValid() {
		return b.String()
	}
	return ""
}

// StringJoinIPs joins the string representations of the IPs of a and b using ", "
func StringJoinIPs(a, b netip.Prefix) string {
	if a.IsValid() && b.IsValid() {
		return strings.Join([]string{a.Addr().String(), b.Addr().String()}, ", ")
	} else if a.IsValid() {
		return a.Addr().String()
	} else if b.IsValid() {
		return b.Addr().String()
	}
	return ""
}

// ParseAddresses parses the comma-separated addresses stored for a device.
// An entry is accepted both as a prefix ("10.44.0.2/32") and as a bare
// address ("10.44.0.2"), because rows written by an older version, by the
// migrate command or by hand may hold either. Entries that are neither are
// returned as the second result, so a single unusable row makes the caller
// report it instead of failing for every device.
func ParseAddresses(addresses string) ([]netip.Addr, []string) {
	split := SplitAddresses(addresses)
	parsed := make([]netip.Addr, 0, len(split))
	var unusable []string
	for _, addr := range split {
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			parsed = append(parsed, prefix.Addr())
			continue
		}
		if ip, err := netip.ParseAddr(addr); err == nil {
			parsed = append(parsed, ip)
			continue
		}
		unusable = append(unusable, addr)
	}
	return parsed, unusable
}

// SplitAddresses splits multiple comma-separated addresses into a slice of address strings
func SplitAddresses(addresses string) []string {
	split := strings.Split(addresses, ",")
	for i, addr := range split {
		split[i] = strings.TrimSpace(addr)
	}
	return split
}

// ForwardingOptions contains all options used for configuring the firewall rules
type ForwardingOptions struct {
	GatewayIface    string
	CIDR, CIDRv6    string
	NAT44, NAT66    bool
	ClientIsolation bool
	AllowedIPs      []string
	allowedIPv4s    []string
	allowedIPv6s    []string
	// Policies restrict what the devices of the people in them may reach,
	// instead of AllowedIPs. A device whose owner is in no policy keeps
	// AllowedIPs. Only the nftables backend has them.
	Policies []Policy
	// ServerAddresses are the addresses of the WireGuard interface itself.
	// Every client reaches them whatever a policy says: that is where the
	// embedded DNS proxy answers, and a policy that cut it off would leave
	// its members without name resolution.
	ServerAddresses []string
	// Firewall is the backend that sets up the rules: FirewallIPTables,
	// FirewallNftables or FirewallNone.
	Firewall string
}

// Policy is what one access policy allows, and whose devices it applies to.
type Policy struct {
	// Name is what the configuration calls it. It ends up in the name of an
	// nftables set, so it is restricted to what an identifier may hold - see
	// ValidPolicyName.
	Name string
	// AllowedIPs are the networks the members may reach.
	AllowedIPs []string
	// Members are the addresses of the devices of the people in the policy.
	Members []string
}

// policyNamePattern is what a policy may be called: the name becomes part of
// an nftables set name, and nothing else may end up in the ruleset.
var policyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// ValidPolicyName reports whether a policy may be called that.
func ValidPolicyName(name string) bool {
	return policyNamePattern.MatchString(name)
}

// The chains wg-access-server owns in the iptables backend.
const (
	forwardChain     = "WG_ACCESS_SERVER_FORWARD"
	postroutingChain = "WG_ACCESS_SERVER_POSTROUTING"
)

// The firewall backends.
const (
	FirewallIPTables = "iptables"
	FirewallNftables = "nftables"
	FirewallNone     = "none"
)

// ResolveFirewall picks the firewall backend from the configuration. An
// empty choice keeps what older versions did: iptables, unless the
// deprecated disableIPTables turned it off.
func ResolveFirewall(firewall string, disableIPTables bool) (string, error) {
	switch firewall {
	case "":
		if disableIPTables {
			logrus.Warn("vpn.disableIPTables is deprecated - use vpn.firewall: none")
			return FirewallNone, nil
		}
		return FirewallIPTables, nil
	case FirewallIPTables, FirewallNftables, FirewallNone:
		if disableIPTables && firewall != FirewallNone {
			return "", fmt.Errorf("vpn.disableIPTables and vpn.firewall: %s contradict each other - set only vpn.firewall", firewall)
		}
		return firewall, nil
	}
	return "", fmt.Errorf("unknown firewall %q: use iptables, nftables or none", firewall)
}

// ConfigureForwarding sets up the rules that send the clients' traffic to
// the allowed networks and nowhere else.
func ConfigureForwarding(options ForwardingOptions) error {
	if options.Firewall == FirewallNone {
		return nil
	}

	options, err := splitAllowedIPs(options)
	if err != nil {
		return err
	}

	// Rules of the other backend from an earlier start would keep applying
	// next to the new ones - an old reject could block what is allowed now.
	if options.Firewall == FirewallNftables {
		removeIPTables()
		return configureNftables(options)
	}
	removeNftables()
	return configureIPTables(options)
}

// family is one address family with the settings that apply to it. Both
// firewall backends work through these, so that IPv4 and IPv6 cannot drift
// apart.
type family struct {
	protocol iptables.Protocol
	// nftables keyword for this family
	keyword string
	cidr    string
	allowed []string
	nat     bool
}

// families returns the address families the server hands out addresses in.
func (options ForwardingOptions) families() []family {
	all := []family{
		{iptables.ProtocolIPv4, "ip", options.CIDR, options.allowedIPv4s, options.NAT44},
		{iptables.ProtocolIPv6, "ip6", options.CIDRv6, options.allowedIPv6s, options.NAT66},
	}
	configured := make([]family, 0, len(all))
	for _, f := range all {
		if f.cidr != "" {
			configured = append(configured, f)
		}
	}
	return configured
}

func configureIPTables(options ForwardingOptions) error {
	for _, f := range options.families() {
		if err := configureIPTablesFamily(options, f); err != nil {
			return err
		}
	}
	return nil
}

func configureIPTablesFamily(options ForwardingOptions, f family) error {
	ipt, err := iptables.NewWithProtocol(f.protocol)
	if err != nil {
		return fmt.Errorf("failed to init iptables: %w", err)
	}

	var forward [][]string
	if options.ClientIsolation {
		// Reject inter-device traffic
		forward = append(forward, []string{"-s", f.cidr, "-d", f.cidr, "-j", "REJECT"})
	}
	// Accept client traffic for given allowed ips
	for _, allowedCIDR := range f.allowed {
		forward = append(forward, []string{"-s", f.cidr, "-d", allowedCIDR, "-j", "ACCEPT"})
	}
	// Accept return traffic when NAT is disabled
	if !f.nat {
		for _, allowedCIDR := range f.allowed {
			forward = append(forward, []string{"-s", allowedCIDR, "-d", f.cidr, "-j", "ACCEPT"})
		}
	}
	// And reject everything else
	forward = append(forward, []string{"-s", f.cidr, "-j", "REJECT"})

	var postrouting [][]string
	if options.GatewayIface != "" && f.nat {
		postrouting = append(postrouting, []string{"-s", f.cidr, "-o", options.GatewayIface, "-j", "MASQUERADE"})
	}

	// Both chains are replaced in one iptables-restore: each table is
	// swapped at once, and a rebuild that fails leaves the previous rules in
	// place. Flushing the chain and adding the rules one by one left it
	// without its rejects for a moment on every rebuild, and open for good
	// if one of the additions failed.
	if err := restoreChains(ipt.Proto(), []chainRules{
		{"filter", forwardChain, forward},
		{"nat", postroutingChain, postrouting},
	}); err != nil {
		return err
	}

	if err := ipt.AppendUnique("filter", "FORWARD", "-j", forwardChain); err != nil {
		return fmt.Errorf("failed to append FORWARD rule to filter chain: %w", err)
	}
	if err := ipt.AppendUnique("nat", "POSTROUTING", "-j", postroutingChain); err != nil {
		return fmt.Errorf("failed to append POSTROUTING rule to nat chain: %w", err)
	}
	return nil
}

// chainRules is the whole content of one of our chains.
type chainRules struct {
	table, chain string
	rules        [][]string
}

// restoreChains replaces the content of the given chains, creating the ones
// that do not exist yet. With --noflush, iptables-restore leaves everything
// else alone and empties only the chains it declares.
func restoreChains(protocol iptables.Protocol, chains []chainRules) error {
	input, err := restoreInput(chains)
	if err != nil {
		return err
	}

	command := "iptables-restore"
	if protocol == iptables.ProtocolIPv6 {
		command = "ip6tables-restore"
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", command, err)
	}
	cmd := exec.Command(path, "--noflush", "--wait")
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set the iptables rules with %s: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// restoreInput writes the chains in the format of iptables-restore. A rule
// that is already there is left out, as AppendUnique did.
func restoreInput(chains []chainRules) (string, error) {
	var b strings.Builder
	for _, c := range chains {
		fmt.Fprintf(&b, "*%s\n:%s - [0:0]\n", c.table, c.chain)
		seen := make(map[string]bool, len(c.rules))
		for _, rule := range c.rules {
			for _, arg := range rule {
				// one line per rule: an argument must not start another one
				if arg == "" || strings.ContainsAny(arg, " \t\r\n\"'") {
					return "", fmt.Errorf("invalid argument %q for an iptables rule", arg)
				}
			}
			line := "-A " + c.chain + " " + strings.Join(rule, " ")
			if seen[line] {
				continue
			}
			seen[line] = true
			b.WriteString(line + "\n")
		}
		b.WriteString("COMMIT\n")
	}
	return b.String(), nil
}

// splitAllowedIPs sorts the allowed networks into IPv4 and IPv6 ones.
func splitAllowedIPs(options ForwardingOptions) (ForwardingOptions, error) {
	allowedIPv4s := make([]string, 0, len(options.AllowedIPs)/2)
	allowedIPv6s := make([]string, 0, len(options.AllowedIPs)/2)

	for _, allowedCIDR := range options.AllowedIPs {
		parsedAddress, parsedNetwork, err := net.ParseCIDR(allowedCIDR)
		if err != nil {
			return options, fmt.Errorf("invalid cidr in AllowedIPs: %w", err)
		}
		if as4 := parsedAddress.To4(); as4 != nil {
			// Handle IPv4-mapped IPv6 addresses, if they go into ip6tables they don't get hit
			// and go-iptables can't convert them (whereas commandline iptables can).
			parsedNetwork.IP = as4
			allowedIPv4s = append(allowedIPv4s, parsedNetwork.String())
		} else {
			allowedIPv6s = append(allowedIPv6s, parsedNetwork.String())
		}
	}
	options.allowedIPv4s = allowedIPv4s
	options.allowedIPv6s = allowedIPv6s
	return options, nil
}

// removeIPTables takes out the chains a start with the iptables backend left
// behind. Best effort: without iptables there is nothing to remove.
func removeIPTables() {
	for _, protocol := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		ipt, err := iptables.NewWithProtocol(protocol)
		if err != nil {
			continue
		}
		for _, chain := range []struct{ table, parent, name string }{
			{"filter", "FORWARD", forwardChain},
			{"nat", "POSTROUTING", postroutingChain},
		} {
			exists, err := ipt.ChainExists(chain.table, chain.name)
			if err != nil || !exists {
				continue
			}
			if err := ipt.DeleteIfExists(chain.table, chain.parent, "-j", chain.name); err != nil {
				logrus.Warn(fmt.Errorf("failed to remove the jump to %s: %w", chain.name, err))
				continue
			}
			if err := ipt.ClearAndDeleteChain(chain.table, chain.name); err != nil {
				logrus.Warn(fmt.Errorf("failed to remove %s: %w", chain.name, err))
			}
		}
	}
}
