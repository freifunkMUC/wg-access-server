package network

import (
	"net"
	"net/netip"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
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
	// Firewall is the backend that sets up the rules: FirewallIPTables,
	// FirewallNftables or FirewallNone.
	Firewall string
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
			return "", errors.Errorf("vpn.disableIPTables and vpn.firewall: %s contradict each other - set only vpn.firewall", firewall)
		}
		return firewall, nil
	}
	return "", errors.Errorf("unknown firewall %q: use iptables, nftables or none", firewall)
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
		return errors.Wrap(err, "failed to init iptables")
	}

	// Cleanup our chains first so that we don't leak
	// iptable rules when the network configuration changes.
	if err := clearOrCreateChain(ipt, "filter", forwardChain); err != nil {
		return err
	}
	if err := clearOrCreateChain(ipt, "nat", postroutingChain); err != nil {
		return err
	}

	if err := ipt.AppendUnique("filter", "FORWARD", "-j", forwardChain); err != nil {
		return errors.Wrap(err, "failed to append FORWARD rule to filter chain")
	}
	if err := ipt.AppendUnique("nat", "POSTROUTING", "-j", postroutingChain); err != nil {
		return errors.Wrap(err, "failed to append POSTROUTING rule to nat chain")
	}

	if options.ClientIsolation {
		// Reject inter-device traffic
		if err := ipt.AppendUnique("filter", forwardChain, "-s", f.cidr, "-d", f.cidr, "-j", "REJECT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}
	// Accept client traffic for given allowed ips
	for _, allowedCIDR := range f.allowed {
		if err := ipt.AppendUnique("filter", forwardChain, "-s", f.cidr, "-d", allowedCIDR, "-j", "ACCEPT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}

	// Accept return traffic when NAT is disabled
	if !f.nat {
		for _, allowedCIDR := range f.allowed {
			if err := ipt.AppendUnique("filter", forwardChain, "-s", allowedCIDR, "-d", f.cidr, "-j", "ACCEPT"); err != nil {
				return errors.Wrap(err, "failed to set ip tables rule for return traffic")
			}
		}
	}

	// And reject everything else
	if err := ipt.AppendUnique("filter", forwardChain, "-s", f.cidr, "-j", "REJECT"); err != nil {
		return errors.Wrap(err, "failed to set ip tables rule")
	}

	if options.GatewayIface != "" && f.nat {
		if err := ipt.AppendUnique("nat", postroutingChain, "-s", f.cidr, "-o", options.GatewayIface, "-j", "MASQUERADE"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}
	return nil
}

func clearOrCreateChain(ipt *iptables.IPTables, table, chain string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return errors.Wrapf(err, "failed to read table %s", table)
	}
	if exists {
		err = ipt.ClearChain(table, chain)
		if err != nil {
			return errors.Wrapf(err, "failed to clear chain %s in table %s", chain, table)
		}
	} else {
		// Create our own chain for forwarding rules
		err = ipt.NewChain(table, chain)
		if err != nil {
			return errors.Wrapf(err, "failed to create chain %s in table %s", chain, table)
		}
	}
	return nil
}

// splitAllowedIPs sorts the allowed networks into IPv4 and IPv6 ones.
func splitAllowedIPs(options ForwardingOptions) (ForwardingOptions, error) {
	allowedIPv4s := make([]string, 0, len(options.AllowedIPs)/2)
	allowedIPv6s := make([]string, 0, len(options.AllowedIPs)/2)

	for _, allowedCIDR := range options.AllowedIPs {
		parsedAddress, parsedNetwork, err := net.ParseCIDR(allowedCIDR)
		if err != nil {
			return options, errors.Wrap(err, "invalid cidr in AllowedIPs")
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
				logrus.Warn(errors.Wrapf(err, "failed to remove the jump to %s", chain.name))
				continue
			}
			if err := ipt.ClearAndDeleteChain(chain.table, chain.name); err != nil {
				logrus.Warn(errors.Wrapf(err, "failed to remove %s", chain.name))
			}
		}
	}
}
