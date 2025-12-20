package network

import (
	"net/netip"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
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
	DisableIPTables bool
	FirewallBackend FirewallBackend
}

func ConfigureForwarding(options ForwardingOptions) error {
	// If iptables is disabled, return early
	if options.DisableIPTables {
		return nil
	}

	// Create firewall instance based on backend preference
	fw, err := NewFirewall(options.FirewallBackend)
	if err != nil {
		return errors.Wrap(err, "failed to initialize firewall")
	}

	// Configure forwarding rules using the firewall backend
	return fw.ConfigureForwarding(options)
}

func configureForwardingv4(options ForwardingOptions) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return errors.Wrap(err, "failed to init iptables")
	}

	// Cleanup our chains first so that we don't leak
	// iptable rules when the network configuration changes.
	err = clearOrCreateChain(ipt, "filter", "WG_ACCESS_SERVER_FORWARD")
	if err != nil {
		return err
	}

	err = clearOrCreateChain(ipt, "nat", "WG_ACCESS_SERVER_POSTROUTING")
	if err != nil {
		return err
	}

	err = ipt.AppendUnique("filter", "FORWARD", "-j", "WG_ACCESS_SERVER_FORWARD")
	if err != nil {
		return errors.Wrap(err, "failed to append FORWARD rule to filter chain")
	}

	err = ipt.AppendUnique("nat", "POSTROUTING", "-j", "WG_ACCESS_SERVER_POSTROUTING")
	if err != nil {
		return errors.Wrap(err, "failed to append POSTROUTING rule to nat chain")
	}

	if options.ClientIsolation {
		// Reject inter-device traffic
		if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDR, "-d", options.CIDR, "-j", "REJECT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}
	// Accept client traffic for given allowed ips
	for _, allowedCIDR := range options.allowedIPv4s {
		if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDR, "-d", allowedCIDR, "-j", "ACCEPT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}

	// Accept return traffic when NAT is disabled
	if !options.NAT44 {
		for _, allowedCIDR := range options.allowedIPv4s {
			if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", allowedCIDR, "-d", options.CIDR, "-j", "ACCEPT"); err != nil {
				return errors.Wrap(err, "failed to set ip tables rule for return traffic")
			}
		}
	}

	// And reject everything else
	if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDR, "-j", "REJECT"); err != nil {
		return errors.Wrap(err, "failed to set ip tables rule")
	}

	if options.GatewayIface != "" {
		if options.NAT44 {
			if err := ipt.AppendUnique("nat", "WG_ACCESS_SERVER_POSTROUTING", "-s", options.CIDR, "-o", options.GatewayIface, "-j", "MASQUERADE"); err != nil {
				return errors.Wrap(err, "failed to set ip tables rule")
			}
		}
	}
	return nil
}

func configureForwardingv6(options ForwardingOptions) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return errors.Wrap(err, "failed to init ip6tables")
	}

	err = clearOrCreateChain(ipt, "filter", "WG_ACCESS_SERVER_FORWARD")
	if err != nil {
		return err
	}

	err = clearOrCreateChain(ipt, "nat", "WG_ACCESS_SERVER_POSTROUTING")
	if err != nil {
		return err
	}

	err = ipt.AppendUnique("filter", "FORWARD", "-j", "WG_ACCESS_SERVER_FORWARD")
	if err != nil {
		return errors.Wrap(err, "failed to append FORWARD rule to filter chain")
	}

	err = ipt.AppendUnique("nat", "POSTROUTING", "-j", "WG_ACCESS_SERVER_POSTROUTING")
	if err != nil {
		return errors.Wrap(err, "failed to append POSTROUTING rule to nat chain")
	}

	if options.ClientIsolation {
		// Reject inter-device traffic
		if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDRv6, "-d", options.CIDRv6, "-j", "REJECT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}
	// Accept client traffic for given allowed ips
	for _, allowedCIDR := range options.allowedIPv6s {
		if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDRv6, "-d", allowedCIDR, "-j", "ACCEPT"); err != nil {
			return errors.Wrap(err, "failed to set ip tables rule")
		}
	}

	// Accept return traffic when NAT is disabled
	if !options.NAT66 {
		for _, allowedCIDR := range options.allowedIPv6s {
			if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", allowedCIDR, "-d", options.CIDRv6, "-j", "ACCEPT"); err != nil {
				return errors.Wrap(err, "failed to set ip tables rule for return traffic")
			}
		}
	}

	// And reject everything else
	if err := ipt.AppendUnique("filter", "WG_ACCESS_SERVER_FORWARD", "-s", options.CIDRv6, "-j", "REJECT"); err != nil {
		return errors.Wrap(err, "failed to set ip tables rule")
	}

	if options.GatewayIface != "" {
		if options.NAT66 {
			if err := ipt.AppendUnique("nat", "WG_ACCESS_SERVER_POSTROUTING", "-s", options.CIDRv6, "-o", options.GatewayIface, "-j", "MASQUERADE"); err != nil {
				return errors.Wrap(err, "failed to set ip tables rule")
			}
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
