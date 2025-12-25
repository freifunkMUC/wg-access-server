package network

import (
	"net"

	"github.com/google/nftables"
	"github.com/pkg/errors"
)

// ipNet represents a parsed IP network
type ipNet struct {
	IP   []byte
	Mask []byte
}

// parseCIDR parses a CIDR string into an ipNet
func parseCIDR(cidr string) (*ipNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Convert mask to bytes
	mask := network.Mask
	ip := network.IP

	// For IPv4, ensure we use 4 bytes, not 16
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		mask = mask[len(mask)-4:]
	}

	return &ipNet{
		IP:   ip,
		Mask: mask,
	}, nil
}

// ipSourceOffset returns the byte offset of the source IP address in the IP header
// IPv4: offset 12 (RFC 791 - Internet Protocol, Section 3.1)
// IPv6: offset 8 (RFC 2460 - Internet Protocol, Version 6 Specification, Section 3)
func ipSourceOffset(family nftables.TableFamily) uint32 {
	if family == nftables.TableFamilyIPv4 {
		return 12 // IPv4 source address offset
	}
	return 8 // IPv6 source address offset
}

// ipDestOffset returns the byte offset of the destination IP address in the IP header
// IPv4: offset 16 (RFC 791 - Internet Protocol, Section 3.1)
// IPv6: offset 24 (RFC 2460 - Internet Protocol, Version 6 Specification, Section 3)
func ipDestOffset(family nftables.TableFamily) uint32 {
	if family == nftables.TableFamilyIPv4 {
		return 16 // IPv4 destination address offset
	}
	return 24 // IPv6 destination address offset
}

// ipAddrLen returns the length of an IP address for the given family
// IPv4: 4 bytes (32 bits)
// IPv6: 16 bytes (128 bits)
func ipAddrLen(family nftables.TableFamily) uint32 {
	if family == nftables.TableFamilyIPv4 {
		return 4 // IPv4 address length
	}
	return 16 // IPv6 address length
}

// separateAllowedIPs separates a list of CIDRs into IPv4 and IPv6 lists
func separateAllowedIPs(allowedIPs []string) ([]string, []string, error) {
	allowedIPv4s := make([]string, 0, len(allowedIPs)/2)
	allowedIPv6s := make([]string, 0, len(allowedIPs)/2)

	for _, allowedCIDR := range allowedIPs {
		parsedAddress, parsedNetwork, err := net.ParseCIDR(allowedCIDR)
		if err != nil {
			return nil, nil, errors.Wrap(err, "invalid cidr in AllowedIPs")
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

	return allowedIPv4s, allowedIPv6s, nil
}
