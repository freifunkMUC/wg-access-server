package network

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// FirewallBackend represents the available firewall backends
type FirewallBackend string

const (
	FirewallBackendAuto     FirewallBackend = "auto"
	FirewallBackendIPTables FirewallBackend = "iptables"
	FirewallBackendNFTables FirewallBackend = "nftables"
)

// Firewall is an interface for managing firewall rules
type Firewall interface {
	// ConfigureForwarding sets up the firewall rules for VPN forwarding
	ConfigureForwarding(options ForwardingOptions) error
}

// NewFirewall creates a new firewall instance based on the backend preference
func NewFirewall(backend FirewallBackend) (Firewall, error) {
	switch backend {
	case FirewallBackendIPTables:
		return newIPTablesFirewall()
	case FirewallBackendNFTables:
		return newNFTablesFirewall()
	case FirewallBackendAuto:
		// Try nftables first, fallback to iptables
		nft, err := newNFTablesFirewall()
		if err == nil {
			logrus.Info("Using nftables backend")
			return nft, nil
		}
		logrus.Debugf("nftables not available: %v, trying iptables", err)
		ipt, err := newIPTablesFirewall()
		if err == nil {
			logrus.Info("Using iptables backend")
			return ipt, nil
		}
		return nil, errors.Wrap(err, "no firewall backend available")
	default:
		return nil, fmt.Errorf("unknown firewall backend: %s", backend)
	}
}

// iptablesFirewall implements the Firewall interface using iptables
type iptablesFirewall struct{}

func newIPTablesFirewall() (Firewall, error) {
	// Test if iptables is available
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, errors.Wrap(err, "iptables not available")
	}
	// Try to list chains to verify it works
	if _, err := ipt.ListChains("filter"); err != nil {
		return nil, errors.Wrap(err, "iptables not functional")
	}
	return &iptablesFirewall{}, nil
}

func (f *iptablesFirewall) ConfigureForwarding(options ForwardingOptions) error {
	// Use the existing iptables implementation
	return configureForwardingIPTables(options)
}

// configureForwardingIPTables is the existing iptables implementation
func configureForwardingIPTables(options ForwardingOptions) error {
	// Separate IPv4 and IPv6 allowed IPs
	allowedIPv4s, allowedIPv6s, err := separateAllowedIPs(options.AllowedIPs)
	if err != nil {
		return err
	}
	options.allowedIPv4s = allowedIPv4s
	options.allowedIPv6s = allowedIPv6s

	if options.CIDR != "" {
		if err := configureForwardingv4(options); err != nil {
			return err
		}
	}
	if options.CIDRv6 != "" {
		if err := configureForwardingv6(options); err != nil {
			return err
		}
	}
	return nil
}

// nftablesFirewall implements the Firewall interface using nftables
type nftablesFirewall struct {
	conn *nftables.Conn
}

func newNFTablesFirewall() (Firewall, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create nftables connection")
	}
	return &nftablesFirewall{conn: conn}, nil
}

func (f *nftablesFirewall) ConfigureForwarding(options ForwardingOptions) error {
	// Separate IPv4 and IPv6 allowed IPs
	allowedIPv4s, allowedIPv6s, err := separateAllowedIPs(options.AllowedIPs)
	if err != nil {
		return err
	}
	options.allowedIPv4s = allowedIPv4s
	options.allowedIPv6s = allowedIPv6s

	if options.CIDR != "" {
		if err := f.configureForwardingNFTablesV4(options); err != nil {
			return err
		}
	}
	if options.CIDRv6 != "" {
		if err := f.configureForwardingNFTablesV6(options); err != nil {
			return err
		}
	}

	// Apply all changes
	if err := f.conn.Flush(); err != nil {
		return errors.Wrap(err, "failed to apply nftables rules")
	}

	return nil
}

func (f *nftablesFirewall) configureForwardingNFTablesV4(options ForwardingOptions) error {
	return f.configureForwardingNFTables(nftables.TableFamilyIPv4, options.CIDR, options.allowedIPv4s, options.GatewayIface, options.NAT44, options.ClientIsolation)
}

func (f *nftablesFirewall) configureForwardingNFTablesV6(options ForwardingOptions) error {
	return f.configureForwardingNFTables(nftables.TableFamilyIPv6, options.CIDRv6, options.allowedIPv6s, options.GatewayIface, options.NAT66, options.ClientIsolation)
}

func (f *nftablesFirewall) configureForwardingNFTables(family nftables.TableFamily, cidr string, allowedCIDRs []string, gatewayIface string, nat bool, clientIsolation bool) error {
	tableName := "wg-access-server"
	
	// Get or create the table
	table := f.conn.AddTable(&nftables.Table{
		Family: family,
		Name:   tableName,
	})

	// Delete existing chains if they exist to start fresh
	chains, err := f.conn.ListChainsOfTableFamily(family)
	if err == nil {
		for _, chain := range chains {
			if chain.Table.Name == tableName {
				f.conn.DelChain(chain)
			}
		}
	}

	// Create forward chain
	forwardChain := f.conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	// Create postrouting chain for NAT
	postroutingChain := f.conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Parse VPN CIDR
	vpnNet, err := parseCIDR(cidr)
	if err != nil {
		return errors.Wrapf(err, "invalid CIDR: %s", cidr)
	}

	// Add client isolation rule if enabled
	if clientIsolation {
		// Match: source is VPN CIDR and destination is VPN CIDR -> REJECT
		f.conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				// Match source address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipSourceOffset(family),
					Len:          ipAddrLen(family),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            ipAddrLen(family),
					Mask:           vpnNet.Mask,
					Xor:            make([]byte, ipAddrLen(family)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     vpnNet.IP,
				},
				// Match destination address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipDestOffset(family),
					Len:          ipAddrLen(family),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            ipAddrLen(family),
					Mask:           vpnNet.Mask,
					Xor:            make([]byte, ipAddrLen(family)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     vpnNet.IP,
				},
				// Reject
				&expr.Reject{
					Type: unix.NFT_REJECT_ICMP_UNREACH,
					Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
				},
			},
		})
	}

	// Add accept rules for each allowed CIDR
	for _, allowedCIDR := range allowedCIDRs {
		allowedNet, err := parseCIDR(allowedCIDR)
		if err != nil {
			return errors.Wrapf(err, "invalid allowed CIDR: %s", allowedCIDR)
		}

		// Match: source is VPN CIDR and destination is allowed CIDR -> ACCEPT
		f.conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				// Match source address (VPN CIDR)
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipSourceOffset(family),
					Len:          ipAddrLen(family),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            ipAddrLen(family),
					Mask:           vpnNet.Mask,
					Xor:            make([]byte, ipAddrLen(family)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     vpnNet.IP,
				},
				// Match destination address (allowed CIDR)
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipDestOffset(family),
					Len:          ipAddrLen(family),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            ipAddrLen(family),
					Mask:           allowedNet.Mask,
					Xor:            make([]byte, ipAddrLen(family)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     allowedNet.IP,
				},
				// Accept
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})

		// Add return traffic rule when NAT is disabled
		if !nat {
			// Match: source is allowed CIDR and destination is VPN CIDR -> ACCEPT
			f.conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: forwardChain,
				Exprs: []expr.Any{
					// Match source address (allowed CIDR)
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipSourceOffset(family),
						Len:          ipAddrLen(family),
					},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            ipAddrLen(family),
						Mask:           allowedNet.Mask,
						Xor:            make([]byte, ipAddrLen(family)),
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     allowedNet.IP,
					},
					// Match destination address (VPN CIDR)
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipDestOffset(family),
						Len:          ipAddrLen(family),
					},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            ipAddrLen(family),
						Mask:           vpnNet.Mask,
						Xor:            make([]byte, ipAddrLen(family)),
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     vpnNet.IP,
					},
					// Accept
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			})
		}
	}

	// Reject everything else from VPN CIDR
	f.conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match source address (VPN CIDR)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       ipSourceOffset(family),
				Len:          ipAddrLen(family),
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            ipAddrLen(family),
				Mask:           vpnNet.Mask,
				Xor:            make([]byte, ipAddrLen(family)),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     vpnNet.IP,
			},
			// Reject
			&expr.Reject{
				Type: unix.NFT_REJECT_ICMP_UNREACH,
				Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
			},
		},
	})

	// Add NAT rule if enabled and gateway interface is specified
	if nat && gatewayIface != "" {
		// Match: source is VPN CIDR and outgoing interface is gateway -> MASQUERADE
		f.conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: postroutingChain,
			Exprs: []expr.Any{
				// Match source address (VPN CIDR)
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipSourceOffset(family),
					Len:          ipAddrLen(family),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            ipAddrLen(family),
					Mask:           vpnNet.Mask,
					Xor:            make([]byte, ipAddrLen(family)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     vpnNet.IP,
				},
				// Match outgoing interface
				&expr.Meta{
					Key:      expr.MetaKeyOIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(gatewayIface + "\x00"),
				},
				// Masquerade
				&expr.Masq{},
			},
		})
	}

	return nil
}
