package serve

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/hooks"
	"github.com/freifunkMUC/wg-access-server/internal/network"
)

// vpnAddressing is the server's own place in the VPN: the addresses of its
// interface, in the forms the interface and the DNS proxy want them in.
type vpnAddressing struct {
	ipv4, ipv6 netip.Prefix
	prefixes   []string
	addrs      []netip.Addr
}

// vpnAddresses works out the server's addresses from the configured networks.
// Clients are allowed to reach them, because that is where the embedded DNS
// proxy answers.
func vpnAddresses(conf *config.AppConfig) vpnAddressing {
	ipv4, ipv6, err := network.ServerVPNIPs(conf.VPN.CIDR, conf.VPN.CIDRv6)
	if err != nil {
		logrus.Fatal(err)
	}
	if !ipv4.IsValid() && !ipv6.IsValid() {
		logrus.Fatal("Need at least one of VPN.CIDR or VPN.CIDRv6 set")
	}

	addressing := vpnAddressing{ipv4: ipv4, ipv6: ipv6}
	for _, address := range []struct {
		prefix netip.Prefix
		bits   int
	}{{ipv4, 32}, {ipv6, 128}} {
		if !address.prefix.IsValid() {
			continue
		}
		conf.VPN.AllowedIPs = append(conf.VPN.AllowedIPs, netip.PrefixFrom(address.prefix.Addr(), address.bits).String())
		addressing.prefixes = append(addressing.prefixes, address.prefix.String())
		addressing.addrs = append(addressing.addrs, address.prefix.Addr())
	}
	return addressing
}

// startWireGuard brings up the interface and the forwarding rules for it. The
// returned function takes them down again and has to be called even when
// starting failed, because part of it may be up already.
func (cmd *servecmd) startWireGuard(conf *config.AppConfig, vpn vpnAddressing) (wgembed.WireGuardInterface, func(), error) {
	cmd.verifyLifecycleCommands(conf)

	if !conf.WireGuard.Enabled {
		return wgembed.NewNoOpInterface(), func() {}, nil
	}

	if err := hooks.Run(hooks.PreUp, conf.WireGuard.Interface, conf.WireGuard.PreUp); err != nil {
		logrus.Fatal(err)
	}

	if err := removeStaleInterface(conf.WireGuard.Interface, netlink.LinkByName, netlink.LinkDel); err != nil {
		logrus.Fatal(err)
	}

	wg, err := wgembed.NewWithOpts(wgembed.Options{
		InterfaceName:     conf.WireGuard.Interface,
		AllowKernelModule: true,
		// A device may have networks behind it. Their traffic reaches the
		// interface only if the kernel routes them there, which wg-quick does
		// with "Table = auto" and wg-embed does with this.
		ManageRoutes: true,
	})
	if err != nil {
		logrus.Fatal(fmt.Errorf("failed to create WireGuard interface: %w", err))
	}
	// PreDown runs while the interface is still there, PostDown once it is gone.
	stop := func() {
		if err := hooks.Run(hooks.PreDown, conf.WireGuard.Interface, conf.WireGuard.PreDown); err != nil {
			logrus.Error(err)
		}
		_ = wg.Close()
		if err := hooks.Run(hooks.PostDown, conf.WireGuard.Interface, conf.WireGuard.PostDown); err != nil {
			logrus.Error(err)
		}
	}

	logrus.Infof("Starting WireGuard on :%d", conf.WireGuard.Port)

	wgconfig := &wgembed.ConfigFile{
		Interface: wgembed.IfaceConfig{
			PrivateKey: conf.WireGuard.PrivateKey,
			Address:    vpn.prefixes,
			ListenPort: &conf.WireGuard.Port,
			MTU:        &conf.WireGuard.MTU,
		},
	}
	if err := wg.LoadConfig(wgconfig); err != nil {
		return wg, stop, fmt.Errorf("failed to load WireGuard config: %w", err)
	}

	logrus.Infof("WireGuard VPN network is %s", network.StringJoinIPNets(vpn.ipv4, vpn.ipv6))

	if err := network.ConfigureForwarding(forwardingOptions(conf, vpn, devices.FirewallState{})); err != nil {
		return wg, stop, err
	}

	if err := hooks.Run(hooks.PostUp, conf.WireGuard.Interface, conf.WireGuard.PostUp); err != nil {
		logrus.Fatal(err)
	}
	return wg, stop, nil
}

// forwardingOptions describes the firewall rules for the clients: what the
// configuration allows them to reach, plus what changes while the server runs
// - the networks routed through devices, and who is in which access policy.
func forwardingOptions(conf *config.AppConfig, vpn vpnAddressing, state devices.FirewallState) network.ForwardingOptions {
	allowed := make([]string, 0, len(conf.VPN.AllowedIPs)+len(state.Routed))
	allowed = append(allowed, conf.VPN.AllowedIPs...)
	allowed = append(allowed, state.Routed...)

	// Every policy the configuration has, whether anybody is in it or not: a
	// policy that loses its last member has to lose its rules, and a set that
	// is not declared cannot be named by one.
	policies := make([]network.Policy, 0, len(conf.VPN.Policies))
	for _, name := range sortedPolicyNames(conf.VPN.Policies) {
		policies = append(policies, network.Policy{
			Name:       name,
			AllowedIPs: conf.VPN.Policies[name].AllowedIPs,
			Members:    state.Policies[name],
		})
	}

	serverAddresses := make([]string, 0, len(vpn.addrs))
	for _, addr := range vpn.addrs {
		serverAddresses = append(serverAddresses, addr.String())
	}

	return network.ForwardingOptions{
		GatewayIface:    conf.VPN.GatewayInterface,
		CIDR:            conf.VPN.CIDR,
		CIDRv6:          conf.VPN.CIDRv6,
		NAT44:           conf.VPN.NAT44,
		NAT66:           conf.VPN.NAT66,
		ClientIsolation: conf.VPN.ClientIsolation,
		AllowedIPs:      allowed,
		Policies:        policies,
		ServerAddresses: serverAddresses,
		Firewall:        conf.VPN.Firewall,
	}
}

func sortedPolicyNames(policies map[string]config.PolicyConfig) []string {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// firewallSync returns what the device manager calls when what the rules are
// built from has changed: a network routed through a device, or somebody whose
// access policies are not what they were. The rules are built from scratch
// every time, which is what happens at startup too - for nftables that is one
// atomic replacement of the ruleset.
//
// Without the WireGuard interface there are no rules of ours to speak of.
func firewallSync(conf *config.AppConfig, vpn vpnAddressing) func(devices.FirewallState) error {
	if !conf.WireGuard.Enabled {
		return nil
	}
	return func(state devices.FirewallState) error {
		logrus.Infof("Updating the firewall rules: %d network(s) routed through devices, %d access policy(s) with members",
			len(state.Routed), len(state.Policies))
		return network.ConfigureForwarding(forwardingOptions(conf, vpn, state))
	}
}

// verifyLifecycleCommands checks the config file the operator's commands come
// from. They run as this process does - root in most deployments - so the file
// has to be trustworthy.
func (cmd *servecmd) verifyLifecycleCommands(conf *config.AppConfig) {
	lifecycleCommands := [][]string{
		conf.WireGuard.PreUp, conf.WireGuard.PostUp,
		conf.WireGuard.PreDown, conf.WireGuard.PostDown,
	}
	for _, commands := range lifecycleCommands {
		if len(commands) == 0 {
			continue
		}
		if err := hooks.VerifyConfigFile(cmd.ConfigFilePath); err != nil {
			logrus.Fatal(fmt.Errorf("refusing to run the configured lifecycle commands: %w", err))
		}
		return
	}
}
