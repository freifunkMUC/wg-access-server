package serve

import (
	"net/netip"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
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

	wg, err := wgembed.NewWithOpts(wgembed.Options{
		InterfaceName:     conf.WireGuard.Interface,
		AllowKernelModule: true,
	})
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "failed to create WireGuard interface"))
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
		return wg, stop, errors.Wrap(err, "failed to load WireGuard config")
	}

	logrus.Infof("WireGuard VPN network is %s", network.StringJoinIPNets(vpn.ipv4, vpn.ipv6))

	options := network.ForwardingOptions{
		GatewayIface:    conf.VPN.GatewayInterface,
		CIDR:            conf.VPN.CIDR,
		CIDRv6:          conf.VPN.CIDRv6,
		NAT44:           conf.VPN.NAT44,
		NAT66:           conf.VPN.NAT66,
		ClientIsolation: conf.VPN.ClientIsolation,
		AllowedIPs:      conf.VPN.AllowedIPs,
		Firewall:        conf.VPN.Firewall,
	}
	if err := network.ConfigureForwarding(options); err != nil {
		return wg, stop, err
	}

	if err := hooks.Run(hooks.PostUp, conf.WireGuard.Interface, conf.WireGuard.PostUp); err != nil {
		logrus.Fatal(err)
	}
	return wg, stop, nil
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
			logrus.Fatal(errors.Wrap(err, "refusing to run the configured lifecycle commands"))
		}
		return
	}
}
