package serve

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v2"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/resolvconf"
)

// ReadConfig reads the config file from disk if specified and overrides any env vars or cmdline options
func (cmd *servecmd) ReadConfig() *config.AppConfig {
	if cmd.ConfigFilePath != "" {
		b, err := os.ReadFile(cmd.ConfigFilePath)
		if err != nil {
			logrus.Fatal(errors.Wrap(err, "failed to read configuration file"))
		}
		if err := yaml.Unmarshal(b, &cmd.AppConfig); err != nil {
			logrus.Fatal(errors.Wrap(err, "failed to bind configuration file"))
		}
	}

	if err := cmd.loadSecretFiles(); err != nil {
		logrus.Fatal(err)
	}

	if cmd.AppConfig.LogLevel != "" {
		if level, err := logrus.ParseLevel(cmd.AppConfig.LogLevel); err == nil {
			logrus.SetLevel(level)
		}
	}

	if !cmd.AppConfig.EnableMetadata {
		logrus.Info("Metadata collection has been disabled. No device connectivity information or device metrics will be recorded or shown")
	} else if !cmd.AppConfig.EnableDeviceMetrics {
		logrus.Info("Device-level Prometheus metrics are disabled; metadata remains available for the UI")
	}
	metricsAuthEnabled := cmd.AppConfig.Metrics.BasicAuth.Username != "" && cmd.AppConfig.Metrics.BasicAuth.PasswordHash != ""
	if cmd.AppConfig.Metrics.BasicAuth.Username != "" {
		if !metricsAuthEnabled {
			logrus.Warn("Metrics basic auth username is set but password hash is missing")
		} else {
			logrus.Info("Basic auth is enabled for /metrics")
		}
	}
	if cmd.AppConfig.EnableMetadata && cmd.AppConfig.EnableDeviceMetrics && cmd.AppConfig.Metrics.MaxDeviceSeries != 0 && !metricsAuthEnabled {
		logrus.Warn("Per-device metrics are exposed on the unauthenticated /metrics endpoint: device names and owner identities are readable by anyone who can reach it")
	}

	if !cmd.AppConfig.HttpEnabled && !cmd.AppConfig.HTTPS.Enabled {
		logrus.Fatal("Both the HTTP and the HTTPS listener are disabled - the web UI would not be reachable at all")
	}
	if !cmd.AppConfig.HttpEnabled && (cmd.AppConfig.Auth.SessionStore == nil || !cmd.AppConfig.Auth.SessionStore.Secure) {
		logrus.Info("The web UI is served over HTTPS only: consider setting auth.sessionStore.secure to keep browsers from ever sending the session cookie over plain HTTP")
	}
	if cmd.AppConfig.HttpEnabled && cmd.AppConfig.HTTPS.Enabled {
		// Info, not a warning: serving plain HTTP behind a TLS terminating
		// proxy is a perfectly normal setup.
		logrus.Infof("The web UI is also served over plain HTTP on port %d. Unless something in front of it terminates TLS, client configurations and their private keys travel unencrypted - disable it with --no-http-enabled", cmd.AppConfig.Port)
	}

	if err := cmd.AppConfig.Auth.Validate(); err != nil {
		logrus.Fatal(err)
	}

	firewall, err := network.ResolveFirewall(cmd.AppConfig.VPN.Firewall, cmd.AppConfig.VPN.DisableIPTables)
	if err != nil {
		logrus.Fatal(err)
	}
	cmd.AppConfig.VPN.Firewall = firewall

	if !cmd.AppConfig.Auth.IsEnabled() {
		if cmd.AppConfig.AdminPassword == "" {
			logrus.Fatal("Missing admin password: please set via environment variable, flag or config file")
		}
	}

	if cmd.AppConfig.AdminPassword != "" {
		// set a basic auth entry for the admin user
		pw, err := bcrypt.GenerateFromPassword([]byte(cmd.AppConfig.AdminPassword), bcrypt.DefaultCost)
		if err != nil {
			logrus.Fatal(errors.Wrap(err, "failed to generate a bcrypt hash for the provided admin password"))
		}
		if cmd.AppConfig.Auth.Simple == nil && cmd.AppConfig.Auth.Basic == nil {
			// basic and simple auth are unset, enable simple auth for the admin user
			cmd.AppConfig.Auth.Simple = &authconfig.SimpleAuthConfig{}
			cmd.AppConfig.Auth.Simple.Users = append(cmd.AppConfig.Auth.Simple.Users, fmt.Sprintf("%s:%s", cmd.AppConfig.AdminUsername, string(pw)))
		} else if cmd.AppConfig.Auth.Simple != nil {
			// there already exists a simple auth section, set a simple auth entry for the admin user
			warnIfUserExists(cmd.AppConfig.Auth.Simple.Users, cmd.AppConfig.AdminUsername, "auth.simple")
			cmd.AppConfig.Auth.Simple.Users = append(cmd.AppConfig.Auth.Simple.Users, fmt.Sprintf("%s:%s", cmd.AppConfig.AdminUsername, string(pw)))
		} else {
			// there already exists a basic auth section, set a basic auth entry for the admin user
			warnIfUserExists(cmd.AppConfig.Auth.Basic.Users, cmd.AppConfig.AdminUsername, "auth.basic")
			cmd.AppConfig.Auth.Basic.Users = append(cmd.AppConfig.Auth.Basic.Users, fmt.Sprintf("%s:%s", cmd.AppConfig.AdminUsername, string(pw)))
		}
	}

	// we'll generate a private key when using memory://
	// storage only.
	if cmd.AppConfig.WireGuard.PrivateKey == "" {
		if !strings.HasPrefix(cmd.AppConfig.Storage, "memory://") {
			logrus.Fatal(missingPrivateKey)
		}
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			logrus.Fatal(errors.Wrap(err, "failed to generate a server private key"))
		}
		cmd.AppConfig.WireGuard.PrivateKey = key.String()
	}

	// The empty string can be hard to pass through an env var, so we accept '0' too
	if cmd.AppConfig.VPN.CIDR == "0" {
		cmd.AppConfig.VPN.CIDR = ""
	}
	if cmd.AppConfig.VPN.CIDRv6 == "0" {
		cmd.AppConfig.VPN.CIDRv6 = ""
	}
	if cmd.AppConfig.DNS.Domain == "0" {
		cmd.AppConfig.DNS.Domain = ""
	}

	// kingpin only splits env vars by \n, let's split at commas as well
	if len(cmd.AppConfig.VPN.AllowedIPs) == 1 {
		cmd.AppConfig.VPN.AllowedIPs = splitByCommaAndTrim(cmd.AppConfig.VPN.AllowedIPs[0])
	}
	if len(cmd.AppConfig.DNS.Upstream) == 1 {
		cmd.AppConfig.DNS.Upstream = splitByCommaAndTrim(cmd.AppConfig.DNS.Upstream[0])
	}
	if len(cmd.AppConfig.ClientConfig.DNSServers) == 1 {
		cmd.AppConfig.ClientConfig.DNSServers = splitByCommaAndTrim(cmd.AppConfig.ClientConfig.DNSServers[0])
	}

	return &cmd.AppConfig
}

// warnIfUserExists reports a user list that already carries an entry for the
// admin username. The login check stops at the first entry whose username
// matches, and the admin entry is appended behind the configured ones, so the
// existing entry decides the password while the admin password set through
// the environment, a flag or the config file quietly does nothing. The user
// still gets admin rights - those follow the username, not the entry.
func warnIfUserExists(users []string, username, section string) {
	for _, user := range users {
		if name, _, ok := strings.Cut(user, ":"); ok && name == username {
			logrus.Warnf("%s already contains a user '%s': that entry decides the password and the configured admin password has no effect - remove one of the two", section, username)
			return
		}
	}
}

func splitByCommaAndTrim(s string) []string {
	result := strings.Split(s, ",")
	for i, addr := range result {
		result[i] = strings.TrimSpace(addr)
	}
	return result
}

func detectDNSUpstream(ipv4Enabled, ipv6Enabled bool) []string {
	upstream := resolvconf.Nameservers()
	if len(upstream) == 0 {
		logrus.Warn("Failed to get nameservers from /etc/resolv.conf defaulting to Cloudflare DNS instead")
		// If there's no default route for IPv6, lookup fails immediately without delay and we retry using IPv4
		if ipv6Enabled {
			upstream = append(upstream, "2606:4700:4700::1111")
		}
		if ipv4Enabled {
			upstream = append(upstream, "1.1.1.1")
		}
	}
	return upstream
}

func detectDefaultInterface() string {
	links, err := netlink.LinkList()
	if err != nil {
		logrus.Warn(errors.Wrap(err, "failed to list network interfaces"))
		return ""
	}
	return defaultInterfaceName(links, netlink.RouteList)
}

// defaultInterfaceName returns the name of the first link that carries a
// default route. routeList is netlink.RouteList in production and a stub in
// the tests.
func defaultInterfaceName(links []netlink.Link, routeList func(netlink.Link, int) ([]netlink.Route, error)) string {
	for _, link := range links {
		// First try IPv4, then IPv6, hope both have the same default interface
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := routeList(link, family)
			if err != nil {
				// One interface whose routes cannot be read (e.g. it went away
				// while we were listing) must not hide the default route of
				// every interface still to come.
				logrus.Warn(errors.Wrapf(err, "failed to list routes for interface %s", link.Attrs().Name))
				continue
			}
			for _, route := range routes {
				if route.Dst != nil && route.Dst.IP.IsUnspecified() {
					return link.Attrs().Name
				}
			}
		}
	}
	logrus.Warn(errors.New("Could not determine the default network interface name"))
	return ""
}

var missingPrivateKey = `Missing WireGuard private key:

    create a key:

        $ wg genkey

    configure via environment variable:

        $ export WG_WIREGUARD_PRIVATE_KEY="<private-key>"

    or configure via flag:

        $ wg-access-server serve --wireguard-private-key="<private-key>"

    or configure via file:

      wireguard:
        privateKey: "<private-key>"

`
