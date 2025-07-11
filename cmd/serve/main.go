package serve

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/docker/docker/libnetwork/types"
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v2"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/dnsproxy"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/services"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
)

func Register(app *kingpin.Application) *servecmd {
	cmd := &servecmd{}
	cli := app.Command(cmd.Name(), "Run the server")
	cli.Flag("config", "Path to a wg-access-server config file").Envar("WG_CONFIG").StringVar(&cmd.ConfigFilePath)
	cli.Flag("admin-username", "Admin username (defaults to admin)").Envar("WG_ADMIN_USERNAME").Default("admin").StringVar(&cmd.AppConfig.AdminUsername)
	cli.Flag("admin-password", "Admin password (provide plaintext, stored in-memory only)").Envar("WG_ADMIN_PASSWORD").StringVar(&cmd.AppConfig.AdminPassword)
	cli.Flag("port", "The port that the web ui server will listen on").Envar("WG_PORT").Default("8000").IntVar(&cmd.AppConfig.Port)
	cli.Flag("external-host", "The external origin of the server (e.g. https://mydomain.com)").Envar("WG_EXTERNAL_HOST").StringVar(&cmd.AppConfig.ExternalHost)
	cli.Flag("storage", "The storage backend connection string").Envar("WG_STORAGE").Default("memory://").StringVar(&cmd.AppConfig.Storage)
	cli.Flag("disable-metadata", "Disable metadata collection (i.e. metrics)").Envar("WG_DISABLE_METADATA").Default("false").BoolVar(&cmd.AppConfig.DisableMetadata)
	cli.Flag("enable-inactive-device-deletion", "Enable inactive device deletion").Envar("WG_ENABLE_INACTIVE_DEVICE_DELETION").Default("false").BoolVar(&cmd.AppConfig.EnableInactiveDeviceDeletion)
	cli.Flag("inactive-device-grace-period", "Duration after inactive device are deleted").Envar("WG_INACTIVE_DEVICE_GRACE_PERIOD").Default((1 * config.Year).String()).DurationVar(&cmd.AppConfig.InactiveDeviceGracePeriod)
	cli.Flag("filename", "The configuration filename (e.g. WireGuard-Home)").Envar("WG_FILENAME").StringVar(&cmd.AppConfig.Filename)
	cli.Flag("https-enabled", "Enable HTTPS for the web UI").Envar("WG_HTTPS_ENABLED").Default("true").BoolVar(&cmd.AppConfig.HTTPS.Enabled)
	cli.Flag("https-cert-file", "Path to the TLS certificate file").Envar("WG_HTTPS_CERT_FILE").StringVar(&cmd.AppConfig.HTTPS.CertFile)
	cli.Flag("https-key-file", "Path to the TLS private key file").Envar("WG_HTTPS_KEY_FILE").StringVar(&cmd.AppConfig.HTTPS.KeyFile)
	cli.Flag("https-port", "Port for HTTPS server").Envar("WG_HTTPS_PORT").Default("8443").IntVar(&cmd.AppConfig.HTTPS.Port)
	cli.Flag("https-host", "Listen host for HTTPS server").Envar("WG_HTTPS_HOST").Default("").StringVar(&cmd.AppConfig.HTTPS.Host)
	cli.Flag("http-host", "Listen host for HTTP server").Envar("WG_HTTP_HOST").Default("").StringVar(&cmd.AppConfig.HttpHost)
	cli.Flag("wireguard-enabled", "Enable or disable the embedded wireguard server (useful for development)").Envar("WG_WIREGUARD_ENABLED").Default("true").BoolVar(&cmd.AppConfig.WireGuard.Enabled)
	cli.Flag("wireguard-interface", "Set the wireguard interface name").Default("wg0").Envar("WG_WIREGUARD_INTERFACE").StringVar(&cmd.AppConfig.WireGuard.Interface)
	cli.Flag("wireguard-private-key", "Wireguard private key").Envar("WG_WIREGUARD_PRIVATE_KEY").StringVar(&cmd.AppConfig.WireGuard.PrivateKey)
	cli.Flag("wireguard-port", "The port that the Wireguard server will listen on").Envar("WG_WIREGUARD_PORT").Default("51820").IntVar(&cmd.AppConfig.WireGuard.Port)
	cli.Flag("wireguard-mtu", "The maximum transmission unit (MTU) to be used on the server-side interface.").Envar("WG_WIREGUARD_MTU").Default("1420").IntVar(&cmd.AppConfig.WireGuard.MTU)
	cli.Flag("vpn-allowed-ips", "A list of networks that VPN clients will be allowed to connect to via the VPN").Envar("WG_VPN_ALLOWED_IPS").Default("0.0.0.0/0", "::/0").StringsVar(&cmd.AppConfig.VPN.AllowedIPs)
	cli.Flag("vpn-cidr", "The network CIDR for the VPN").Envar("WG_VPN_CIDR").Default("10.44.0.0/24").StringVar(&cmd.AppConfig.VPN.CIDR)
	cli.Flag("vpn-cidrv6", "The IPv6 network CIDR for the VPN").Envar("WG_VPN_CIDRV6").Default("fd48:4c4:7aa9::/64").StringVar(&cmd.AppConfig.VPN.CIDRv6)
	cli.Flag("vpn-gateway-interface", "The gateway network interface (i.e. eth0)").Envar("WG_VPN_GATEWAY_INTERFACE").Default(detectDefaultInterface()).StringVar(&cmd.AppConfig.VPN.GatewayInterface)
	cli.Flag("vpn-nat44-enabled", "Enable or disable NAT of IPv6 traffic leaving through the gateway").Envar("WG_IPV4_NAT_ENABLED").Default("true").BoolVar(&cmd.AppConfig.VPN.NAT44)
	cli.Flag("vpn-nat66-enabled", "Enable or disable NAT of IPv6 traffic leaving through the gateway").Envar("WG_IPV6_NAT_ENABLED").Default("true").BoolVar(&cmd.AppConfig.VPN.NAT66)
	cli.Flag("vpn-client-isolation", "Block or allow traffic between client devices").Envar("WG_VPN_CLIENT_ISOLATION").Default("false").BoolVar(&cmd.AppConfig.VPN.ClientIsolation)
	cli.Flag("vpn-disable-iptables", "Disable iptables configuration completely").Envar("WG_VPN_DISABLE_IPTABLES").Default("false").BoolVar(&cmd.AppConfig.VPN.DisableIPTables)
	cli.Flag("dns-enabled", "Enable or disable the embedded dns proxy server (useful for development)").Envar("WG_DNS_ENABLED").Default("true").BoolVar(&cmd.AppConfig.DNS.Enabled)
	cli.Flag("dns-upstream", "An upstream DNS server to proxy DNS traffic to. Defaults to resolvconf with Cloudflare DNS as fallback").Envar("WG_DNS_UPSTREAM").StringsVar(&cmd.AppConfig.DNS.Upstream)
	cli.Flag("dns-domain", "A domain to serve configured device names authoritatively").Envar("WG_DNS_DOMAIN").StringVar(&cmd.AppConfig.DNS.Domain)
	cli.Flag("clientconfig-dns-servers", "DNS servers (one or more IPs, comma separated) to write into the client configuration file").Envar("WG_CLIENTCONFIG_DNS_SERVERS").StringsVar(&cmd.AppConfig.ClientConfig.DNSServers)
	cli.Flag("clientconfig-dns-search-domain", "DNS search domain to write into the client configuration file").Envar("WG_CLIENTCONFIG_DNS_SEARCH_DOMAIN").StringVar(&cmd.AppConfig.ClientConfig.DNSSearchDomain)
	cli.Flag("clientconfig-mtu", "The maximum transmission unit (MTU) to write into the client configuration file").Envar("WG_CLIENTCONFIG_MTU").IntVar(&cmd.AppConfig.ClientConfig.MTU)
	return cmd
}

type servecmd struct {
	ConfigFilePath string
	AppConfig      config.AppConfig
}

func (cmd *servecmd) Name() string {
	return "serve"
}

func (cmd *servecmd) Run() {

	// Swallow any panic stacktrace
	defer func() {
		if err := recover(); err != nil {
			logrus.Fatal(err)
		}
	}()

	conf := cmd.ReadConfig()

	// Software banner
	logrus.Infof("+++ wg-access-server %s (%s)", buildinfo.Version(), buildinfo.ShortCommitHash())

	// Get the server's IP addresses within the VPN
	var vpnip, vpnipv6 netip.Prefix
	var err error
	vpnip, vpnipv6, err = network.ServerVPNIPs(conf.VPN.CIDR, conf.VPN.CIDRv6)
	if err != nil {
		logrus.Fatal(err)
	}
	if !vpnip.IsValid() && !vpnipv6.IsValid() {
		logrus.Fatal("Need at least one of VPN.CIDR or VPN.CIDRv6 set")
	}

	// Allow traffic to wg-access-server's peer endpoint.
	// This is important because clients will send traffic
	// to the embedded DNS proxy using the VPN IP
	vpnipstrings := make([]string, 0, 2)
	if vpnip.IsValid() {
		conf.VPN.AllowedIPs = append(conf.VPN.AllowedIPs, netip.PrefixFrom(vpnip.Addr(), 32).String())
		vpnipstrings = append(vpnipstrings, vpnip.String())
	}
	if vpnipv6.IsValid() {
		conf.VPN.AllowedIPs = append(conf.VPN.AllowedIPs, netip.PrefixFrom(vpnipv6.Addr(), 128).String())
		vpnipstrings = append(vpnipstrings, vpnipv6.String())
	}
	vpnips := make([]netip.Addr, 0, 2)
	if vpnip.IsValid() {
		vpnips = append(vpnips, vpnip.Addr())
	}
	if vpnipv6.IsValid() {
		vpnips = append(vpnips, vpnipv6.Addr())
	}

	// WireGuard Server
	wg := wgembed.NewNoOpInterface()
	if conf.WireGuard.Enabled {
		wgOpts := wgembed.Options{
			InterfaceName:     conf.WireGuard.Interface,
			AllowKernelModule: true,
		}
		wgimpl, err := wgembed.NewWithOpts(wgOpts)
		if err != nil {
			logrus.Fatal(errors.Wrap(err, "failed to create WireGuard interface"))
		}
		defer wgimpl.Close()
		wg = wgimpl

		logrus.Infof("Starting WireGuard on :%d", conf.WireGuard.Port)

		wgconfig := &wgembed.ConfigFile{
			Interface: wgembed.IfaceConfig{
				PrivateKey: conf.WireGuard.PrivateKey,
				Address:    vpnipstrings,
				ListenPort: &conf.WireGuard.Port,
				MTU:        &conf.WireGuard.MTU,
			},
		}

		if err := wg.LoadConfig(wgconfig); err != nil {
			logrus.Error(errors.Wrap(err, "failed to load WireGuard config"))
			return
		}

		logrus.Infof("WireGuard VPN network is %s", network.StringJoinIPNets(vpnip, vpnipv6))

		options := network.ForwardingOptions{
			GatewayIface:    conf.VPN.GatewayInterface,
			CIDR:            conf.VPN.CIDR,
			CIDRv6:          conf.VPN.CIDRv6,
			NAT44:           conf.VPN.NAT44,
			NAT66:           conf.VPN.NAT66,
			ClientIsolation: conf.VPN.ClientIsolation,
			AllowedIPs:      conf.VPN.AllowedIPs,
			DisableIPTables: conf.VPN.DisableIPTables,
		}

		if err := network.ConfigureForwarding(options); err != nil {
			logrus.Error(err)
			return
		}
	}

	// Storage
	storageBackend, err := storage.NewStorage(conf.Storage)
	if err != nil {
		logrus.Error(errors.Wrap(err, "failed to create storage backend"))
		return
	}
	if err := storageBackend.Open(); err != nil {
		logrus.Error(errors.Wrap(err, "failed to connect/open storage backend"))
		return
	}
	defer storageBackend.Close()

	// Device manager
	deviceManager := devices.New(wg, storageBackend, conf.VPN.CIDR, conf.VPN.CIDRv6)

	// DNS Server
	if conf.DNS.Enabled {
		if len(conf.DNS.Upstream) == 0 {
			conf.DNS.Upstream = detectDNSUpstream(conf.VPN.CIDR != "", conf.VPN.CIDRv6 != "")
		}
		listenAddr := make([]string, 0, 2)
		for _, addr := range vpnips {
			listenAddr = append(listenAddr, net.JoinHostPort(addr.String(), "53"))
		}
		dns, err := dnsproxy.New(dnsproxy.DNSServerOpts{
			Upstream:   conf.DNS.Upstream,
			Domain:     conf.DNS.Domain,
			ListenAddr: listenAddr,
		})
		if err != nil {
			logrus.Error(errors.Wrap(err, "failed to create dns server"))
			return
		}
		dns.ListenAndServe()
		defer dns.Close()
		if conf.DNS.Domain != "" {
			// Generate initial DNS zone for registered devices
			zone := generateZone(deviceManager, vpnips)
			dns.PushAuthZone(zone)
			// Update the zone in the background whenever a device changes
			storageBackend.OnAdd(
				func(_ *storage.Device) {
					zone := generateZone(deviceManager, vpnips)
					dns.PushAuthZone(zone)
				},
			)
			storageBackend.OnDelete(
				func(_ *storage.Device) {
					zone := generateZone(deviceManager, vpnips)
					dns.PushAuthZone(zone)
				},
			)
		}
	}

	// Services
	if err := deviceManager.StartSync(conf.DisableMetadata, conf.EnableInactiveDeviceDeletion, conf.InactiveDeviceGracePeriod); err != nil {
		logrus.Error(errors.Wrap(err, "failed to sync"))
		return
	}

	router := mux.NewRouter()
	router.Use(services.TracesMiddleware)
	router.Use(services.RecoveryMiddleware)

	// Health check endpoint
	router.PathPrefix("/health").Handler(services.HealthEndpoint(deviceManager))

	// Authentication middleware
	middleware, err := authnz.NewMiddleware(conf.Auth, authnz.ClaimsMiddleware(conf))
	if err != nil {
		logrus.Error(errors.Wrap(err, "failed to set up authnz middleware"))
		return
	}
	router.Use(middleware)

	// Subrouter for our site (web + api)
	site := router.PathPrefix("/").Subrouter()
	site.Use(authnz.RequireAuthentication)

	// Grpc api
	site.PathPrefix("/api").Handler(services.ApiRouter(&services.ApiServices{
		Config:        conf,
		DeviceManager: deviceManager,
		Wg:            wg,
	}))

	// Static website
	site.PathPrefix("/").Handler(services.WebsiteRouter())

	publicRouter := router

	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	errChan := make(chan error)

	// Listen
	address := fmt.Sprintf("%s:%d", conf.HttpHost, conf.Port)

	// Create a new HTTP server
	httpSrv := &http.Server{
		Addr:    address,
		Handler: publicRouter,
	}

	// Start HTTP server
	go func() {
		logrus.Infof("Web UI listening on http://%v", address)
		err := httpSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- errors.Wrap(err, "unable to start http server")
		}
	}()

	// Start HTTPS server if enabled
	var httpsSrv *http.Server
	if conf.HTTPS.Enabled {
		// Determine HTTPS port
		httpsAddress := fmt.Sprintf("%s:%d", conf.HTTPS.Host, conf.HTTPS.Port)

		// Determine certificate paths
		certPath := conf.HTTPS.CertFile
		keyPath := conf.HTTPS.KeyFile
		if certPath == "" || keyPath == "" {
			certPath, keyPath = services.GetDefaultCertPaths()
		}

		// Load TLS certificate
		tlsConfig, err := services.LoadTLSCert(certPath, keyPath)
		if err != nil {
			logrus.Error(errors.Wrap(err, "failed to load TLS certificate"))
			return
		}

		// Create HTTPS server
		httpsSrv = &http.Server{
			Addr:      httpsAddress,
			Handler:   publicRouter,
			TLSConfig: tlsConfig,
		}

		// Start HTTPS server
		go func() {
			logrus.Infof("Web UI listening on https://%v", httpsAddress)
			err := httpsSrv.ListenAndServeTLS("", "") // Cert and key are already in TLSConfig
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- errors.Wrap(err, "unable to start https server")
			}
		}()
	}

	select {
	case <-signalChan:
		// Shutdown logic
		logrus.Info("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			logrus.Error(errors.Wrap(err, "unable to shutdown http server"))
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(ctx); err != nil {
				logrus.Error(errors.Wrap(err, "unable to shutdown https server"))
			}
		}
	case err := <-errChan:
		logrus.Error(err)
	}
}

// ReadConfig reads the config file from disk if specified and overrides any env vars or cmdline options
func (cmd *servecmd) ReadConfig() *config.AppConfig {
	if cmd.ConfigFilePath != "" {
		if b, err := os.ReadFile(cmd.ConfigFilePath); err == nil {
			if err := yaml.Unmarshal(b, &cmd.AppConfig); err != nil {
				logrus.Fatal(errors.Wrap(err, "failed to bind configuration file"))
			}
		}
	}

	if cmd.AppConfig.LogLevel != "" {
		if level, err := logrus.ParseLevel(cmd.AppConfig.LogLevel); err == nil {
			logrus.SetLevel(level)
		}
	}

	if cmd.AppConfig.DisableMetadata {
		logrus.Info("Metadata collection has been disabled. No metrics or device connectivity information will be recorded or shown")
	}

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
			cmd.AppConfig.Auth.Simple.Users = append(cmd.AppConfig.Auth.Simple.Users, fmt.Sprintf("%s:%s", cmd.AppConfig.AdminUsername, string(pw)))
		} else {
			// there already exists a basic auth section, set a basic auth entry for the admin user
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

func splitByCommaAndTrim(s string) []string {
	result := strings.Split(s, ",")
	for i, addr := range result {
		result[i] = strings.TrimSpace(addr)
	}
	return result
}

func detectDNSUpstream(ipv4Enabled, ipv6Enabled bool) []string {
	upstream := []string{}
	if r, err := resolvconf.Get(); err == nil {
		upstream = resolvconf.GetNameservers(r.Content, types.IP)
	}
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
	for _, link := range links {
		// First try IPv4, then IPv6, hope both have the same default interface
		for family := range []int{4, 6} {
			routes, err := netlink.RouteList(link, family)
			if err != nil {
				logrus.Warn(errors.Wrapf(err, "failed to list routes for interface %s", link.Attrs().Name))
				return ""
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

func generateZone(deviceManager *devices.DeviceManager, vpnips []netip.Addr) dnsproxy.Zone {
	devs, err := deviceManager.ListAllDevices()
	if err != nil {
		logrus.Error(errors.Wrap(err, "could not query devices to generate the DNS zone"))
	}

	zone := make(dnsproxy.Zone)
	for _, device := range devs {
		owner := device.Owner
		name := device.Name
		addressStrings := network.SplitAddresses(device.Address)
		addresses := make([]netip.Addr, 0, 2)
		for _, str := range addressStrings {
			pref, err := netip.ParsePrefix(str)
			if err != nil {
				continue
			}
			addresses = append(addresses, pref.Addr())
		}
		zone[dnsproxy.ZoneKey{Owner: owner, Name: name}] = addresses
	}
	zone[dnsproxy.ZoneKey{}] = vpnips
	return zone
}

var missingPrivateKey = `Missing WireGuard private key:

    create a key:

        $ wg genkey

    configure via environment variable:

        $ export WIREGUARD_PRIVATE_KEY="<private-key>"

    or configure via flag:

        $ wg-access-server serve --wireguard-private-key="<private-key>"

    or configure via file:

      wireguard:
        privateKey: "<private-key>"

`
