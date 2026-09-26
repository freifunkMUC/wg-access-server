package serve

import (
	"strconv"

	"github.com/alecthomas/kingpin/v2"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/dnsproxy"
	"github.com/freifunkMUC/wg-access-server/internal/metrics"
)

func Register(app *kingpin.Application) *servecmd {
	cmd := &servecmd{}
	cli := app.Command(cmd.Name(), "Run the server")
	cli.Flag("config", "Path to a wg-access-server config file").Envar("WG_CONFIG").StringVar(&cmd.ConfigFilePath)
	cli.Flag("admin-username", "Admin username (defaults to admin)").Envar("WG_ADMIN_USERNAME").Default("admin").StringVar(&cmd.AppConfig.AdminUsername)
	cli.Flag("admin-password", "Admin password (provide plaintext, stored in-memory only)").Envar("WG_ADMIN_PASSWORD").StringVar(&cmd.AppConfig.AdminPassword)
	cli.Flag("admin-password-file", "Read the admin password from this file (e.g. a Docker secret); exclusive with --admin-password").Envar("WG_ADMIN_PASSWORD_FILE").StringVar(&cmd.AdminPasswordFile)
	cli.Flag("port", "The port that the web ui server will listen on").Envar("WG_PORT").Default("8000").IntVar(&cmd.AppConfig.Port)
	cli.Flag("external-host", "The external origin of the server (e.g. https://mydomain.com)").Envar("WG_EXTERNAL_HOST").StringVar(&cmd.AppConfig.ExternalHost)
	cli.Flag("storage", "The storage backend connection string").Envar("WG_STORAGE").Default("memory://").StringVar(&cmd.AppConfig.Storage)
	cli.Flag("enable-metadata", "Enable metadata collection (i.e. metrics)").Envar("WG_ENABLE_METADATA").Default("true").BoolVar(&cmd.AppConfig.EnableMetadata)
	cli.Flag("enable-device-metrics", "Expose device-level metrics on /metrics (requires enable-metadata)").Envar("WG_ENABLE_DEVICE_METRICS").Default("false").BoolVar(&cmd.AppConfig.EnableDeviceMetrics)
	cli.Flag("metrics-basic-auth-username", "Require basic auth for /metrics (username)").Envar("WG_METRICS_BASIC_AUTH_USERNAME").StringVar(&cmd.AppConfig.Metrics.BasicAuth.Username)
	cli.Flag("metrics-basic-auth-password-hash", "Require basic auth for /metrics (bcrypt hash)").Envar("WG_METRICS_BASIC_AUTH_PASSWORD_HASH").StringVar(&cmd.AppConfig.Metrics.BasicAuth.PasswordHash)
	cli.Flag("metrics-max-device-series", "Maximum number of devices exported as individual series on /metrics (negative: unlimited, 0: aggregates only)").Envar("WG_METRICS_MAX_DEVICE_SERIES").Default(strconv.Itoa(metrics.DefaultMaxDeviceSeries)).IntVar(&cmd.AppConfig.Metrics.MaxDeviceSeries)
	cli.Flag("enable-inactive-device-deletion", "Enable inactive device deletion").Envar("WG_ENABLE_INACTIVE_DEVICE_DELETION").Default("false").BoolVar(&cmd.AppConfig.EnableInactiveDeviceDeletion)
	cli.Flag("inactive-device-grace-period", "Duration after inactive device are deleted").Envar("WG_INACTIVE_DEVICE_GRACE_PERIOD").Default((1 * config.Year).String()).DurationVar(&cmd.AppConfig.InactiveDeviceGracePeriod)
	cli.Flag("max-devices-per-user", "Maximum number of devices a single user may create (0: no limit)").Envar("WG_MAX_DEVICES_PER_USER").Default("0").IntVar(&cmd.AppConfig.MaxDevicesPerUser)
	cli.Flag("enable-api-tokens", "Let users create tokens for using the API from scripts").Envar("WG_ENABLE_API_TOKENS").Default("false").BoolVar(&cmd.AppConfig.EnableAPITokens)
	cli.Flag("filename", "The configuration filename (e.g. WireGuard-Home)").Envar("WG_FILENAME").StringVar(&cmd.AppConfig.Filename)
	cli.Flag("https-enabled", "Enable HTTPS for the web UI").Envar("WG_HTTPS_ENABLED").Default("true").BoolVar(&cmd.AppConfig.HTTPS.Enabled)
	cli.Flag("https-cert-file", "Path to the TLS certificate file").Envar("WG_HTTPS_CERT_FILE").StringVar(&cmd.AppConfig.HTTPS.CertFile)
	cli.Flag("https-key-file", "Path to the TLS private key file").Envar("WG_HTTPS_KEY_FILE").StringVar(&cmd.AppConfig.HTTPS.KeyFile)
	cli.Flag("https-port", "Port for HTTPS server").Envar("WG_HTTPS_PORT").Default("8443").IntVar(&cmd.AppConfig.HTTPS.Port)
	cli.Flag("https-host", "Listen host for HTTPS server").Envar("WG_HTTPS_HOST").Default("").StringVar(&cmd.AppConfig.HTTPS.Host)
	cli.Flag("http-host", "Listen host for HTTP server").Envar("WG_HTTP_HOST").Default("").StringVar(&cmd.AppConfig.HttpHost)
	cli.Flag("http-enabled", "Serve the web UI over plain HTTP as well. Disable to serve it over HTTPS only").Envar("WG_HTTP_ENABLED").Default("true").BoolVar(&cmd.AppConfig.HttpEnabled)
	cli.Flag("wireguard-enabled", "Enable or disable the embedded wireguard server (useful for development)").Envar("WG_WIREGUARD_ENABLED").Default("true").BoolVar(&cmd.AppConfig.WireGuard.Enabled)
	cli.Flag("wireguard-interface", "Set the wireguard interface name").Default("wg0").Envar("WG_WIREGUARD_INTERFACE").StringVar(&cmd.AppConfig.WireGuard.Interface)
	cli.Flag("wireguard-private-key", "Wireguard private key").Envar("WG_WIREGUARD_PRIVATE_KEY").StringVar(&cmd.AppConfig.WireGuard.PrivateKey)
	cli.Flag("wireguard-private-key-file", "Read the Wireguard private key from this file (e.g. a Docker secret); exclusive with --wireguard-private-key").Envar("WG_WIREGUARD_PRIVATE_KEY_FILE").StringVar(&cmd.WireGuardPrivateKeyFile)
	cli.Flag("wireguard-port", "The port that the Wireguard server will listen on").Envar("WG_WIREGUARD_PORT").Default("51820").IntVar(&cmd.AppConfig.WireGuard.Port)
	cli.Flag("wireguard-mtu", "The maximum transmission unit (MTU) to be used on the server-side interface.").Envar("WG_WIREGUARD_MTU").Default("1420").IntVar(&cmd.AppConfig.WireGuard.MTU)
	cli.Flag("vpn-allowed-ips", "A list of networks that VPN clients will be allowed to connect to via the VPN").Envar("WG_VPN_ALLOWED_IPS").Default("0.0.0.0/0", "::/0").StringsVar(&cmd.AppConfig.VPN.AllowedIPs)
	cli.Flag("vpn-cidr", "The network CIDR for the VPN").Envar("WG_VPN_CIDR").Default("10.44.0.0/24").StringVar(&cmd.AppConfig.VPN.CIDR)
	cli.Flag("vpn-cidrv6", "The IPv6 network CIDR for the VPN").Envar("WG_VPN_CIDRV6").Default("fd48:4c4:7aa9::/64").StringVar(&cmd.AppConfig.VPN.CIDRv6)
	cli.Flag("vpn-gateway-interface", "The gateway network interface (i.e. eth0)").Envar("WG_VPN_GATEWAY_INTERFACE").Default(detectDefaultInterface()).StringVar(&cmd.AppConfig.VPN.GatewayInterface)
	cli.Flag("vpn-nat44-enabled", "Enable or disable NAT of IPv6 traffic leaving through the gateway").Envar("WG_IPV4_NAT_ENABLED").Default("true").BoolVar(&cmd.AppConfig.VPN.NAT44)
	cli.Flag("vpn-nat66-enabled", "Enable or disable NAT of IPv6 traffic leaving through the gateway").Envar("WG_IPV6_NAT_ENABLED").Default("true").BoolVar(&cmd.AppConfig.VPN.NAT66)
	cli.Flag("vpn-client-isolation", "Block or allow traffic between client devices").Envar("WG_VPN_CLIENT_ISOLATION").Default("false").BoolVar(&cmd.AppConfig.VPN.ClientIsolation)
	cli.Flag("vpn-firewall", "How to set up the forwarding rules: iptables, nftables or none").Envar("WG_VPN_FIREWALL").StringVar(&cmd.AppConfig.VPN.Firewall)
	cli.Flag("vpn-disable-iptables", "Deprecated: use --vpn-firewall=none").Envar("WG_VPN_DISABLE_IPTABLES").Default("false").BoolVar(&cmd.AppConfig.VPN.DisableIPTables)
	cli.Flag("dns-enabled", "Enable or disable the embedded dns proxy server (useful for development)").Envar("WG_DNS_ENABLED").Default("true").BoolVar(&cmd.AppConfig.DNS.Enabled)
	cli.Flag("dns-upstream", "An upstream DNS server to proxy DNS traffic to. Defaults to resolvconf with Cloudflare DNS as fallback").Envar("WG_DNS_UPSTREAM").StringsVar(&cmd.AppConfig.DNS.Upstream)
	cli.Flag("dns-cache-size", "How many DNS responses the embedded DNS proxy caches (0 disables caching)").Envar("WG_DNS_CACHE_SIZE").Default(strconv.Itoa(dnsproxy.DefaultCacheSize)).IntVar(&cmd.AppConfig.DNS.CacheSize)
	cli.Flag("dns-domain", "A domain to serve configured device names authoritatively").Envar("WG_DNS_DOMAIN").StringVar(&cmd.AppConfig.DNS.Domain)
	cli.Flag("clientconfig-dns-servers", "DNS servers (one or more IPs, comma separated) to write into the client configuration file").Envar("WG_CLIENTCONFIG_DNS_SERVERS").StringsVar(&cmd.AppConfig.ClientConfig.DNSServers)
	cli.Flag("clientconfig-dns-search-domain", "DNS search domain to write into the client configuration file").Envar("WG_CLIENTCONFIG_DNS_SEARCH_DOMAIN").StringVar(&cmd.AppConfig.ClientConfig.DNSSearchDomain)
	cli.Flag("clientconfig-mtu", "The maximum transmission unit (MTU) to write into the client configuration file").Envar("WG_CLIENTCONFIG_MTU").IntVar(&cmd.AppConfig.ClientConfig.MTU)
	cli.Flag("clientconfig-persistent-keepalive", "The default persistent keepalive interval for all clients (in seconds)").Envar("WG_CLIENTCONFIG_PERSISTENT_KEEPALIVE").Default("0").IntVar(&cmd.AppConfig.ClientConfig.PersistentKeepalive)
	return cmd
}

type servecmd struct {
	ConfigFilePath          string
	AdminPasswordFile       string
	WireGuardPrivateKeyFile string
	AppConfig               config.AppConfig
}
