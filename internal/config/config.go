package config

import (
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
)

const (
	Day  time.Duration = 24 * time.Hour
	Year               = 365 * Day
)

type AppConfig struct {
	// Set the log level.
	// Defaults to "info" (fatal, error, warn, info, debug, trace)
	LogLevel string `yaml:"loglevel"`
	// Set the superadmin username
	// Defaults to "admin"
	AdminUsername string `yaml:"adminUsername"`
	// Set the superadmin password (required)
	AdminPassword string `yaml:"adminPassword"`
	// Port sets the port that the web UI will listen on.
	// Defaults to 8000
	Port int `yaml:"port"`
	// HTTP listen host
	// Defaults to "" (all hosts)
	HttpHost string `yaml:"httpHost"`
	// HttpEnabled controls whether the web UI is also served over plain
	// HTTP on Port. Turn it off to serve the UI over HTTPS only - the web UI
	// hands out client configurations including private keys, so anything
	// reaching it over HTTP sends them unencrypted.
	// Defaults to true
	HttpEnabled bool `yaml:"httpEnabled"`
	// ExternalHost is the address that clients
	// use to connect to the WireGuard interface
	// By default, this will be empty and the web ui
	// will use the current page's origin.
	ExternalHost string `yaml:"externalHost"`
	// The storage backend where device configuration will
	// be persisted.
	// Supports memory:// postgresql:// mysql:// sqlite3://
	// Defaults to memory://
	Storage string `yaml:"storage"`
	// EnableMetadata allows you to turn on collection of device
	// metadata including last handshake time & rx/tx bytes
	EnableMetadata bool `yaml:"enableMetadata"`
	// EnableDeviceMetrics controls whether device-level Prometheus metrics
	// are exposed on /metrics. Requires EnableMetadata to be effective.
	EnableDeviceMetrics bool `yaml:"enableDeviceMetrics"`
	// EnableInactiveDeviceDeletion allows you to delete inactive devices
	// automatically after a time duration defined by InactiveDeviceGracePeriod
	EnableInactiveDeviceDeletion bool `yaml:"enableInactiveDeviceDeletion"`
	// InactiveDeviceGracePeriod sets the duration after which inactive
	// devices are automatically deleted
	// Defaults to 1 year
	InactiveDeviceGracePeriod time.Duration `yaml:"inactiveDeviceGracePeriod"`
	// MaxDevicesPerUser limits how many devices a single user may create.
	// Admins are not exempt - the limit is about the addresses in the VPN
	// subnet, not about trust.
	// Defaults to 0 (no limit)
	MaxDevicesPerUser int `yaml:"maxDevicesPerUser"`
	// EnableAPITokens lets users create tokens for using the API from
	// scripts. A token keeps working until it expires or is revoked, even
	// after the web session it was created in has ended.
	// Defaults to false
	EnableAPITokens bool `yaml:"enableApiTokens"`
	// The name of the WireGuard configuration file that can
	// be downloaded through the web UI after adding a device.
	// Do not include the '.conf' extension
	// Defaults to 'WireGuard' (resulting full name 'WireGuard.conf')
	Filename string `yaml:"filename"`
	// Configure WireGuard related settings
	WireGuard WireGuardConfig `yaml:"wireguard"`
	// Configure VPN related settings (networking)
	VPN VPNConfig `yaml:"vpn"`
	// Configure the embedded DNS server
	DNS DNSConfig `yaml:"dns"`
	// Configures settings in the configuration file distributed to clients, either by download, or QR-code.
	ClientConfig ClientConfig `yaml:"clientConfig"`
	// Metrics configures access to the /metrics endpoint.
	Metrics MetricsConfig `yaml:"metrics"`
	// Auth configures optional authentication backends
	// to control access to the web ui.
	// Devices will be managed on a per-user basis if any
	// auth backends are configured.
	// If no authentication backends are configured then
	// the server will not require any authentication.
	Auth authconfig.AuthConfig `yaml:"auth"`
	// HTTPS configuration
	HTTPS HTTPSConfig `yaml:"https"`
}

type WireGuardConfig struct {
	// Set this to false to disable the embedded WireGuard
	// server. This is useful for development environments
	// on mac and windows where we don't currently support
	// the OS's network stack.
	Enabled bool `yaml:"enabled"`
	// The network interface name of the WireGuard
	// network device.
	// Defaults to wg0
	Interface string `yaml:"interface"`
	// The WireGuard PrivateKey
	// If this value is lost then any existing
	// clients (WireGuard peers) will no longer
	// be able to connect.
	// Clients will either have to manually update
	// their connection configuration or setup
	// their VPN again using the web ui (easier for most people)
	PrivateKey string `yaml:"privateKey"`
	// The WireGuard ListenPort
	// Defaults to 51820
	Port int `yaml:"port"`
	// The maximum transmission unit (MTU) used on the server-side.
	// Empty by default.
	MTU int `yaml:"mtu"`
	// PreUp, PostUp, PreDown and PostDown are shell commands run around
	// the lifecycle of the WireGuard interface, like the options of the
	// same name in a wg-quick configuration. '%i' is replaced with the
	// interface name, which is also passed as $WG_INTERFACE.
	//
	// They run as the user the server runs as, which is usually root, so
	// they can only be set in the config file - never through a flag or
	// an environment variable - and the file must not be writable by
	// anyone but its owner.
	// Empty by default.
	PreUp    []string `yaml:"preUp"`
	PostUp   []string `yaml:"postUp"`
	PreDown  []string `yaml:"preDown"`
	PostDown []string `yaml:"postDown"`
}

type VPNConfig struct {
	// The "AllowedIPs" for VPN clients.
	// This value will be included in client config
	// files and in server-side iptable rules
	// to enforce network access.
	// defaults to ["0.0.0.0/0", "::/0"]
	AllowedIPs []string `yaml:"allowedIPs"`
	// CIDR configures a network address space
	// that client (WireGuard peers) will be allocated
	// an IP address from
	// defaults to 10.44.0.0/24
	CIDR string `yaml:"cidr"`
	// CIDRv6 configures an IPv6 network address space
	// that client (WireGuard peers) will be allocated
	// an IP address from
	// defaults to fd48:4c4:7aa9::/64
	CIDRv6 string `yaml:"cidrv6"`
	// GatewayInterface will be used in iptable forwarding
	// rules that send VPN traffic from clients to this interface
	// Most use-cases will want this interface to have access
	// to the outside internet
	GatewayInterface string `yaml:"gatewayInterface"`
	// NAT44 configures whether IPv4 traffic leaving
	// through the GatewayInterface should be masqueraded
	// defaults to true
	NAT44 bool `yaml:"nat44"`
	// NAT66 configures whether IPv6 traffic leaving
	// through the GatewayInterface should be
	// masqueraded like IPv4 traffic
	// defaults to true
	NAT66 bool `yaml:"nat66"`
	// ClientIsolation configures whether traffic between client devices will be blocked or allowed
	// defaults to false
	ClientIsolation bool `yaml:"clientIsolation"`
	// Firewall is how the forwarding rules are set up: "iptables",
	// "nftables" or "none" (set up nothing).
	// defaults to iptables
	Firewall string `yaml:"firewall"`
	// DisableIPTables is the deprecated way of saying Firewall: none.
	DisableIPTables bool `yaml:"disableIPTables"`
}

type DNSConfig struct {
	// Enabled allows you to turn on/off
	// the VPN DNS proxy feature.
	// DNS Proxying is enabled by default.
	Enabled bool `yaml:"enabled"`
	// Upstream configures the addresses of upstream
	// DNS servers to which client DNS requests will be sent to.
	// An address may name a port ("192.0.2.1:5353", "[2001:db8::1]:5353"),
	// otherwise port 53 is used.
	// NOTE: wg-access-server prefers the first upstream and falls back on
	// failures. An upstream that fails is skipped for a short while, so a
	// dead resolver does not slow down every query.
	// Defaults the host's upstream DNS servers (via resolvconf)
	// or Cloudflare DNS if resolvconf cannot be used.
	Upstream []string `yaml:"upstream"`
	// CacheSize sets how many DNS responses the embedded DNS proxy keeps
	// in its cache. The cache is filled by what the clients query, so it
	// is bounded: the least recently used entries are dropped once it is
	// full. Set to 0 to disable caching.
	// Defaults to 10000.
	CacheSize int `yaml:"cacheSize"`
	// Domain sets a domain that the embedded dns server should serve authoritatively for device addresses.
	// A and AAAA queries for names in the format <device>.<user>.<domain> will be answered with the IP addresses
	// of the according device. Queries for <domain> will be answered with the VPN server address.
	// Example domain: 'vpn.home.arpa.'
	// Disabled by default.
	Domain string `yaml:"domain"`
}

type ClientConfig struct {
	// DNS servers to be provided with the client configuration file.
	// These are written into the configuration file as is.
	// If left empty the server decides about the address; usually the wg-access-server address.
	// If not empty, these replace the wg-access-servers DNS addresses.
	// Empty by default.
	DNSServers []string `yaml:"dnsServers"`
	// Search domain to be provided with the client configuration file.
	// Empty by default.
	DNSSearchDomain string `yaml:"dnsSearchDomain"`
	// The maximum transmission unit (MTU) to be written into the client configuration file.
	// If left empty "the MTU is automatically determined from the endpoint addresses or the system default route,
	// which is usually a sane choice." (From wg-quick 8 manual page.)
	// Empty by default.
	MTU int `yaml:"mtu"`
	// The default persistent keepalive interval for all clients.
	// If set, this value will be used as the default in the web UI.
	// Users can still override this value per device.
	// Defaults to 0 (disabled)
	PersistentKeepalive int `yaml:"PersistentKeepalive"`
}

type MetricsConfig struct {
	BasicAuth MetricsBasicAuthConfig `yaml:"basicAuth"`
	// MaxDeviceSeries caps how many devices are exported as individual
	// time series on /metrics. Device names and owners are user
	// controlled, so an uncapped export lets any user inflate the
	// cardinality of the scraping Prometheus.
	// A negative value removes the cap, 0 exports only the aggregate
	// device metrics. Defaults to 1000.
	MaxDeviceSeries int `yaml:"maxDeviceSeries"`
}

type HTTPSConfig struct {
	// Enable HTTPS for the web UI
	// Defaults to true
	Enabled bool `yaml:"enabled"`
	// Path to the TLS certificate file
	// If not provided, a self-signed certificate will be generated
	CertFile string `yaml:"certFile"`
	// Path to the TLS private key file
	// If not provided, a self-signed certificate will be generated
	KeyFile string `yaml:"keyFile"`
	// Port for HTTPS server
	// Defaults to 8443
	Port int `yaml:"port"`
	// Listen host for HTTPS server
	// Defaults to "" (all hosts)
	Host string `yaml:"host"`
}

// MetricsBasicAuthConfig is the basic auth that guards /metrics.
type MetricsBasicAuthConfig struct {
	// Username required when accessing /metrics. Empty disables auth.
	Username string `yaml:"username"`
	// Bcrypt hashed password required when accessing /metrics.
	PasswordHash string `yaml:"passwordHash"`
}
