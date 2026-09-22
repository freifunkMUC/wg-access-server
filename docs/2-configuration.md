# Configuration

You can configure wg-access-server using environment variables, cli flags or a config file
taking precedence over one another in that order.

The default configuration should work out of the box if you're just looking to try it out.

The only required configuration is a wireguard private key.
You can generate a wireguard private key by [following the official docs](https://www.wireguard.com/quickstart/#key-generation).

TLDR:

```bash
wg genkey
```

The config file format is `yaml` and an example is provided [below](#the-config-file-configyaml).

The format for specifying multiple values for options that allow it is:

- as commandline flags:
  - repeat the flag (e.g. `--dns-upstream 2001:db8::1 --dns-upstream 192.0.2.1`)
  - separate the values with a comma (e.g. `--dns-upstream 2001:db8::1,192.0.2.1`)
- as environment variables:
  - separate with a comma (e.g. `WG_DNS_UPSTREAM="2001:db8::1,192.0.2.1"`)
  - separate with a new line char (e.g. `WG_DNS_UPSTREAM=$'2001:db8::1\n192.0.2.1'`)
- in the config file as YAML list.

Here's what you can configure:

| Environment Variable                 | CLI Flag                            | Config File Path               | Required | Default (docker)                             | Description                                                                                                                                                                                                                                                                   |
| ------------------------------------ | ----------------------------------- | ------------------------------ | -------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WG_CONFIG`                          | `--config`                          |                                |          |                                              | The path to a wg-access-server config.yaml file                                                                                                                                                                                                                               |
| `WG_LOG_LEVEL`                       | `--log-level`                       | `loglevel`                     |          | `info`                                       | The global log level                                                                                                                                                                                                                                                          |
| `WG_ADMIN_USERNAME`                  | `--admin-username`                  | `adminUsername`                |          | `admin`                                      | The admin account username                                                                                                                                                                                                                                                    |
| `WG_ADMIN_PASSWORD`                  | `--admin-password`                  | `adminPassword`                | Yes      |                                              | The admin account password                                                                                                                                                                                                                                                    |
| `WG_ADMIN_PASSWORD_FILE`             | `--admin-password-file`             |                                |          |                                              | Read the admin password from a file, e.g. a Docker secret mounted at `/run/secrets/...`. Trailing line breaks are removed. Exclusive with `WG_ADMIN_PASSWORD` / `adminPassword`: setting both stops the server.                                                               |
| `WG_PORT`                            | `--port`                            | `port`                         |          | `8000`                                       | The port the web ui will listen on (http)                                                                                                                                                                                                                                     |
| `WG_HTTP_HOST`                       | `--http-host`                       | `httpHost`                     |          | `` (all hosts)                               | Hostname or IP address to bind the HTTP server to. If left empty, the HTTP server will listen on all IP addresses on all available network interfaces.                                                                                                                                |
| `WG_HTTP_ENABLED`                    | `--[no-]http-enabled`               | `httpEnabled`                  |          | `true`                                       | Serve the web UI over plain HTTP on `port` as well. Disable it (`--no-http-enabled`) to serve the UI over HTTPS only: the UI hands out client configurations including private keys, which travel unencrypted over HTTP unless something in front of the server terminates TLS. Disabling both this and `https.enabled` is refused at startup.                                          |
| `WG_EXTERNAL_HOST`                   | `--external-host`                   | `externalHost`                 |          |                                              | The external domain for the server (e.g. www.mydomain.com)                                                                                                                                                                                                                    |
| `WG_STORAGE`                         | `--storage`                         | `storage`                      |          | `sqlite3:///data/db.sqlite3`                 | A storage backend connection string. See [storage docs](./3-storage.md)                                                                                                                                                                                                       |
| `WG_ENABLE_METADATA`                 | `--enable-metadata`                 | `enableMetadata`               |          | `true`                                       | Turn on collection of device metadata logging. Includes last handshake time and RX/TX bytes only.                                                                                                                                                                             |
| `WG_ENABLE_DEVICE_METRICS`           | `--enable-device-metrics`           | `enableDeviceMetrics`          |          | `false`                                      | Expose device-level Prometheus metrics on `/metrics`. Requires `enableMetadata` to provide data.                                                                                                                                                                              |
| `WG_METRICS_BASIC_AUTH_USERNAME`     | `--metrics-basic-auth-username`     | `metrics.basicAuth.username`   |          |                                              | Username required when accessing `/metrics`. Leave empty to keep the endpoint unauthenticated.                                                                                                                                                                                |
| `WG_METRICS_BASIC_AUTH_PASSWORD_HASH` | `--metrics-basic-auth-password-hash` | `metrics.basicAuth.passwordHash` |          |                                              | Bcrypt hash of the password required for `/metrics`. Use together with the username to protect the endpoint.                                                                                                                                                                 |
| `WG_METRICS_MAX_DEVICE_SERIES`       | `--metrics-max-device-series`       | `metrics.maxDeviceSeries`      |          | `1000`                                       | Maximum number of devices exported as individual `{device,owner}` series on `/metrics`. Device names and owners are user controlled, so this caps the cardinality an individual user can cause. Set to `0` to export only aggregate device metrics, or to a negative value for no limit. Dropped devices are counted in `wg_access_server_device_metrics_series_dropped`.                                       |
| `WG_ENABLE_INACTIVE_DEVICE_DELETION` | `--enable-inactive-device-deletion` | `enableInactiveDeviceDeletion` |          | `false`                                      | Enable/Disable the automatic deletion of inactive devices.                                                                                                                                                                                                                    |
| `WG_INACTIVE_DEVICE_GRACE_PERIOD`    | `--inactive-device-grace-period`    | `inactiveDeviceGracePeriod`    |          | `8760h` (1 Year)                             | The duration after which inactive devices are automatically deleted, if automatic deletion is enabled. A device is inactive if it has not been connected to the server for longer than the inactive device grace period. The duration format is the go duration string format |
| `WG_MAX_DEVICES_PER_USER`            | `--max-devices-per-user`            | `maxDevicesPerUser`            |          | `0` (no limit)                               | Maximum number of devices a single user may create. Admins are not exempt: the limit is about the addresses in the VPN subnet, not about trust. Deleting a device frees its slot again.                                                                                                  |
| `WG_ENABLE_API_TOKENS`               | `--enable-api-tokens`               | `enableApiTokens`              |          | `false`                                      | Let users create tokens for using the API from scripts, see [API tokens](./4-auth.md#api-tokens). A token keeps working until it expires or is revoked, independent of the web session it was created in. |
| `WG_FILENAME        `                | `--filename`                        | `filename`                     |          | `WireGuard`                                  | Change the name of the configuration file the user can download (Do not include the '.conf' extension )                                                                                                                                                                       |
| `WG_WIREGUARD_ENABLED`               | `--[no-]wireguard-enabled`          | `wireguard.enabled`            |          | `true`                                       | Enable/disable the wireguard server. Useful for development on non-linux machines.                                                                                                                                                                                            |
| `WG_WIREGUARD_INTERFACE`             | `--wireguard-interface`             | `wireguard.interface`          |          | `wg0`                                        | The wireguard network interface name                                                                                                                                                                                                                                          |
| `WG_WIREGUARD_PRIVATE_KEY`           | `--wireguard-private-key`           | `wireguard.privateKey`         | Yes      |                                              | The wireguard private key. This value is required and must be stable. If this value changes all devices must re-register.                                                                                                                                                     |
| `WG_WIREGUARD_PRIVATE_KEY_FILE`      | `--wireguard-private-key-file`      |                                |          |                                              | Read the wireguard private key from a file, e.g. a Docker secret. Trailing line breaks are removed. Exclusive with `WG_WIREGUARD_PRIVATE_KEY` / `wireguard.privateKey`. An empty file is an error rather than a reason to generate a new key.                                 |
| `WG_WIREGUARD_PORT`                  | `--wireguard-port`                  | `wireguard.port`               |          | `51820`                                      | The wireguard server port (udp)                                                                                                                                                                                                                                               |
| `WG_WIREGUARD_MTU`                   | `--wireguard-mtu`                   | `wireguard.mtu`                |          | `1420`                                       | The maximum transmission unit (MTU) to be used on the server-side interface.                                                                                                                                                                                                  |
|                                      |                                     | `wireguard.preUp`              |          |                                              | Shell commands run before the WireGuard interface is created. See [Lifecycle commands](#lifecycle-commands). Config file only.                                                                                                                                                |
|                                      |                                     | `wireguard.postUp`             |          |                                              | Shell commands run after the interface is up and the firewall rules are in place. Config file only.                                                                                                                                                                          |
|                                      |                                     | `wireguard.preDown`            |          |                                              | Shell commands run on shutdown while the interface still exists. Config file only.                                                                                                                                                                                           |
|                                      |                                     | `wireguard.postDown`           |          |                                              | Shell commands run on shutdown after the interface is gone. Config file only.                                                                                                                                                                                                |
| `WG_VPN_CIDR`                        | `--vpn-cidr`                        | `vpn.cidr`                     |          | `10.44.0.0/24`                               | The VPN IPv4 network range. VPN clients will be assigned IP addresses in this range. Set to `0` to disable IPv4.                                                                                                                                                              |
| `WG_IPV4_NAT_ENABLED`                | `--vpn-nat44-enabled`               | `vpn.nat44`                    |          | `true`                                       | Disables NAT for IPv4                                                                                                                                                                                                                                                         |
| `WG_IPV6_NAT_ENABLED`                | `--vpn-nat66-enabled`               | `vpn.nat66`                    |          | `true`                                       | Disables NAT for IPv6                                                                                                                                                                                                                                                         |
| `WG_VPN_CLIENT_ISOLATION`            | `--vpn-client-isolation`            | `vpn.clientIsolation`          |          | `false`                                      | BLock or allow traffic between client devices (client isolation)                                                                                                                                                                                                              |
| `WG_VPN_CIDRV6`                      | `--vpn-cidrv6`                      | `vpn.cidrv6`                   |          | `fd48:4c4:7aa9::/64`                         | The VPN IPv6 network range. VPN clients will be assigned IP addresses in this range. Set to `0` to disable IPv6.                                                                                                                                                              |
| `WG_VPN_GATEWAY_INTERFACE`           | `--vpn-gateway-interface`           | `vpn.gatewayInterface`         |          | _default gateway interface (e.g. eth0)_      | The VPN gateway interface. VPN client traffic will be forwarded to this interface.                                                                                                                                                                                            |
| `WG_VPN_ALLOWED_IPS`                 | `--vpn-allowed-ips`                 | `vpn.allowedIPs`               |          | `0.0.0.0/0, ::/0`                            | Allowed IPs that clients may route through this VPN. This will be set in the client's WireGuard connection file and routing is also enforced by the server using iptables.                                                                                                    |
| `WG_VPN_FIREWALL`                    | `--vpn-firewall`                    | `vpn.firewall`                 |          | `iptables`                                   | How the forwarding rules are set up: `iptables`, `nftables` or `none`. See [Firewall](#firewall).                                                                                                                                                                             |
| `WG_VPN_DISABLE_IPTABLES`            | `--vpn-disable-iptables`            | `vpn.disableIPTables`          |          | `false`                                      | Deprecated: the same as `vpn.firewall: none`.                                                                                                                                                                                                                                 |
| `WG_DNS_ENABLED`                     | `--[no-]dns-enabled`                | `dns.enabled`                  |          | `true`                                       | Enable/disable the embedded DNS proxy server. This is enabled by default and allows VPN clients to avoid DNS leaks by sending all DNS requests to wg-access-server itself.                                                                                                    |
| `WG_DNS_UPSTREAM`                    | `--dns-upstream`                    | `dns.upstream`                 |          | _resolvconf autodetection or Cloudflare DNS_ | The upstream DNS servers to proxy DNS requests to. An address may name a port (e.g. `192.0.2.1:5353` or `[2001:db8::1]:5353`), otherwise port 53 is used. The first upstream is preferred; one that fails is skipped for 30 seconds so a dead resolver does not slow down every query. By default the host machine's resolveconf configuration is used to find its upstream DNS server, with a fallback to Cloudflare.                                                                                            |
| `WG_DNS_CACHE_SIZE`                  | `--dns-cache-size`                  | `dns.cacheSize`                |          | `10000`                                      | How many DNS responses the embedded DNS proxy keeps in its cache. The cache is filled by what the clients query, so it is bounded and drops the least recently used entries once it is full. Set to `0` to disable caching.                                                                    |
| `WG_DNS_DOMAIN`                      | `--dns-domain`                      | `dns.domain`                   |          |                                              | A domain to serve configured devices authoritatively. Queries for names in the format <device>.<user>.<domain> will be answered with the device's IP addresses.                                                                                                               |
| `WG_CLIENTCONFIG_DNS_SERVERS`        | `--clientconfig-dns-servers`        | `clientConfig.dnsServers`      |          |                                              | DNS servers (one or more IP addresses) to write into the client configuration file. Are used instead of the servers DNS settings, if set.                                                                                                                                     |
| `WG_CLIENTCONFIG_DNS_SEARCH_DOMAIN`  | `--clientconfig-dns-search-domain`  | `clientConfig.dnsSearchDomain` |          |                                              | DNS search domain to write into the client configuration file.                                                                                                                                                                                                                |
| `WG_CLIENTCONFIG_MTU`                | `--clientconfig-mtu`                | `clientConfig.mtu`             |          |                                              | The maximum transmission unit (MTU) to write into the client configuration file. If left empty, a sensible default is used.
| `WG_CLIENTCONFIG_PERSISTENT_KEEPALIVE` | `--clientconfig-persistent-keepalive` | `clientConfig.PersistentKeepalive` |          | `0`                                          | The default persistent keepalive interval for all clients (in seconds). Can be overridden per device in the web UI at creation time.                                                                                                                                                   |
| `WG_HTTPS_ENABLED`                   | `--https-enabled`                   | `https.enabled`                |          | `true`                                       | Enable HTTPS for the web UI.                                                                                                                                                                                                                                                  |
| `WG_HTTPS_CERT_FILE`                 | `--https-cert-file`                 | `https.certFile`               |          | `/data/wg-access-server.crt`                 | Path to the TLS certificate file. If the file does not exist, a self-signed certificate is generated for `localhost`, every address configured on the machine (LAN and VPN address) and `externalHost`. The docker image points this into the `/data` volume so the certificate survives a recreated container.                                                                                                                                                                               |
| `WG_HTTPS_KEY_FILE`                  | `--https-key-file`                  | `https.keyFile`                |          | `/data/wg-access-server.key`                 | Path to the TLS private key file. If the file does not exist, it is generated together with the self-signed certificate.                                                                                                                                                                               |
| `WG_HTTPS_PORT`                      | `--https-port`                      | `https.port`                   |          | 8443                                         | Port for HTTPS server.                                                                                                                                                                                                                                                        |
| `WG_HTTPS_HOST`                      | `--https-host`                      | `https.host`                   |          | ``  (listen all hosts)                       | Hostname or IP address to bind the HTTPS server to. If left empty, the HTTPS server will listen on all IP addresses on all available network interfaces.                                                                                                                      |

## Firewall

wg-access-server sets up the rules that forward the clients' traffic to the networks in
`vpn.allowedIPs` and reject everything else they send, isolate the clients from each other with
`vpn.clientIsolation`, and masquerade their traffic on the gateway interface (`vpn.nat44`,
`vpn.nat66`). `vpn.firewall` decides how:

- **`iptables`** (default) - chains of its own, `WG_ACCESS_SERVER_FORWARD` and
  `WG_ACCESS_SERVER_POSTROUTING`, for IPv4 and IPv6.
- **`nftables`** - one table of its own, `inet wg_access_server`, for IPv4 and IPv6. It is replaced
  as a whole on every start, in a single transaction, and uses native nftables only. Choose it on
  hosts that manage their firewall with `nft`, or whose kernel lacks the iptables compatibility
  modules: the iptables in the Docker image writes to nftables, too, but needs those modules for
  `REJECT` and `MASQUERADE`. Outside of Docker, it needs the `nft` command.
- **`none`** - wg-access-server does not touch the firewall, for setups that manage it themselves.

Both backends set up the same rules. Switching between `iptables` and `nftables` removes the rules
of the other one, so no old reject keeps applying next to the new rules. `none` leaves any rules of
an earlier start in place.

Accepting a packet only ends the chain it is in. Another firewall on the host - firewalld, ufw,
Docker's own rules - can still drop what wg-access-server accepts, with either backend. If clients
can connect but reach nothing, look there.

## Lifecycle commands

`wireguard.preUp`, `postUp`, `preDown` and `postDown` run shell commands around the lifecycle of the
WireGuard interface, like the options of the same name in a `wg-quick` configuration. The typical use
is a route that wg-access-server does not set up itself:

```yaml
wireguard:
  postUp:
    - "ip route add 192.168.178.0/24 dev %i"
  preDown:
    - "ip route del 192.168.178.0/24 dev %i"
```

- `%i` is replaced with the interface name, which is also passed to the command as `$WG_INTERFACE`.
- The commands of a phase run in order, through `sh -c`. A failing `preUp` or `postUp` command stops
  the server: a network that is only half set up is not what you asked for. A failing `preDown` or
  `postDown` command is logged, the shutdown continues.
- `preUp` runs before the interface is created, `postUp` after the firewall rules are in place,
  `preDown` while the interface still exists and `postDown` once it is gone.
- Nothing runs when the embedded WireGuard server is disabled - there is no interface then.

These commands run as the user the server runs as, which is root in most deployments. They can
therefore **only be set in the config file**, never through a flag or an environment variable, and
wg-access-server refuses to run them - and refuses to start - unless the config file is writable by
its owner alone and owned either by root or by the user running the server.

## The Config File (config.yaml)

Here's an example config file to get started with.

```yaml
loglevel: info
storage: sqlite3:///data/db.sqlite3
wireguard:
  privateKey: "<some-key>"
dns:
  upstream:
    - "2001:678:e68:f000::"
    - "2001:678:ed0:f000::"
    - "5.1.66.255"
    - "185.150.99.255"
```
