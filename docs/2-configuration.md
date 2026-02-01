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
| `WG_PORT`                            | `--port`                            | `port`                         |          | `8000`                                       | The port the web ui will listen on (http)                                                                                                                                                                                                                                     |
| `WG_HTTP_HOST`                       | `--http-host`                       | `httpHost`                     |          | `` (all hosts)                               | Hostname or IP address to bind the HTTP server to. If left empty, the HTTP server will listen on all IP addresses on all available network interfaces.                                                                                                                                |
| `WG_EXTERNAL_HOST`                   | `--external-host`                   | `externalHost`                 |          |                                              | The external domain for the server (e.g. www.mydomain.com)                                                                                                                                                                                                                    |
| `WG_STORAGE`                         | `--storage`                         | `storage`                      |          | `sqlite3:///data/db.sqlite3`                 | A storage backend connection string. See [storage docs](./3-storage.md)                                                                                                                                                                                                       |
| `WG_ENABLE_METADATA`                 | `--enable-metadata`                 | `enableMetadata`               |          | `false`                                      | Turn on collection of device metadata logging. Includes last handshake time and RX/TX bytes only.                                                                                                                                                                             |
| `WG_ENABLE_INACTIVE_DEVICE_DELETION` | `--enable-inactive-device-deletion` | `enableInactiveDeviceDeletion` |          | `false`                                      | Enable/Disable the automatic deletion of inactive devices.                                                                                                                                                                                                                    |
| `WG_INACTIVE_DEVICE_GRACE_PERIOD`    | `--inactive-device-grace-period`    | `inactiveDeviceGracePeriod`    |          | `8760h` (1 Year)                             | The duration after which inactive devices are automatically deleted, if automatic deletion is enabled. A device is inactive if it has not been connected to the server for longer than the inactive device grace period. The duration format is the go duration string format |
| `WG_FILENAME        `                | `--filename`                        | `filename`                     |          | `WireGuard`                                  | Change the name of the configuration file the user can download (Do not include the '.conf' extension )                                                                                                                                                                       |
| `WG_WIREGUARD_ENABLED`               | `--[no-]wireguard-enabled`          | `wireguard.enabled`            |          | `true`                                       | Enable/disable the wireguard server. Useful for development on non-linux machines.                                                                                                                                                                                            |
| `WG_WIREGUARD_INTERFACE`             | `--wireguard-interface`             | `wireguard.interface`          |          | `wg0`                                        | The wireguard network interface name                                                                                                                                                                                                                                          |
| `WG_WIREGUARD_PRIVATE_KEY`           | `--wireguard-private-key`           | `wireguard.privateKey`         | Yes      |                                              | The wireguard private key. This value is required and must be stable. If this value changes all devices must re-register.                                                                                                                                                     |
| `WG_WIREGUARD_PORT`                  | `--wireguard-port`                  | `wireguard.port`               |          | `51820`                                      | The wireguard server port (udp)                                                                                                                                                                                                                                               |
| `WG_WIREGUARD_MTU`                   | `--wireguard-mtu`                   | `wireguard.mtu`                |          | `1420`                                       | The maximum transmission unit (MTU) to be used on the server-side interface.                                                                                                                                                                                                  |
|                                      |                                     | `wireguard.preUp`              |          |                                              | Path to a script to run before the WireGuard interface is brought up. The script file must be owned by root:root and not writable by group or others. This option can only be set via the config file.                                                                        |
|                                      |                                     | `wireguard.postUp`             |          |                                              | Path to a script to run after the WireGuard interface is brought up and iptables rules are configured. The script file must be owned by root:root and not writable by group or others. This option can only be set via the config file.                                       |
|                                      |                                     | `wireguard.preDown`            |          |                                              | Path to a script to run before the WireGuard interface is brought down. The script file must be owned by root:root and not writable by group or others. This option can only be set via the config file.                                                                      |
|                                      |                                     | `wireguard.postDown`           |          |                                              | Path to a script to run after the WireGuard interface is brought down. The script file must be owned by root:root and not writable by group or others. This option can only be set via the config file.                                                                       |
| `WG_VPN_CIDR`                        | `--vpn-cidr`                        | `vpn.cidr`                     |          | `10.44.0.0/24`                               | The VPN IPv4 network range. VPN clients will be assigned IP addresses in this range. Set to `0` to disable IPv4.                                                                                                                                                              |
| `WG_IPV4_NAT_ENABLED`                | `--vpn-nat44-enabled`               | `vpn.nat44`                    |          | `true`                                       | Disables NAT for IPv4                                                                                                                                                                                                                                                         |
| `WG_IPV6_NAT_ENABLED`                | `--vpn-nat66-enabled`               | `vpn.nat66`                    |          | `true`                                       | Disables NAT for IPv6                                                                                                                                                                                                                                                         |
| `WG_VPN_CLIENT_ISOLATION`            | `--vpn-client-isolation`            | `vpn.clientIsolation`          |          | `false`                                      | BLock or allow traffic between client devices (client isolation)                                                                                                                                                                                                              |
| `WG_VPN_CIDRV6`                      | `--vpn-cidrv6`                      | `vpn.cidrv6`                   |          | `fd48:4c4:7aa9::/64`                         | The VPN IPv6 network range. VPN clients will be assigned IP addresses in this range. Set to `0` to disable IPv6.                                                                                                                                                              |
| `WG_VPN_GATEWAY_INTERFACE`           | `--vpn-gateway-interface`           | `vpn.gatewayInterface`         |          | _default gateway interface (e.g. eth0)_      | The VPN gateway interface. VPN client traffic will be forwarded to this interface.                                                                                                                                                                                            |
| `WG_VPN_ALLOWED_IPS`                 | `--vpn-allowed-ips`                 | `vpn.allowedIPs`               |          | `0.0.0.0/0, ::/0`                            | Allowed IPs that clients may route through this VPN. This will be set in the client's WireGuard connection file and routing is also enforced by the server using iptables.                                                                                                    |
| `WG_VPN_DISABLE_IPTABLES`            | `--vpn-disable-iptables`            | `vpn.disableIPTables`          |          | `false`                                      | Disable iptables configuration completely. When enabled, no iptables rules will be configured (no NAT, no client isolation, no forwarding rules).                                                                                                                             |
| `WG_DNS_ENABLED`                     | `--[no-]dns-enabled`                | `dns.enabled`                  |          | `true`                                       | Enable/disable the embedded DNS proxy server. This is enabled by default and allows VPN clients to avoid DNS leaks by sending all DNS requests to wg-access-server itself.                                                                                                    |
| `WG_DNS_UPSTREAM`                    | `--dns-upstream`                    | `dns.upstream`                 |          | _resolvconf autodetection or Cloudflare DNS_ | The upstream DNS servers to proxy DNS requests to. By default the host machine's resolveconf configuration is used to find its upstream DNS server, with a fallback to Cloudflare.                                                                                            |
| `WG_DNS_DOMAIN`                      | `--dns-domain`                      | `dns.domain`                   |          |                                              | A domain to serve configured devices authoritatively. Queries for names in the format <device>.<user>.<domain> will be answered with the device's IP addresses.                                                                                                               |
| `WG_CLIENTCONFIG_DNS_SERVERS`        | `--clientconfig-dns-servers`        | `clientConfig.dnsServers`      |          |                                              | DNS servers (one or more IP addresses) to write into the client configuration file. Are used instead of the servers DNS settings, if set.                                                                                                                                     |
| `WG_CLIENTCONFIG_DNS_SEARCH_DOMAIN`  | `--clientconfig-dns-search-domain`  | `clientConfig.dnsSearchDomain` |          |                                              | DNS search domain to write into the client configuration file.                                                                                                                                                                                                                |
| `WG_CLIENTCONFIG_MTU`                | `--clientconfig-mtu`                | `clientConfig.mtu`             |          |                                              | The maximum transmission unit (MTU) to write into the client configuration file. If left empty, a sensible default is used.
| `WG_CLIENTCONFIG_PERSISTENT_KEEPALIVE` | `--clientconfig-persistent-keepalive` | `clientConfig.persistentkeepalive` |          | `0`                                          | The default persistent keepalive interval for all clients (in seconds). Can be overridden per device in the web UI at creation time.                                                                                                                                                   |
| `WG_HTTPS_ENABLED`                   | `--https-enabled`                   | `https.enabled`                |          | `true`                                       | Enable HTTPS for the web UI.                                                                                                                                                                                                                                                  |
| `WG_HTTPS_CERT_FILE`                 | `--https-cert-file`                 | `https.certFile`               |          |                                              | Path to the TLS certificate file. If not provided, a self-signed certificate will be generated.                                                                                                                                                                               |
| `WG_HTTPS_KEY_FILE`                  | `--https-key-file`                  | `https.keyFile`                |          |                                              | Path to the TLS private key file. If not provided, a self-signed certificate will be generated.                                                                                                                                                                               |
| `WG_HTTPS_PORT`                      | `--https-port`                      | `https.port`                   |          | 8443                                         | Port for HTTPS server.                                                                                                                                                                                                                                                        |
| `WG_HTTPS_HOST`                      | `--https-host`                      | `https.host`                   |          | ``  (listen all hosts)                       | Hostname or IP address to bind the HTTPS server to. If left empty, the HTTPS server will listen on all IP addresses on all available network interfaces.                                                                                                                      |

## The Config File (config.yaml)

Here's an example config file to get started with.

```yaml
loglevel: info
storage: sqlite3:///data/db.sqlite3
wireguard:
  privateKey: "<some-key>"
  # Optional: scripts to run when the interface goes up/down
  # postUp: "/etc/wg-access-server/postup.sh"
  # preDown: "/etc/wg-access-server/predown.sh"
dns:
  upstream:
    - "2001:678:e68:f000::"
    - "2001:678:ed0:f000::"
    - "5.1.66.255"
    - "185.150.99.255"
```

### Pre/Post Up/Down Scripts

The `wireguard.preUp`, `wireguard.postUp`, `wireguard.preDown`, and `wireguard.postDown` configuration options allow you to run custom scripts at different stages of the WireGuard interface lifecycle.

**Use cases:**
- Adding custom routes when the interface comes up
- Setting up additional firewall rules
- Notifying external systems
- Custom logging or monitoring

**Security requirements:**
- Script files must be owned by `root:root` (UID 0, GID 0)
- Script files must not be writable by group or others
- Scripts can only be configured via the config file (not via environment variables)

**Example script** (`/etc/wg-access-server/postup.sh`):
```bash
#!/bin/bash
# Add a custom route
ip route add 192.168.100.0/24 dev wg0
```

Make sure the script is executable and has the correct ownership and permissions:
```bash
chown root:root /etc/wg-access-server/postup.sh
chmod 755 /etc/wg-access-server/postup.sh
```
