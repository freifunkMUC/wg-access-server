# Docker

Load the `ip_tables`, `ip6_tables` and `wireguard` kernel modules on the host.

```bash
modprobe ip_tables && modprobe ip6_tables && modprobe wireguard
# Load modules on boot
echo ip_tables >> /etc/modules
echo ip6_tables >> /etc/modules
echo wireguard >> /etc/modules
```

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -p 8000:8000/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

## Modules

If you are unable to load the `iptables` kernel modules, you can add the `SYS_MODULE` capability instead: `--cap-add SYS_MODULE`. You must also add the following mount: `-v /lib/modules:/lib/modules:ro`.

This is not recommended as it essentially gives the container root privileges over the host system and an attacker could easily break out of the container.

The WireGuard module should be loaded automatically, even without `SYS_MODULE` capability or `/lib/modules` mount.
If it still fails to load, the server automatically falls back to the userspace implementation.

## IPv6-only (without IPv4)

If you don't want IPv4 inside the VPN network, set `WG_VPN_CIDR=0`.

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -e "WG_VPN_CIDR=0"
  -p 8000:8000/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

## IPv4-only (without IPv6)

If you don't want IPv6 inside the VPN network, set `WG_VPN_CIDRV6=0`.
In this case you can also get rid of the sysctls:

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -e "WG_VPN_CIDRV6=0"
  -p 8000:8000/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

## Using Docker Secrets

For enhanced security, you can use Docker secrets to store sensitive configuration values like passwords and private keys. This is particularly useful in Docker Swarm deployments or when following security best practices.

### Creating Docker Secrets

First, create the secrets:

```bash
# Create admin password secret
echo "your-secure-password" | docker secret create wg_admin_password -

# Create WireGuard private key secret
wg genkey | docker secret create wg_private_key -
```

### Using Secrets in Docker Run

When using `docker run`, you can mount secrets as files:

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -v /path/to/admin_password:/run/secrets/admin_password:ro \
  -v /path/to/wg_private_key:/run/secrets/wg_private_key:ro \
  -e "WG_ADMIN_PASSWORD_FILE=/run/secrets/admin_password" \
  -e "WG_WIREGUARD_PRIVATE_KEY_FILE=/run/secrets/wg_private_key" \
  -p 8000:8000/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

### Using Secrets in Docker Stack (Swarm)

For Docker Swarm deployments, you can reference secrets directly in your stack file. See the [docker-compose documentation](./2-docker-compose.md) for more details on using Docker secrets in stack files.

**Note:** When `WG_ADMIN_PASSWORD_FILE` or `WG_WIREGUARD_PRIVATE_KEY_FILE` are set, they take precedence over `WG_ADMIN_PASSWORD` and `WG_WIREGUARD_PRIVATE_KEY` respectively.
