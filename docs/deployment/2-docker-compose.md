# Docker Compose

You can run wg-access-server using the following example Docker Compose file.

Checkout the [configuration docs](../2-configuration.md) to learn how wg-access-server can be configured.

Please also read the [Docker instructions](1-docker.md) for general information regarding Docker deployments.

```yaml
{!../docker-compose.yml!}
```

Set the two variables and start it:

```sh
export WG_ADMIN_PASSWORD="<a password for the admin account>"
export WG_WIREGUARD_PRIVATE_KEY="$(wg genkey)"
docker compose up -d
```

Keep the private key: the device configurations handed out so far only work with it. Put the
variables into an `.env` file next to `docker-compose.yml` to have them at the next start - or use
[Docker secrets](#with-docker-secrets).

The web UI is at `https://<your-server>:8443`, with a self-signed certificate. Plain HTTP on port
8000 is only reachable from the machine itself: it would carry passwords unencrypted.

## Behind Traefik, with a Let's Encrypt certificate

Traefik terminates TLS, so wg-access-server serves plain HTTP to it. Port 80 is needed for Let's
Encrypt's challenge and redirects everything else to HTTPS.

```yaml
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      WG_ADMIN_PASSWORD: "${WG_ADMIN_PASSWORD:?set WG_ADMIN_PASSWORD, the password of the admin account}"
      WG_WIREGUARD_PRIVATE_KEY: "${WG_WIREGUARD_PRIVATE_KEY:?set WG_WIREGUARD_PRIVATE_KEY, e.g. to the output of wg genkey}"
      WG_HTTPS_ENABLED: "false" # Traefik terminates TLS
    ports:
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.vpn.rule=Host(`vpn.example.com`)"
      - "traefik.http.routers.vpn.entrypoints=websecure"
      - "traefik.http.routers.vpn.tls.certresolver=letsencrypt"
      - "traefik.http.services.vpn.loadbalancer.server.port=8000"

  traefik:
    image: traefik:v3
    container_name: traefik
    restart: unless-stopped
    command:
      # only containers labelled traefik.enable=true are published
      - "--providers.docker.exposedByDefault=false"
      - "--entryPoints.web.address=:80"
      - "--entryPoints.web.http.redirections.entryPoint.to=websecure"
      - "--entryPoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=you@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"

volumes:
  wg-access-server-data:
```

Replace `vpn.example.com` and the email address with yours; the name must point to the server.

## Behind Traefik, with a self-signed certificate

The same without Let's Encrypt, for a test or a network where the certificate is not needed:

```yaml
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      WG_ADMIN_PASSWORD: "${WG_ADMIN_PASSWORD:?set WG_ADMIN_PASSWORD, the password of the admin account}"
      WG_WIREGUARD_PRIVATE_KEY: "${WG_WIREGUARD_PRIVATE_KEY:?set WG_WIREGUARD_PRIVATE_KEY, e.g. to the output of wg genkey}"
      WG_HTTPS_ENABLED: "false" # Traefik terminates TLS
    ports:
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.vpn.rule=Host(`vpn.example.com`)"
      - "traefik.http.routers.vpn.entrypoints=websecure"
      - "traefik.http.routers.vpn.tls=true"
      - "traefik.http.services.vpn.loadbalancer.server.port=8000"

  traefik:
    image: traefik:v3
    container_name: traefik
    restart: unless-stopped
    command:
      - "--providers.docker.exposedByDefault=false"
      - "--entryPoints.websecure.address=:443"
    ports:
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"

volumes:
  wg-access-server-data:
```

For more Traefik options, see <https://doc.traefik.io/traefik/https/tls/>.

## IPv6-only (without IPv4)

In the first example, set `WG_VPN_CIDR` to `0`:

```yaml
    environment:
      WG_ADMIN_PASSWORD: "${WG_ADMIN_PASSWORD:?set WG_ADMIN_PASSWORD, the password of the admin account}"
      WG_WIREGUARD_PRIVATE_KEY: "${WG_WIREGUARD_PRIVATE_KEY:?set WG_WIREGUARD_PRIVATE_KEY, e.g. to the output of wg genkey}"
      WG_VPN_CIDR: "0" # no IPv4
```

## IPv4-only (without IPv6)

In the first example, set `WG_VPN_CIDRV6` to `0`. The two `sysctls` for IPv6 are then not needed:

```yaml
    environment:
      WG_ADMIN_PASSWORD: "${WG_ADMIN_PASSWORD:?set WG_ADMIN_PASSWORD, the password of the admin account}"
      WG_WIREGUARD_PRIVATE_KEY: "${WG_WIREGUARD_PRIVATE_KEY:?set WG_WIREGUARD_PRIVATE_KEY, e.g. to the output of wg genkey}"
      WG_VPN_CIDRV6: "0" # no IPv6
```

## With Docker secrets

Instead of passing the admin password and the WireGuard private key as environment
variables, you can mount them as [Docker secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
and point wg-access-server at the files. Environment variables are visible in
`docker inspect` and to every process in the container; secret files are not.

Create the two files first. `wg genkey` writes a trailing newline, which
wg-access-server strips when it reads the file:

```bash
mkdir -p secrets
wg genkey > secrets/wg_private_key
printf '%s' 'example' > secrets/wg_admin_password
chmod 600 secrets/*
```

Then reference them through the `_FILE` variables:

```yaml
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      WG_ADMIN_PASSWORD_FILE: "/run/secrets/wg_admin_password"
      WG_WIREGUARD_PRIVATE_KEY_FILE: "/run/secrets/wg_private_key"
    secrets:
      - wg_admin_password
      - wg_private_key
    ports:
      - "8443:8443/tcp"
      - "127.0.0.1:8000:8000/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"

secrets:
  wg_admin_password:
    file: ./secrets/wg_admin_password
  wg_private_key:
    file: ./secrets/wg_private_key

volumes:
  wg-access-server-data:
```

A `_FILE` variable and its direct counterpart are exclusive: if both
`WG_ADMIN_PASSWORD` and `WG_ADMIN_PASSWORD_FILE` are set - including `adminPassword`
in a config file - the server refuses to start instead of guessing which one you meant.
