# Docker Compose

You can run wg-access-server using the following example Docker Compose file.

Checkout the [configuration docs](../2-configuration.md) to learn how wg-access-server can be configured.

Please also read the [Docker instructions](1-docker.md) for general information regarding Docker deployments.

```yaml
{!../docker-compose.yml!}
```

## With traefik as Reverse proxy (with LetsEncrypt)

```yaml
version: "3.0"
services:
  wg-access-server:
    # to build the docker image from the source
    # build:
    #   dockerfile: Dockerfile
    #   context: .
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    #   - "./config.yaml:/config.yaml" # if you have a custom config file
    environment:
      - "WG_ADMIN_PASSWORD=${WG_ADMIN_PASSWORD:?\n\nplease set the WG_ADMIN_PASSWORD environment variable:\n    export WG_ADMIN_PASSWORD=example\n}"
      - "WG_WIREGUARD_PRIVATE_KEY=${WG_WIREGUARD_PRIVATE_KEY:?\n\nplease set the WG_WIREGUARD_PRIVATE_KEY environment variable:\n    export WG_WIREGUARD_PRIVATE_KEY=$(wg genkey)\n}"
      - "WG_HTTPS_ENABLED=false"
    #  - "WG_VPN_CIDRV6=0" # to disable IPv6
    expose:
      - "8000/tcp"
    ports:
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    depends_on:
      - reverse-proxy
    labels:
      - traefik.http.routers.vpn.rule=Host(`vpn.example.com`)
      - traefik.http.routers.vpn.tls=true
      - traefik.http.routers.vpn.tls.certresolver=myresolver

  reverse-proxy:
    # The official v3 Traefik docker image
    image: traefik:v3
    command: >
      --providers.docker
      --entryPoints.websecure.address=:443
      --certificatesresolvers.myresolver.acme.email=your-email@example.com
      --certificatesresolvers.myresolver.acme.storage=letsencrypt/acme.json
      --certificatesresolvers.myresolver.acme.httpchallenge.entrypoint=web
    ports:
      # The HTTPS port
      - "443:443"
    volumes:
      # So that Traefik can listen to the Docker events
      - /var/run/docker.sock:/var/run/docker.sock
      - ./letsencrypt:/letsencrypt

# shared volumes with the host
volumes:
  wg-access-server-data:
    driver: local
```

## With traefik as Reverse proxy (with traefik self generated certificate)

```yaml
version: "3.0"
services:
  wg-access-server:
    # to build the docker image from the source
    # build:
    #   dockerfile: Dockerfile
    #   context: .
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    #   - "./config.yaml:/config.yaml" # if you have a custom config file
    environment:
      - "WG_ADMIN_PASSWORD=${WG_ADMIN_PASSWORD:?\n\nplease set the WG_ADMIN_PASSWORD environment variable:\n    export WG_ADMIN_PASSWORD=example\n}"
      - "WG_WIREGUARD_PRIVATE_KEY=${WG_WIREGUARD_PRIVATE_KEY:?\n\nplease set the WG_WIREGUARD_PRIVATE_KEY environment variable:\n    export WG_WIREGUARD_PRIVATE_KEY=$(wg genkey)\n}"
      - "WG_HTTPS_ENABLED=false"
    #  - "WG_VPN_CIDRV6=0" # to disable IPv6
    expose:
      - "8000/tcp"
    ports:
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    depends_on:
      - reverse-proxy
    labels:
      - traefik.http.routers.vpn.rule=Host(`vpn.example.com`)
      - traefik.http.routers.vpn.tls=true

  reverse-proxy:
    # The official v3 Traefik docker image
    image: traefik:v3
    command: >
      --providers.docker
      --entryPoints.websecure.address=:443
    ports:
      # The HTTPS port
      - "443:443"
    volumes:
      # So that Traefik can listen to the Docker events
      - /var/run/docker.sock:/var/run/docker.sock

# shared volumes with the host
volumes:
  wg-access-server-data:
    driver: local
```

For more Traefik options, take a look here: https://doc.traefik.io/traefik/https/tls/

## IPv6-only (without IPv4)

```yaml
version: "3.0"
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      - "WG_ADMIN_PASSWORD=${WG_ADMIN_PASSWORD:?\n\nplease set the WG_ADMIN_PASSWORD environment variable:\n    export WG_ADMIN_PASSWORD=example\n}"
      - "WG_WIREGUARD_PRIVATE_KEY=${WG_WIREGUARD_PRIVATE_KEY:?\n\nplease set the WG_WIREGUARD_PRIVATE_KEY environment variable:\n    export WG_WIREGUARD_PRIVATE_KEY=$(wg genkey)\n}"
      - "WG_VPN_CIDR=0" # to disable IPv4
    ports:
      - "8000:8000/tcp"
      - "8443:8443/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"

volumes:
  wg-access-server-data:
    driver: local
```

## IPv4-only (without IPv6)

```yaml
version: "3.0"
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    volumes:
      - "wg-access-server-data:/data"
    environment:
      - "WG_ADMIN_PASSWORD=${WG_ADMIN_PASSWORD:?\n\nplease set the WG_ADMIN_PASSWORD environment variable:\n    export WG_ADMIN_PASSWORD=example\n}"
      - "WG_WIREGUARD_PRIVATE_KEY=${WG_WIREGUARD_PRIVATE_KEY:?\n\nplease set the WG_WIREGUARD_PRIVATE_KEY environment variable:\n    export WG_WIREGUARD_PRIVATE_KEY=$(wg genkey)\n}"
      - "WG_VPN_CIDRV6=0" # to disable IPv6
    ports:
      - "8000:8000/tcp"
      - "8443:8443/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"

volumes:
  wg-access-server-data:
    driver: local
```

## Using Docker Secrets

Docker Compose and Docker Swarm support Docker secrets for securely managing sensitive data. Here's how to use Docker secrets with wg-access-server:

### Docker Compose with Secrets

```yaml
version: "3.0"
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      - "WG_ADMIN_PASSWORD_FILE=/run/secrets/wg_admin_password"
      - "WG_WIREGUARD_PRIVATE_KEY_FILE=/run/secrets/wg_private_key"
    ports:
      - "8000:8000/tcp"
      - "8443:8443/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    secrets:
      - wg_admin_password
      - wg_private_key

secrets:
  wg_admin_password:
    file: ./secrets/admin_password.txt
  wg_private_key:
    file: ./secrets/wg_private_key.txt

volumes:
  wg-access-server-data:
    driver: local
```

Before running the above compose file, create the secret files:

```bash
mkdir -p secrets
echo "your-secure-password" > secrets/admin_password.txt
wg genkey > secrets/wg_private_key.txt
chmod 600 secrets/*.txt
```

### Docker Stack (Swarm Mode)

For Docker Swarm deployments, create the secrets first:

```bash
# Create secrets in Swarm
echo "your-secure-password" | docker secret create wg_admin_password -
wg genkey | docker secret create wg_private_key -
```

Then use this stack file:

```yaml
version: "3.0"
services:
  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    volumes:
      - "wg-access-server-data:/data"
    environment:
      - "WG_ADMIN_PASSWORD_FILE=/run/secrets/wg_admin_password"
      - "WG_WIREGUARD_PRIVATE_KEY_FILE=/run/secrets/wg_private_key"
    ports:
      - "8000:8000/tcp"
      - "8443:8443/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    secrets:
      - wg_admin_password
      - wg_private_key

secrets:
  wg_admin_password:
    external: true
  wg_private_key:
    external: true

volumes:
  wg-access-server-data:
    driver: local
```

Deploy the stack:

```bash
docker stack deploy -c docker-compose.yml wg-access-server
```

**Note:** When using `WG_ADMIN_PASSWORD_FILE` or `WG_WIREGUARD_PRIVATE_KEY_FILE`, they take precedence over `WG_ADMIN_PASSWORD` and `WG_WIREGUARD_PRIVATE_KEY` respectively.
