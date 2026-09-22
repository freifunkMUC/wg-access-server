# Raspberry Pi with Pi-hole

This runs wg-access-server next to [Pi-hole](https://pi-hole.net/) with Docker Compose, so that
devices connected to the VPN get Pi-hole's ad and tracker blocking wherever they are. It works the
same on any other Docker host; both images are published for the Raspberry Pi (`arm64` and `arm/v7`).

The VPN clients use wg-access-server's DNS server (`10.44.0.1`, the default), which forwards their
queries to Pi-hole. Pi-hole itself is only reachable from inside Docker - it does not have to answer
anybody else, and port 53 of the host stays free.

## Prerequisites

- Docker with the Compose plugin
- The WireGuard kernel module. Raspberry Pi OS Bookworm and newer ship it; check with
  `sudo modprobe wireguard`. See [Docker](1-docker.md#modules) for loading it on boot.
- UDP port 51820 forwarded to the Raspberry Pi if clients connect from outside your network

## docker-compose.yml

```yaml
services:
  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    environment:
      TZ: "Europe/Berlin"
      FTLCONF_webserver_api_password: "${PIHOLE_PASSWORD:?please set PIHOLE_PASSWORD}"
    volumes:
      - "pihole-data:/etc/pihole"
    ports:
      - "8080:80/tcp" # Pi-hole's web interface
    networks:
      dns:
        ipv4_address: 172.30.0.53
    restart: unless-stopped

  wg-access-server:
    image: ghcr.io/freifunkmuc/wg-access-server:latest
    container_name: wg-access-server
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv6.conf.all.disable_ipv6: 0
      net.ipv6.conf.all.forwarding: 1
    environment:
      WG_ADMIN_PASSWORD: "${WG_ADMIN_PASSWORD:?please set WG_ADMIN_PASSWORD}"
      WG_WIREGUARD_PRIVATE_KEY: "${WG_WIREGUARD_PRIVATE_KEY:?please set WG_WIREGUARD_PRIVATE_KEY}"
      # the VPN clients' DNS server forwards to Pi-hole
      WG_DNS_UPSTREAM: "172.30.0.53"
    volumes:
      - "wg-access-server-data:/data"
    ports:
      - "8000:8000/tcp"
      - "51820:51820/udp"
    devices:
      - "/dev/net/tun:/dev/net/tun"
    networks:
      - dns
    depends_on:
      - pihole
    restart: unless-stopped

networks:
  dns:
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  pihole-data:
  wg-access-server-data:
```

Pi-hole gets a fixed address in a network of its own, so wg-access-server can name it as its
upstream. Both containers are in that network, so Pi-hole's default of only answering its local
network is all that is needed.

## Start it

```sh
export PIHOLE_PASSWORD="<a password for Pi-hole's web interface>"
export WG_ADMIN_PASSWORD="<a password for wg-access-server>"
export WG_WIREGUARD_PRIVATE_KEY="$(wg genkey)"
docker compose up -d
```

Keep the private key: the device configurations handed out so far only work with it. Put the
variables into an `.env` file next to `docker-compose.yml` to have them at the next start.

Then add a device in wg-access-server at `http://<raspberry-pi>:8000` and connect. Pi-hole's web
interface at `http://<raspberry-pi>:8080/admin` shows the queries of the VPN clients - all coming
from wg-access-server's address, because it forwards them.

## Check that it works

From a connected device, look up a domain that Pi-hole blocks:

```sh
nslookup doubleclick.net 10.44.0.1
```

The answer is `0.0.0.0` when the query went through Pi-hole. On the first start Pi-hole needs a
minute or so to download its block lists; until then it answers everything.
