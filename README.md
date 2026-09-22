# wg-access-server

wg-access-server is a single binary file that contains a WireGuard
VPN server and a web user interface for device management. We support user authentication,
_1-click_ device enrollment that works with macOS, Linux, Windows, iOS/iPadOS and Android
including QR codes. Furthermore, you can choose from different network isolation modes for a
better control over connected devices. Generally speaking you can customize the project
to your use-case with relative ease.

This project aims to provide a simple VPN solution for developers,
homelab enthusiasts, and anyone else who is adventurous.

**This is a fork of the original work of place1, maintained by [Freifunk Munich](https://ffmuc.net/).
Since the upstream is currently unmaintained, we try to add new features and keep the project up to date and in a working state.**

**Contributions are always welcome so that we can offer new bug fixes, features and improvements to the users of this project**.

## Features

- Sign-in with OpenID Connect, GitLab, GitHub or a list of users of your own ([auth](https://www.freie-netze.org/wg-access-server/4-auth/))
- [API tokens](https://www.freie-netze.org/wg-access-server/4-auth/#api-tokens) for scripts, using the same API as the web UI
- Devices can be renamed; admins see and manage the devices of all users
- An optional limit on how many devices a user may create
- WireGuard client configurations as a file or a QR code
- IPv6: dual-stack, IPv6-only or IPv4-only, with NAT on or off for each
- Client isolation and a choice of the networks clients may reach
- Firewall rules with iptables or nftables ([firewall](https://www.freie-netze.org/wg-access-server/2-configuration/#firewall))
- A caching DNS proxy for the clients, with names for their devices
- PostgreSQL, MySQL or SQLite storage; several replicas can share PostgreSQL or MySQL
- An [audit log](https://www.freie-netze.org/wg-access-server/5-audit/) and Prometheus [metrics](#metrics)
- Commands to run when the WireGuard interface comes up or goes down
- The WireGuard kernel module where available, with an embedded userspace implementation as fallback
- Dark and light mode

## Documentation

[See our documentation website](https://www.freie-netze.org/wg-access-server/)

Quick Links:

- [Configuration overview](https://www.freie-netze.org/wg-access-server/2-configuration/)
- [Deploy with Docker](https://www.freie-netze.org/wg-access-server/deployment/1-docker/)
- [Deploy with Docker Compose](https://www.freie-netze.org/wg-access-server/deployment/2-docker-compose/)
- [Deploy with Helm](https://www.freie-netze.org/wg-access-server/deployment/3-kubernetes/)
- [Raspberry Pi with Pi-hole](https://www.freie-netze.org/wg-access-server/deployment/4-raspberry-pi-pi-hole/)

## Running with Docker

Here is a quick command to start the wg-access-server for the first time and try it out.

```bash
export WG_ADMIN_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
export WG_WIREGUARD_PRIVATE_KEY="$(wg genkey)"
echo "Your automatically generated admin password for the wg-access-server's web interface: $WG_ADMIN_PASSWORD"

docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -v /lib/modules:/lib/modules:ro \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -p 8443:8443/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

**Note:** This command includes the `SYS_MODULE` capability which essentially gives the container root privileges over the host system and an attacker could easily break out of the container. See the [Docker instructions](https://www.freie-netze.org/wg-access-server/deployment/1-docker/) for the recommended way to run the container.

The web UI is at https://localhost:8443 on the machine itself, and at `https://<its address>:8443`
from others in your network - for example from your phone, to add it with the QR code. The
certificate is self-signed, so the browser warns once.

## Running with Docker Compose

Please also read the [Docker instructions](https://www.freie-netze.org/wg-access-server/deployment/1-docker/) for general information regarding Docker deployments.

Download the docker-compose.yml file from the repo and run the following commands.

```bash
export WG_ADMIN_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
export WG_WIREGUARD_PRIVATE_KEY="$(wg genkey)"
echo "Your automatically generated admin password for the wg-access-server's web interface: $WG_ADMIN_PASSWORD"

docker compose up -d
```

You can connect to the web server on the local machine browser at https://localhost:8443

If you open your browser to your machine's LAN IP address you'll be able
to connect your phone using the UI and QR code!

## Running on Kubernetes via Helm

The Helm chart included in this repository has been removed due to lack of expertise on our side and nobody answering
our call for aid.  
If you are a Kubernetes/Helm user, please consider stepping up and taking over maintenance of the chart at
https://github.com/freifunkMUC/wg-access-server-chart.

## Screenshots

![Devices](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/devices.png)

![Devices Darkmode](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/devices-dark.png)

![Connect Mobile](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/connect-mobile.png)

![Connect Mobile Darkmode](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/connect-mobile-dark.png)

![Connect Desktop](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/connect-desktop.png)

![Connect Desktop Darkmode](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/connect-desktop-dark.png)

![Sign In](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/signin.png)

![Sign In Darkmode](https://github.com/freifunkMUC/wg-access-server/raw/master/screenshots/signin-dark.png)

## Metrics

Prometheus metrics are served at `/metrics`, on the same ports as the web UI. **The endpoint needs no
sign-in unless you set up basic auth for it**, and it shows the exact version of wg-access-server and
of Go it was built with - which tells anybody whether an installation is out of date. Protect it with
`metrics.basicAuth` (below) or keep it out of reach of the internet, e.g. in your reverse proxy.

- Endpoint: `/metrics` on the HTTP/HTTPS server.
- Exposed metrics include:
  - `wg_access_server_build_info{version,commit}`: build metadata (value 1)
  - `wg_access_server_up`: 1 if storage and WireGuard are reachable
  - `wg_access_server_devices_total`: total devices in storage
  - `wg_access_server_devices_connected`: devices with a recent handshake
  - `wg_access_server_devices_bytes_received_total`: sum of received bytes across devices
  - `wg_access_server_devices_bytes_transmitted_total`: sum of transmitted bytes across devices
  - `wg_access_server_device_connected{device,owner}`, `wg_access_server_device_bytes_received_total{device,owner}`, `wg_access_server_device_bytes_transmitted_total{device,owner}`, `wg_access_server_device_last_handshake_timestamp_seconds{device,owner}`: the same, per device
  - `wg_access_server_device_metrics_scrape_error`: 1 if the last scrape could not read devices from storage
  - `wg_access_server_device_metrics_series_dropped`: devices left out of the per-device metrics in the last scrape

`EnableMetadata` is on by default so the UI always shows last handshake/bytes, while `EnableDeviceMetrics` defaults to `false` so Prometheus doesn't see device-level data unless you opt in. When both flags are enabled, device-specific metrics are exported. Set `metrics.basicAuth.username` and `metrics.basicAuth.passwordHash` (bcrypt) to protect the `/metrics` endpoint with HTTP Basic Auth.

The per-device metrics carry user controlled label values: the device name as users typed it and the owner's identity from your auth provider. Two things follow from that.

- **They expose who uses the VPN and when.** Enable them only where that is acceptable, and protect `/metrics` with basic auth (or a network policy) — the endpoint is unauthenticated otherwise.
- **Every device adds four time series.** Unless `maxDevicesPerUser` is set, nothing limits how many devices a user may create, so `metrics.maxDeviceSeries` caps how many devices get their own labels; it defaults to `1000`. Beyond the cap devices are dropped in a stable order and counted in `wg_access_server_device_metrics_series_dropped`, while the aggregate metrics stay complete. Set it to `0` to export only the aggregates, or to a negative value to remove the cap. Names longer than 128 bytes are truncated, and devices whose labels collide after truncation are dropped rather than failing the scrape.

## Security

Please do not report security problems in public issues. Report them privately through
[GitHub's vulnerability reporting](https://github.com/freifunkMUC/wg-access-server/security/advisories/new),
so that a fix can be released before the problem is known.

## Changelog

See the [Releases section](https://github.com/freifunkMUC/wg-access-server/releases)

## Development

The software consists of a Go server and a React app.

To work on it locally:

1. Start the web UI's development server: `cd website && npm install && npm start` (Vite, on `:3000`).
2. Start the server: `go run . serve --admin-password dev --no-wireguard-enabled` (on `:8000` and `:8443`).
3. Open http://localhost:8000 and sign in as `admin` with the password `dev`.

Some notes on this setup:

- Without a built web UI in `website/build`, the server passes the UI through from Vite, so changes
  show up right away. After `npm run build` it serves the build instead.
- The server keeps its data in memory and generates a WireGuard key; both are gone after a restart.
- `--no-wireguard-enabled` leaves out the VPN itself, which needs root to set up the interface and the
  firewall. To work on that, run the server with `sudo` and without the flag.

### Running the tests:

```sh
go test ./...
cd website && npm test
```

The storage tests for Postgres and MySQL need a real server and skip themselves without one. To run
them locally, start the databases and point the tests at them - this is what the `test-databases` CI
job does:

```sh
docker run -d --name wgas-pg -e POSTGRES_USER=wgtest -e POSTGRES_PASSWORD=wgtest -e POSTGRES_DB=wgtest -p 5432:5432 postgres:17-alpine
docker run -d --name wgas-mysql -e MYSQL_ROOT_PASSWORD=wgtest -e MYSQL_DATABASE=wgtest -e MYSQL_USER=wgtest -e MYSQL_PASSWORD=wgtest -p 3306:3306 mysql:9

export WG_TEST_POSTGRES_URI="postgresql://wgtest:wgtest@localhost:5432/wgtest?sslmode=disable"
export WG_TEST_MYSQL_URI="mysql://root:wgtest@localhost:3306/wgtest"
go test -race ./...
```

They cover what only a real server shows: the allocation lock that keeps two replicas from handing
out the same VPN address, the LISTEN/NOTIFY watcher that tells the replicas about new devices, and
the schema migrations. The migration tests create a database of their own for every run, which is why
the MySQL tests connect as root.

### Screenshots:

The screenshots in this README are taken with [Playwright](https://playwright.dev). To take them
again after changing the web UI:

```sh
cd website
npx playwright install chromium   # once
npm run screenshots
```

It builds the web UI and the server, starts the server with a few example devices and writes the
images to `screenshots/`. It needs Go and leaves nothing running.

### The API:

The web UI talks to the server over [gRPC-Web](https://github.com/grpc/grpc-web). The API is
served under `/api` by [connectrpc](https://connectrpc.com), which speaks gRPC-Web itself, as well
as its own [Connect protocol](https://connectrpc.com/docs/protocol). The latter is plain HTTP and
JSON, so with a session - here from the admin password - a request can be sent with curl:

```sh
curl -c cookies -d username=admin -d password=<password> https://localhost:8443/signin/simpleauth
curl -b cookies -H 'Content-Type: application/json' -d '{}' https://localhost:8443/api/proto.Server/Info
```

For scripts, [API tokens](https://www.freie-netze.org/wg-access-server/4-auth/#api-tokens) replace the session.

### gRPC code generation:

The client communicates with the server via gRPC web. You can edit the API specification in `./proto/*.proto`.

After changing a service or message definition, you must regenerate the server and client code:

```sh
go install tool   # the code generators, pinned in go.mod
./codegen.sh
cd website && npm run codegen
```

Or use the Dockerfile at `proto/Dockerfile`:

```sh
docker build -f proto/Dockerfile --target proto-js -t wg-access-server-proto:js .
docker build -f proto/Dockerfile --target proto-go -t wg-access-server-proto:go .
docker run --rm --user "$(id -u):$(id -g)" -v `pwd`/proto:/proto -v `pwd`/website/src/sdk:/code/src/sdk wg-access-server-proto:js
docker run --rm --user "$(id -u):$(id -g)" -v `pwd`/proto:/code/proto wg-access-server-proto:go
```

## License

MIT - see [LICENSE](https://github.com/freifunkMUC/wg-access-server/blob/master/LICENSE).
