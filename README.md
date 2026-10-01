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

- Sign-in with OpenID Connect, GitLab, GitHub or a list of users of your own ([auth](https://www.freie-netze.org/wg-access-server/auth/))
- [API tokens](https://www.freie-netze.org/wg-access-server/auth/#api-tokens) for scripts, using the same API as the web UI
- Users of the built-in sign-in can change their own password ([changing your password](https://www.freie-netze.org/wg-access-server/auth/#changing-your-password))
- Two-factor authentication with an authenticator app or a passkey, for the built-in sign-in ([two-factor](https://www.freie-netze.org/wg-access-server/auth/#two-factor-authentication), [passkeys](https://www.freie-netze.org/wg-access-server/auth/#passkeys))
- Devices can be renamed; admins see and manage the devices of all users
- Admins can block a device or give it an expiry date, for temporary access, one device or many at once ([device access](#device-access))
- Admins can take somebody's access away in one action, without deleting anything ([revoking access](#taking-somebodys-access-away))
- A device can be given a new key without being deleted, keeping its name and address ([new key](#giving-a-device-a-new-key))
- Networks behind a device, for site-to-site links and subnet routers ([routed networks](#networks-behind-a-device))
- An optional limit on how many devices a user may create
- WireGuard client configurations as a file or a QR code
- IPv6: dual-stack, IPv6-only or IPv4-only, with NAT on or off for each
- Client isolation and a choice of the networks clients may reach
- Access policies: what somebody's devices may reach, decided by their identity provider ([policies](https://www.freie-netze.org/wg-access-server/configuration/#access-policies))
- Firewall rules with iptables or nftables ([firewall](https://www.freie-netze.org/wg-access-server/configuration/#firewall))
- A caching DNS proxy for the clients, with names for their devices
- PostgreSQL, MySQL or SQLite storage; several replicas can share PostgreSQL or MySQL
- An [audit log](https://www.freie-netze.org/wg-access-server/audit/) and Prometheus [metrics](#metrics)
- Commands to run when the WireGuard interface comes up or goes down
- The WireGuard kernel module where available, with an embedded userspace implementation as fallback
- Dark and light mode

## Documentation

[See our documentation website](https://www.freie-netze.org/wg-access-server/). It shows the
documentation of the latest release; the version selector at the top has the older releases and
`dev`, the state of the master branch.

Quick Links:

- [Configuration overview](https://www.freie-netze.org/wg-access-server/configuration/)
- [Deploy with Docker](https://www.freie-netze.org/wg-access-server/deployment/docker/)
- [Deploy with Docker Compose](https://www.freie-netze.org/wg-access-server/deployment/docker-compose/)
- [Deploy with Helm](https://www.freie-netze.org/wg-access-server/deployment/kubernetes/)
- [Raspberry Pi with Pi-hole](https://www.freie-netze.org/wg-access-server/deployment/raspberry-pi-pi-hole/)

## Try it out

Load the kernel modules on the host, then start the container:

```bash
modprobe ip_tables && modprobe ip6_tables && modprobe wireguard

export WG_ADMIN_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
export WG_WIREGUARD_PRIVATE_KEY="$(wg genkey)"
echo "Your automatically generated admin password for the wg-access-server's web interface: $WG_ADMIN_PASSWORD"

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
  -p 8443:8443/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

The web UI is at https://localhost:8443 on the machine itself, and at `https://<its address>:8443`
from others in your network - for example from your phone, to add it with the QR code. The
certificate is self-signed, so the browser warns once.

For an installation that stays - Docker Compose, a reverse proxy with a real certificate, a
database, single sign-on - follow the deployment documentation:
[Docker](https://www.freie-netze.org/wg-access-server/deployment/docker/),
[Docker Compose](https://www.freie-netze.org/wg-access-server/deployment/docker-compose/) or
[Raspberry Pi with Pi-hole](https://www.freie-netze.org/wg-access-server/deployment/raspberry-pi-pi-hole/).
It also covers what to do when the kernel modules cannot be loaded, and how to keep the private key
so that the devices you added keep working.

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

## Device access

An admin can take a device's access away without deleting it, from the device list under _admin_:

- **Block** removes the device's WireGuard peer, so it cannot connect. Its address stays reserved and
  its name stays taken. **Unblock** gives the peer back - the configuration file the user already has
  keeps working, so nobody has to set the device up again.
- **Expiry** ends the device's access at the end of a day you pick, which is what temporary access for
  a contractor or a guest looks like. Extending the date, or removing it, gives the access back the
  same way. An expiry in the past is refused: blocking is how access is ended now.

Both are admin-only on purpose. A user can see on their own device why it cannot connect, but cannot
lift a block or push an expiry out - a block they could lift would be no block. They can still delete
the device.

**Several at once.** Every row in the device list has a tick box, and the one in the header takes
everything the search and the filter leave - not only the page in view, which matters when the
search narrows three hundred devices down to the twelve of one person. A bar above the table then
blocks, unblocks or deletes all of them, a few requests at a time, and says how many worked: a
failure in the middle does not stop the rest, and "10 devices blocked, 2 failed" is what you get if
two of them were gone already.

A device whose expiry passes loses its peer within a minute; the server checks for it rather than
waiting for the next restart. Blocking takes effect right away, on every replica sharing a database.
Both are recorded in the [audit log](https://www.freie-netze.org/wg-access-server/audit/), and
`wg_access_server_devices_blocked` counts the devices in that state wherever the device
[metrics](#metrics) are enabled.

## Giving a device a new key

A WireGuard device is its key: whoever has the private half is the device, wherever they are. If it
may have got out - a laptop handed on, a configuration file mailed to the wrong person, a phone
backup nobody can account for - the key icon on the device gives it a **new key pair**, and the
browser hands back the configuration that goes with it.

The device keeps everything else: its name, its address, the networks behind it, its expiry. Nothing
else has to be changed around it, and the old key stops reaching the VPN the moment the new one is
stored - on every replica, not only the one that took the request.

Your own devices only. The private half of the new key is made in the browser and never sent
anywhere, so this is the person using the device, not an admin acting on it. An admin who wants
somebody's device off the VPN blocks it or deletes it - see [device access](#device-access) and
[revoking access](#taking-somebodys-access-away).

Until the new configuration is installed, the device does not connect. That is the point, and the
question the UI asks says so.

## Taking somebody's access away

When a person leaves or a laptop is lost, the device list is the wrong place to start: their access
is their devices, their API tokens and the browsers they are signed in with. **Revoke access**, next
to each user under _admin_, takes all three in one action:

- every device of theirs is blocked, so no tunnel of theirs comes up,
- every API token of theirs is revoked, so no script of theirs reaches the API,
- and every browser session of theirs is ended, so nobody is left signed in as them.

Nothing is deleted. The devices keep their keys and their addresses, so unblocking one gives the
access back and the configuration the person already has keeps working - which is what makes this
usable for somebody who is only away for a while, or for a suspicion that turns out to be wrong.

Revoking twice is not an error, it simply finds nothing left to take. Aiming it at yourself is
refused: it would block your own devices and sign you out halfway through. It is an admin action,
recorded in the [audit log](https://www.freie-netze.org/wg-access-server/audit/) as `user.revoke`
with what it took.

What it does **not** do is stop them from signing in again. If their identity provider still lets
them in, they get a new session - and their devices stay blocked, which is the part that matters.
Removing them at the provider, or deleting the user here, is what ends that.

## Networks behind a device

A device is usually one computer or one phone. It can also be the router of a whole site: an admin
assigns the networks that live behind it under _admin_ → _Networks_, and the server then sends
traffic for them through that device and accepts traffic from them through it. That is what makes a
site-to-site link, or a subnet router for a network the clients could not otherwise reach.

Three things follow from a route, and wg-access-server sets up all of them:

- The networks become part of the device's WireGuard peer, so the tunnel carries them.
- The kernel gets a route for each of them to the WireGuard interface, the way `wg-quick`'s
  `Table = auto` does it. Without that nothing would ever be sent there.
- The firewall rules are extended by them, on top of `vpn.allowedIPs`.

The device on the other end has to be set up for it as well: it needs to forward between its LAN and
the tunnel, and its own `AllowedIPs` must cover the VPN network. Client configurations downloaded
after the change carry the routed networks in their `AllowedIPs`; ones downloaded earlier do not, so
those clients either fetch the configuration again or add the network themselves. With the default
`vpn.allowedIPs` of `0.0.0.0/0, ::/0` there is nothing to do - it covers everything already.

Routes are admin-only, and some networks are refused:

- a default route - name the networks instead,
- anything overlapping the VPN networks, which the server hands out itself,
- anything overlapping a network this server is in: routing it would cut the server off from its own
  gateway, its database or the clients,
- and anything another device already carries, since two devices cannot both be the way to a network.

Changes are recorded in the [audit log](https://www.freie-netze.org/wg-access-server/audit/) as
`device.routes`.

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
  - `wg_access_server_devices_blocked`: devices that may not connect (blocked, or past their expiry)
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

If you use an AI coding assistant, it and you follow
[AGENTS.md](https://github.com/freifunkMUC/wg-access-server/blob/master/AGENTS.md).

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

For scripts, [API tokens](https://www.freie-netze.org/wg-access-server/auth/#api-tokens) replace the session.

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
