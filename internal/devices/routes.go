package devices

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// maxRoutesPerDevice bounds how many networks one device may have behind it.
// Every route is a line in the peer's allowed IPs, a kernel route and a
// firewall rule, and there is no use case for hundreds of them.
const maxRoutesPerDevice = 25

// hostNetworks reports the networks the server itself is part of. A route to
// one of them would send the server's own traffic - its default gateway, its
// database, the address the clients reach it at - into a tunnel. A var so the
// tests can describe a host of their own.
var hostNetworks = func() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("failed to read the addresses of this host: %w", err)
	}

	networks := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(ipnet.String())
		if err != nil {
			continue
		}
		networks = append(networks, prefix.Masked())
	}
	return networks, nil
}

// SetDeviceRoutes stores the networks that live behind a device: what makes it
// a site-to-site link or a subnet router. The server then accepts traffic from
// those networks through the device's peer, and sends traffic for them there.
//
// Whether the caller may do this is decided by the API, and it is admins only.
// A user who could claim a network would be claiming everybody's traffic to it.
func (d *DeviceManager) SetDeviceRoutes(user string, name string, routes []string) (*storage.Device, error) {
	normalized, err := normalizeRoutes(routes)
	if err != nil {
		return nil, err
	}

	// The same lock as device creation: the check against the routes of the
	// other devices has to still hold when this one is saved.
	var changed *storage.Device
	err = d.storage.WithAllocationLock(func() error {
		device, err := d.storage.Get(user, name)
		if err != nil {
			return fmt.Errorf("failed to retrieve device: %w", err)
		}

		if err := d.checkRoutes(normalized, device); err != nil {
			return err
		}

		changed, err = d.storage.SetRoutes(device, strings.Join(routeStrings(normalized), ", "))
		if err != nil {
			return fmt.Errorf("failed to change the routes of the device: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return changed, nil
}

// normalizeRoutes turns what the client sent into the networks to store: every
// one a network address, each of them only once, in the order they were given.
func normalizeRoutes(routes []string) ([]netip.Prefix, error) {
	if len(routes) > maxRoutesPerDevice {
		return nil, invalid("A device may have at most %d networks behind it.", maxRoutesPerDevice)
	}

	seen := map[netip.Prefix]bool{}
	normalized := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, invalid("'%s' is not a network in CIDR notation, like '192.168.5.0/24'.", route)
		}

		// A default route would send everything the clients have - and with
		// the kernel route, everything this server has - into one device.
		if prefix.Bits() == 0 {
			return nil, invalid("'%s' is a default route. Name the networks behind the device instead.", route)
		}

		prefix = prefix.Masked()
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

// checkRoutes rejects what a device must not be allowed to claim: the VPN's
// own networks, the networks this server is in, and what another device
// already routes. Callers must hold the storage's allocation lock.
func (d *DeviceManager) checkRoutes(routes []netip.Prefix, device *storage.Device) error {
	if len(routes) == 0 {
		return nil
	}

	vpn := make([]netip.Prefix, 0, 2)
	for _, cidr := range []string{d.cidr, d.cidrv6} {
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("the configured vpn network '%s' is not a network: %w", cidr, err)
		}
		vpn = append(vpn, prefix.Masked())
	}

	host, err := hostNetworks()
	if err != nil {
		return err
	}

	devices, err := d.ListAllDevices()
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	for _, route := range routes {
		for _, prefix := range vpn {
			if prefix.Overlaps(route) {
				return invalid("'%s' overlaps the VPN network '%s', which the server hands out itself.", route, prefix)
			}
		}
		for _, prefix := range host {
			if prefix.Overlaps(route) {
				return invalid("'%s' overlaps '%s', a network this server is in - routing it would cut the server off.", route, prefix)
			}
		}
		for _, other := range devices {
			if other.Owner == device.Owner && other.Name == device.Name {
				continue
			}
			for _, taken := range other.RouteList() {
				prefix, err := netip.ParsePrefix(taken)
				if err != nil {
					continue
				}
				if prefix.Overlaps(route) {
					return invalid("'%s' overlaps '%s', which is already routed to the device '%s'.", route, prefix, other.Name)
				}
			}
		}
	}

	return nil
}

func routeStrings(routes []netip.Prefix) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, route.String())
	}
	return values
}

// FirewallState is what the firewall has to be built from besides the
// configuration: it changes while the server runs, as devices come and go and
// as people sign in.
type FirewallState struct {
	// Routed are the networks that live behind devices.
	Routed []string
	// Policies maps the name of an access policy to the addresses of the
	// devices of the people in it.
	Policies map[string][]string
}

// key is a form of the state that can be compared, so that a change can be
// told from a recomputation that found the same thing.
func (s FirewallState) key() string {
	names := make([]string, 0, len(s.Policies))
	for name := range s.Policies {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(strings.Join(s.Routed, ","))
	for _, name := range names {
		b.WriteString("|" + name + "=" + strings.Join(s.Policies[name], ","))
	}
	return b.String()
}

// Resync asks for everything to be brought in line with what is stored: the
// WireGuard peers, the routes and the firewall rules. Several asks while one
// is running collapse into one more.
func (d *DeviceManager) Resync() {
	select {
	case d.resync <- struct{}{}:
	default:
	}
}

// syncFirewallState works out what the firewall has to be built from and hands
// it over, unless it is what the firewall was built from last. A failure is
// not remembered, so the next change tries again.
func (d *DeviceManager) syncFirewallState(devices []*storage.Device) {
	if d.firewallSync == nil {
		return
	}

	state, err := d.firewallState(devices)
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to work out the firewall rules: %w", err))
		return
	}

	d.firewallMu.Lock()
	defer d.firewallMu.Unlock()
	if state.key() == d.firewall.key() {
		return
	}

	if err := d.firewallSync(state); err != nil {
		logrus.Error(fmt.Errorf("failed to update the firewall rules: %w", err))
		return
	}
	d.firewall = state
}

// firewallState collects what the rules are made of: the networks behind the
// devices, and the devices of the people in each access policy.
//
// A device that may not connect is left out of the policies: it has no peer,
// so nothing can come from its address, and listing it would say otherwise.
func (d *DeviceManager) firewallState(devices []*storage.Device) (FirewallState, error) {
	users, err := d.storage.Users()
	if err != nil {
		return FirewallState{}, fmt.Errorf("failed to list users: %w", err)
	}
	policiesOf := make(map[string][]string, len(users))
	for _, user := range users {
		if policies := user.PolicyList(); len(policies) > 0 {
			policiesOf[user.Subject] = policies
		}
	}

	state := FirewallState{Routed: []string{}, Policies: map[string][]string{}}
	now := time.Now()
	for _, device := range devices {
		state.Routed = append(state.Routed, device.RouteList()...)

		if !device.AccessAllowed(now) {
			continue
		}
		for _, policy := range policiesOf[device.Owner] {
			state.Policies[policy] = append(state.Policies[policy], network.SplitAddresses(device.Address)...)
		}
	}

	sort.Strings(state.Routed)
	for name := range state.Policies {
		sort.Strings(state.Policies[name])
	}
	return state, nil
}

// RoutedNetworks returns the networks routed through the devices as the
// firewall was last told about them.
func (d *DeviceManager) RoutedNetworks() []string {
	d.firewallMu.Lock()
	defer d.firewallMu.Unlock()
	return append([]string{}, d.firewall.Routed...)
}
