package devices

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

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

// routedNetworksMayHaveChanged recomputes the routed networks after a change
// to one device. An installation that routes nothing - which is most of them -
// pays a comparison for this and nothing else.
func (d *DeviceManager) routedNetworksMayHaveChanged(device *storage.Device) {
	if d.routeSync == nil {
		return
	}

	d.routedMu.Lock()
	known := len(d.routed)
	d.routedMu.Unlock()
	if known == 0 && len(device.RouteList()) == 0 {
		return
	}

	devices, err := d.ListAllDevices()
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to list devices - the firewall rules for the routed networks are unchanged: %w", err))
		return
	}
	d.syncRoutedNetworks(devices)
}

// syncRoutedNetworks hands the networks routed through the devices to the
// route sync, unless they are the ones it already knows. A failure is not
// remembered, so the next change tries again.
func (d *DeviceManager) syncRoutedNetworks(devices []*storage.Device) {
	if d.routeSync == nil {
		return
	}

	routed := []string{}
	for _, device := range devices {
		routed = append(routed, device.RouteList()...)
	}
	sort.Strings(routed)

	d.routedMu.Lock()
	defer d.routedMu.Unlock()
	if slices.Equal(routed, d.routed) {
		return
	}

	if err := d.routeSync(routed); err != nil {
		logrus.Error(fmt.Errorf("failed to update the firewall rules for the routed networks: %w", err))
		return
	}
	d.routed = routed
}

// RoutedNetworks returns the networks routed through the devices as the
// firewall was last told about them.
func (d *DeviceManager) RoutedNetworks() []string {
	d.routedMu.Lock()
	defer d.routedMu.Unlock()
	return append([]string{}, d.routed...)
}
