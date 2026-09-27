package devices

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// withHostNetworks makes the tests describe the networks the server is in,
// instead of whatever the machine running them happens to have.
func withHostNetworks(t *testing.T, networks ...string) {
	t.Helper()
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	previous := hostNetworks
	hostNetworks = func() ([]netip.Prefix, error) { return prefixes, nil }
	t.Cleanup(func() { hostNetworks = previous })
}

// routesManager returns a manager whose events are wired up, with the devices
// already in storage.
func routesManager(t *testing.T, devicesInStorage ...*storage.Device) (*DeviceManager, *countingInterface) {
	t.Helper()

	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for _, device := range devicesInStorage {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}

	wg := &countingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]wgtypes.Peer{}}
	manager := New(wg, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := manager.StartSync(ctx, false, false, 0); err != nil {
		t.Fatal(err)
	}

	return manager, wg
}

func allowedIPsOf(t *testing.T, wg *countingInterface, publicKey string) []string {
	t.Helper()
	peer, ok := wg.peers[publicKey]
	if !ok {
		t.Fatalf("there is no peer for %s", publicKey)
	}
	allowed := make([]string, 0, len(peer.AllowedIPs))
	for _, ipnet := range peer.AllowedIPs {
		allowed = append(allowed, ipnet.String())
	}
	return allowed
}

func contains(values []string, want string) bool {
	return slices.Contains(values, want)
}

// What a route is for: the network behind the device becomes part of its
// peer's allowed IPs, so the server accepts that traffic from it and sends
// traffic for it there.
func TestSetDeviceRoutesReachesThePeer(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24")
	key := testDeviceKey(t, 1)
	manager, wg := routesManager(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: key, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	if allowed := allowedIPsOf(t, wg, key); len(allowed) != 1 {
		t.Fatalf("the peer starts with %v, want only the device's address", allowed)
	}

	device, err := manager.SetDeviceRoutes("alice", "site", []string{"192.168.5.0/24", "2001:db8:5::/48"})
	if err != nil {
		t.Fatal(err)
	}
	if device.Routes != "192.168.5.0/24, 2001:db8:5::/48" {
		t.Errorf("routes = %q, want both networks", device.Routes)
	}

	allowed := allowedIPsOf(t, wg, key)
	for _, want := range []string{"10.44.0.2/32", "192.168.5.0/24", "2001:db8:5::/48"} {
		if !contains(allowed, want) {
			t.Errorf("the peer's allowed IPs %v are missing %s", allowed, want)
		}
	}

	// and taking them away leaves an ordinary device
	if _, err := manager.SetDeviceRoutes("alice", "site", nil); err != nil {
		t.Fatal(err)
	}
	if allowed := allowedIPsOf(t, wg, key); len(allowed) != 1 {
		t.Errorf("the peer keeps %v after the routes were removed", allowed)
	}
}

// A peer that already matches what is stored must be left alone - otherwise
// every sync would reconfigure every peer that has a route.
func TestSyncLeavesARoutedPeerAlone(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24")
	manager, wg := routesManager(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32",
		Routes: "192.168.5.0/24", CreatedAt: time.Now(),
	})

	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	wg.adds = 0
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if wg.adds != 0 {
		t.Errorf("a sync reconfigured %d peer(s) although nothing changed", wg.adds)
	}
}

func TestSetDeviceRoutesNormalizes(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24")
	manager, _ := routesManager(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	// a host address of the network, the same network twice, and some spaces
	device, err := manager.SetDeviceRoutes("alice", "site", []string{" 192.168.5.7/24 ", "192.168.5.0/24", ""})
	if err != nil {
		t.Fatal(err)
	}
	if device.Routes != "192.168.5.0/24" {
		t.Errorf("routes = %q, want the network once", device.Routes)
	}
}

// The routes decide where everybody's traffic for those networks goes. What
// must never be claimed:
func TestSetDeviceRoutesRefusesWhatWouldHijackTraffic(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24", "fe80::/64")

	for _, tc := range []struct {
		name   string
		routes []string
		says   string
	}{
		{"a default route", []string{"0.0.0.0/0"}, "default route"},
		{"an IPv6 default route", []string{"::/0"}, "default route"},
		{"the VPN network itself", []string{"10.44.0.0/24"}, "VPN network"},
		{"a part of the VPN network", []string{"10.44.0.128/25"}, "VPN network"},
		{"the IPv6 VPN network", []string{"fd48:4c4:7aa9::/64"}, "VPN network"},
		{"a network the server is in", []string{"192.0.2.0/25"}, "this server is in"},
		{"a network around the server's", []string{"192.0.0.0/16"}, "this server is in"},
		{"something that is not a network", []string{"192.168.5.0"}, "CIDR notation"},
		{"a network another device routes", []string{"172.16.9.0/24"}, "already routed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, _ := routesManager(t,
				&storage.Device{
					Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1),
					Address: "10.44.0.2/32", CreatedAt: time.Now(),
				},
				&storage.Device{
					Owner: "bob", Name: "other-site", PublicKey: testDeviceKey(t, 2),
					Address: "10.44.0.3/32", Routes: "172.16.0.0/16", CreatedAt: time.Now(),
				},
			)

			_, err := manager.SetDeviceRoutes("alice", "site", tc.routes)
			if err == nil {
				t.Fatalf("%v was accepted", tc.routes)
			}
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v, want a validation error the user is shown", err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the message %q does not say what is wrong (%q)", err.Error(), tc.says)
			}
		})
	}
}

// A device may keep its own routes when they are set again - only another
// device's are taken.
func TestSetDeviceRoutesKeepsItsOwn(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24")
	manager, _ := routesManager(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32",
		Routes: "192.168.5.0/24", CreatedAt: time.Now(),
	})

	if _, err := manager.SetDeviceRoutes("alice", "site", []string{"192.168.5.0/24", "192.168.6.0/24"}); err != nil {
		t.Errorf("a device could not keep its own route: %v", err)
	}
}

func TestSetDeviceRoutesRefusesTooMany(t *testing.T) {
	withHostNetworks(t)
	manager, _ := routesManager(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	routes := make([]string, 0, maxRoutesPerDevice+1)
	for i := 0; i <= maxRoutesPerDevice; i++ {
		routes = append(routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, byte(i), 0}), 24).String())
	}

	if _, err := manager.SetDeviceRoutes("alice", "site", routes); err == nil {
		t.Fatal("more routes than allowed were accepted")
	}
}

// The firewall rules are built at startup from the configuration; the routes
// an admin adds later have to reach them.
func TestRouteSyncIsToldAboutTheNetworks(t *testing.T) {
	withHostNetworks(t, "192.0.2.0/24")

	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Save(&storage.Device{
		Owner: "alice", Name: "site", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	var calls [][]string
	wg := &countingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]wgtypes.Peer{}}
	manager := New(wg, s, "10.44.0.0/24", "", WithRouteSync(func(routes []string) error {
		calls = append(calls, append([]string{}, routes...))
		return nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := manager.StartSync(ctx, false, false, 0); err != nil {
		t.Fatal(err)
	}

	// nothing is routed, so there is nothing to tell the firewall about
	if len(calls) != 0 {
		t.Fatalf("the firewall was reconfigured %d time(s) although nothing is routed", len(calls))
	}

	if _, err := manager.SetDeviceRoutes("alice", "site", []string{"192.168.5.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != "192.168.5.0/24" {
		t.Fatalf("the firewall was told %v, want the one routed network", calls)
	}

	// setting the same routes again changes nothing, so the rules stay as they are
	if _, err := manager.SetDeviceRoutes("alice", "site", []string{"192.168.5.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Errorf("the firewall was reconfigured again for the same networks: %v", calls)
	}

	// and a device that is deleted takes its networks out of the rules
	if err := manager.DeleteDevice("alice", "site"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || len(calls[1]) != 0 {
		t.Errorf("the firewall was told %v after the device was deleted, want no networks", calls)
	}
}
