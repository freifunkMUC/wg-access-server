package serve

import (
	"net"
	"net/netip"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/dnsproxy"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// startDNS runs the embedded DNS proxy on the server's VPN addresses and, if a
// domain is configured, keeps its zone in step with the devices. The returned
// function stops it again.
func startDNS(conf *config.AppConfig, deviceManager *devices.DeviceManager, storageBackend storage.Storage, vpn vpnAddressing) (func(), error) {
	if !conf.DNS.Enabled {
		return func() {}, nil
	}

	if len(conf.DNS.Upstream) == 0 {
		conf.DNS.Upstream = detectDNSUpstream(conf.VPN.CIDR != "", conf.VPN.CIDRv6 != "")
	}
	listenAddr := make([]string, 0, 2)
	for _, addr := range vpn.addrs {
		listenAddr = append(listenAddr, net.JoinHostPort(addr.String(), "53"))
	}
	dns, err := dnsproxy.New(dnsproxy.DNSServerOpts{
		Upstream:   conf.DNS.Upstream,
		Domain:     conf.DNS.Domain,
		ListenAddr: listenAddr,
		CacheSize:  conf.DNS.CacheSize,
	})
	if err != nil {
		return func() {}, errors.Wrap(err, "failed to create dns server")
	}
	dns.ListenAndServe()
	stop := func() { _ = dns.Close() }

	if conf.DNS.Domain != "" {
		rebuild := func() { dns.PushAuthZone(generateZone(deviceManager, vpn.addrs)) }
		rebuild()

		// Rebuild the zone whenever a device changes. A renamed device keeps
		// its addresses but answers to a new name, so an update matters as
		// much as an addition or a deletion.
		updater := newZoneUpdater(rebuild)
		storageBackend.OnAdd(updater.notify)
		storageBackend.OnUpdate(updater.notify)
		storageBackend.OnDelete(updater.notify)
		stop = func() {
			updater.stop()
			_ = dns.Close()
		}
	}
	return stop, nil
}

// zoneUpdater rebuilds the authoritative zone after a device changed. It does
// so in the background and only once for however many changes arrive while it
// is working: the zone is built from every device there is, and the change
// that triggers it reaches us while the device creation holds the allocation
// lock that every other creation waits for. Importing a hundred devices would
// otherwise rebuild the zone a hundred times, each time reading them all.
type zoneUpdater struct {
	changed chan struct{}
	quit    chan struct{}
	done    chan struct{}
}

func newZoneUpdater(rebuild func()) *zoneUpdater {
	updater := &zoneUpdater{
		// one slot: a change that arrives while a rebuild is running leaves a
		// note that one more is needed, and further ones need nothing
		changed: make(chan struct{}, 1),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go func() {
		defer close(updater.done)
		for {
			select {
			case <-updater.changed:
				rebuild()
			case <-updater.quit:
				return
			}
		}
	}()
	return updater
}

// notify says that a device changed. It never blocks, so a storage event is
// not held up by a rebuild, and never fails after stop.
func (u *zoneUpdater) notify(_ *storage.Device) {
	select {
	case u.changed <- struct{}{}:
	default:
	}
}

// stop ends the rebuilding and waits for one in flight to finish.
func (u *zoneUpdater) stop() {
	close(u.quit)
	<-u.done
}

func generateZone(deviceManager *devices.DeviceManager, vpnips []netip.Addr) dnsproxy.Zone {
	devs, err := deviceManager.ListAllDevices()
	if err != nil {
		logrus.Error(errors.Wrap(err, "could not query devices to generate the DNS zone"))
	}

	zone := make(dnsproxy.Zone)
	for _, device := range devs {
		owner := device.Owner
		name := device.Name
		addresses, unusable := network.ParseAddresses(device.Address)
		if len(unusable) > 0 {
			logrus.Warnf("device '%s' of user '%s' has an address that cannot be parsed ('%s') - it is left out of the DNS zone",
				name, owner, strings.Join(unusable, ", "))
		}
		zone[dnsproxy.ZoneKey{Owner: owner, Name: name}] = addresses
	}
	zone[dnsproxy.ZoneKey{}] = vpnips
	return zone
}
