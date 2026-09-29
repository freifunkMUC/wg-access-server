// Package serve runs the server: it reads the configuration, brings up the
// WireGuard interface, the DNS proxy and the web server, and takes them down
// again in the order they came up.
package serve

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/authnz"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

func (cmd *servecmd) Name() string {
	return "serve"
}

func (cmd *servecmd) Run() {
	// Swallow any panic stacktrace
	defer func() {
		if err := recover(); err != nil {
			logrus.Fatal(err)
		}
	}()

	conf := cmd.ReadConfig()

	// Software banner
	logrus.Infof("+++ wg-access-server %s (%s)", buildinfo.Version(), buildinfo.ShortCommitHash())

	vpn := vpnAddresses(conf)

	wg, stopWireGuard, err := cmd.startWireGuard(conf, vpn)
	defer stopWireGuard()
	if err != nil {
		logrus.Error(err)
		return
	}

	// Storage
	storageBackend, err := storage.NewStorage(conf.Storage)
	if err != nil {
		logrus.Error(fmt.Errorf("failed to create storage backend: %w", err))
		return
	}
	if err := storageBackend.Open(); err != nil {
		logrus.Error(fmt.Errorf("failed to connect/open storage backend: %w", err))
		return
	}
	defer storageBackend.Close()

	// Device manager
	deviceManager := devices.New(wg, storageBackend, conf.VPN.CIDR, conf.VPN.CIDRv6,
		devices.WithMaxDevicesPerUser(conf.MaxDevicesPerUser),
		devices.WithFirewallSync(firewallSync(conf, vpn)))

	stopDNS, err := startDNS(conf, deviceManager, storageBackend, vpn)
	defer stopDNS()
	if err != nil {
		logrus.Error(err)
		return
	}

	// Cancelled on shutdown, which stops the background loops of the device
	// manager before the storage backend is closed under them.
	backgroundCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	if err := deviceManager.StartSync(backgroundCtx, conf.EnableMetadata, conf.EnableInactiveDeviceDeletion, conf.InactiveDeviceGracePeriod); err != nil {
		logrus.Error(fmt.Errorf("failed to sync: %w", err))
		return
	}

	// The browser sessions: the cookie carries an id, who signed in is kept
	// here. Expired ones are removed while the server runs.
	maxAge, err := authnz.SessionMaxAge(conf.Auth.SessionStore)
	if err != nil {
		logrus.Error(err)
		return
	}
	browserSessions := websessions.New(storageBackend, maxAge)
	browserSessions.StartCleanup(backgroundCtx)

	handler, err := newRouter(conf, deviceManager, storageBackend, wg, browserSessions)
	if err != nil {
		logrus.Error(err)
		return
	}

	if err := listenAndServe(conf, handler, stopBackground); err != nil {
		logrus.Error(err)
	}
}
