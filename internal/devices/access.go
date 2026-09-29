package devices

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// accessCheckInterval is how often devices are checked for an expiry date that
// has passed. A var so tests can shorten it.
var accessCheckInterval = time.Minute

// accessLoop takes the WireGuard peer away from devices whose access has run
// out. An expiry needs this pass: nothing is written when a date passes, so no
// storage event announces it, and a device would keep its peer until the next
// restart. A device that is disabled loses its peer right away through the
// update event - this pass only has to catch what it missed, which is why the
// interval can be this coarse.
func accessLoop(ctx context.Context, d *DeviceManager) {
	ticker := time.NewTicker(accessCheckInterval)
	defer ticker.Stop()
	for {
		removeBlockedPeers(ctx, d)
		select {
		case <-ctx.Done():
			logrus.Debug("stopping the device access check")
			return
		case <-ticker.C:
		}
	}
}

// removeBlockedPeers removes the peer of every device that may no longer
// connect. The peers are read only when there is a device to look for, so the
// usual pass - nothing expired, nothing disabled - costs one query.
func removeBlockedPeers(ctx context.Context, d *DeviceManager) {
	logrus.Debug("Device access check executing")

	devices, err := d.ListAllDevices()
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to list devices - expired devices keep their access: %w", err))
		return
	}

	now := time.Now()
	blocked := map[string]*storage.Device{}
	for _, device := range devices {
		if !device.AccessAllowed(now) {
			blocked[device.PublicKey] = device
		}
	}
	if len(blocked) == 0 {
		return
	}

	peers, err := d.wg.ListPeers()
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to list peers - expired devices keep their access: %w", err))
		return
	}

	for _, peer := range peers {
		device, ok := blocked[peer.PublicKey.String()]
		if !ok {
			continue
		}

		logrus.Infof("Device '%s' of user '%s' may no longer connect - removing its peer", device.Name, device.Owner)
		if err := d.wg.RemovePeer(device.PublicKey); err != nil {
			logrus.Error(fmt.Errorf("failed to remove the peer of device %s/%s: %w", device.Owner, device.Name, err))
			continue
		}

		// An expiry that has passed is a change nobody asked for, so it is
		// recorded as one by the server itself. This is reached once per
		// device: the peer is gone afterwards, so the next pass finds nothing
		// to remove. A device that is disabled was recorded when the admin
		// disabled it and needs no second entry.
		if device.Expired(now) {
			audit.Log(ctx, audit.DeviceExpire, logrus.Fields{
				"device": device.Name,
				"owner":  device.Owner,
			})
		}
	}
}

// resyncLoop brings the interface back in line with storage whenever the
// backend says events may have been missed. See StartSync for why the changes
// are coalesced rather than counted.
func resyncLoop(ctx context.Context, d *DeviceManager, resync <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("stopping the device resynchronization")
			return
		case <-resync:
			if err := d.sync(); err != nil {
				logrus.Error(fmt.Errorf("device sync after a storage backend event failed: %w", err))
			}
		}
	}
}
