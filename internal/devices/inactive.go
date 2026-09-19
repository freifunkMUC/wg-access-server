package devices

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
)

// inactiveCheckInterval is how often devices are checked for inactivity. A
// var so tests can shorten it.
var inactiveCheckInterval = 30 * time.Second

func inactiveLoop(ctx context.Context, d *DeviceManager, inactiveDeviceGracePeriod time.Duration) {
	ticker := time.NewTicker(inactiveCheckInterval)
	defer ticker.Stop()
	for {
		checkAndRemove(ctx, d, inactiveDeviceGracePeriod)
		select {
		case <-ctx.Done():
			logrus.Debug("stopping inactive device check")
			return
		case <-ticker.C:
		}
	}
}

func checkAndRemove(ctx context.Context, d *DeviceManager, inactiveDeviceGracePeriod time.Duration) {
	logrus.Debug("Inactive check executing")

	devices, err := d.ListAllDevices()
	if err != nil {
		logrus.Warn(errors.Wrap(err, "failed to list devices - inactive devices cannot be deleted"))
		return
	}

	for _, dev := range devices {
		logrus.Debugf("Checking inactive device: %s/%s", dev.Owner, dev.Name)

		var elapsed time.Duration
		if dev.LastHandshakeTime == nil {
			// Never connected
			elapsed = time.Since(dev.CreatedAt)
		} else {
			elapsed = time.Since(*dev.LastHandshakeTime)
		}

		if elapsed > inactiveDeviceGracePeriod {
			logrus.Warnf("Deleting inactive device: %s/%s", dev.Owner, dev.Name)
			err := d.DeleteDevice(dev.Owner, dev.Name)
			if err != nil {
				logrus.Error(errors.Wrap(err, fmt.Sprintf("failed to delete device: %s/%s", dev.Owner, dev.Name)))
				continue
			}
			// No user asked for this, so it is recorded as a change by the
			// server itself.
			audit.Log(ctx, audit.DeviceDelete, logrus.Fields{
				"device": dev.Name,
				"owner":  dev.Owner,
				"reason": "inactive",
			})
		}
	}
}
