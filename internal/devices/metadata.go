package devices

import (
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func metadataLoop(d *DeviceManager) {
	for {
		syncMetrics(d)
		time.Sleep(30 * time.Second)
	}
}

func syncMetrics(d *DeviceManager) {
	logrus.Debug("Metadata sync executing")

	peers, err := d.wg.ListPeers()
	if err != nil {
		logrus.Warn(errors.Wrap(err, "failed to list peers - metrics cannot be recorded"))
		return
	}

	for _, peer := range peers {
		// if the peer is connected we can update their metrics
		// importantly, we'll ignore peers that we know about
		// but aren't connected at the moment.
		// they may actually be connected to another replica.
		if peer.Endpoint != nil {
			if device, err := d.GetByPublicKey(peer.PublicKey.String()); err == nil {
				if !IsConnected(peer.LastHandshakeTime) && device.LastHandshakeTime != nil && !IsConnected(*device.LastHandshakeTime) {
					// Not connected, and we haven't been the last time either, nothing to update
					continue
				}

				publicKey := peer.PublicKey.String()
				currentRx := peer.ReceiveBytes
				currentTx := peer.TransmitBytes

				// Get the last known byte counts for this peer
				d.peerStatsMutex.Lock()
				lastStats, exists := d.peerStats[publicKey]
				
				if !exists {
					// First time seeing this peer in this replica
					// Initialize tracking with current values
					d.peerStats[publicKey] = &peerByteStats{
						ReceiveBytes:  currentRx,
						TransmitBytes: currentTx,
					}
					d.peerStatsMutex.Unlock()
					
					// Update endpoint and handshake time without changing byte counts
					device.Endpoint = peer.Endpoint.IP.String()
					device.LastHandshakeTime = &peer.LastHandshakeTime
					if err := d.SaveDevice(device); err != nil {
						logrus.Error(errors.Wrap(err, "failed to save device during metadata sync"))
					}
					continue
				}

				// Calculate deltas since last sync
				rxDelta := currentRx - lastStats.ReceiveBytes
				txDelta := currentTx - lastStats.TransmitBytes

				// Handle potential counter resets (e.g., if WireGuard interface was restarted)
				// If delta is negative, it means the counter was reset, so use the current value as delta
				if rxDelta < 0 {
					logrus.Warnf("Receive byte counter reset detected for peer %s, using current value as delta", publicKey)
					rxDelta = currentRx
				}
				if txDelta < 0 {
					logrus.Warnf("Transmit byte counter reset detected for peer %s, using current value as delta", publicKey)
					txDelta = currentTx
				}

				// Update tracking with current values
				lastStats.ReceiveBytes = currentRx
				lastStats.TransmitBytes = currentTx
				d.peerStatsMutex.Unlock()

				// Only update database if there's a change
				if rxDelta > 0 || txDelta > 0 {
					// Add the delta to the database atomically
					if err := d.storage.AddByteCounts(publicKey, rxDelta, txDelta); err != nil {
						logrus.Error(errors.Wrap(err, "failed to add byte counts during metadata sync"))
					}
				}

				// Update endpoint and handshake time
				device.Endpoint = peer.Endpoint.IP.String()
				device.LastHandshakeTime = &peer.LastHandshakeTime
				if err := d.SaveDevice(device); err != nil {
					logrus.Error(errors.Wrap(err, "failed to save device during metadata sync"))
				}
			}
		}
	}

	// Clean up tracking for peers that are no longer connected to this replica
	d.peerStatsMutex.Lock()
	connectedPeers := make(map[string]bool)
	for _, peer := range peers {
		if peer.Endpoint != nil {
			connectedPeers[peer.PublicKey.String()] = true
		}
	}
	for publicKey := range d.peerStats {
		if !connectedPeers[publicKey] {
			delete(d.peerStats, publicKey)
		}
	}
	d.peerStatsMutex.Unlock()
}
