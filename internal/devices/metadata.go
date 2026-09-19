package devices

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// metadataSyncInterval is how often the peer counters are read. A var so
// tests can shorten it.
var metadataSyncInterval = 30 * time.Second

func metadataLoop(ctx context.Context, d *DeviceManager) {
	tracker := newTrafficTracker()
	ticker := time.NewTicker(metadataSyncInterval)
	defer ticker.Stop()
	for {
		syncMetrics(d, tracker)
		select {
		case <-ctx.Done():
			logrus.Debug("stopping metadata sync")
			return
		case <-ticker.C:
		}
	}
}

func syncMetrics(d *DeviceManager, tracker *trafficTracker) {
	logrus.Debug("Metadata sync executing")

	peers, err := d.wg.ListPeers()
	if err != nil {
		logrus.Warn(errors.Wrap(err, "failed to list peers - metrics cannot be recorded"))
		return
	}

	updates := collectMetadata(peers, tracker)
	if err := d.RecordMetadata(updates); err != nil {
		logrus.Error(errors.Wrap(err, "failed to record device metadata during metadata sync"))
	}
}

// collectMetadata turns one snapshot of this replica's WireGuard peers into
// storage updates. It needs no database reads: updates address devices by
// public key, which keeps a sync cheap no matter how many devices exist.
func collectMetadata(peers []wgtypes.Peer, tracker *trafficTracker) []storage.MetadataUpdate {
	tracker.forgetAllBut(peers)

	var updates []storage.MetadataUpdate
	for _, peer := range peers {
		update := storage.MetadataUpdate{PublicKey: peer.PublicKey.String()}
		update.ReceiveBytes, update.TransmitBytes = tracker.observe(peer.PublicKey, peer.ReceiveBytes, peer.TransmitBytes)

		// Every replica knows every peer, but only the one the client talks to
		// has a recent handshake. Letting only that replica report endpoint and
		// handshake stops a replica the client has left from overwriting the
		// current values with its stale ones.
		if peer.Endpoint != nil && IsConnected(peer.LastHandshakeTime) {
			update.Connection = &storage.PeerConnection{
				Endpoint:          peer.Endpoint.IP.String(),
				LastHandshakeTime: peer.LastHandshakeTime,
			}
		}

		if update.ReceiveBytes == 0 && update.TransmitBytes == 0 && update.Connection == nil {
			continue
		}
		updates = append(updates, update)
	}
	return updates
}

// trafficTracker remembers each peer's WireGuard byte counters as of the
// previous sync, so only the traffic since then is recorded. WireGuard's
// counters cannot be reset or read per replica in any other way.
type trafficTracker struct {
	last map[wgtypes.Key]byteCounters
}

type byteCounters struct {
	receive, transmit int64
}

func newTrafficTracker() *trafficTracker {
	return &trafficTracker{last: map[wgtypes.Key]byteCounters{}}
}

// observe records the current counters and returns the traffic since the
// previous observation.
//
// A peer seen for the first time counts in full. That is correct because the
// interface is created fresh when the server starts - wg-embed's LinkAdd fails
// on an existing one - so its counters only hold traffic of this process.
func (t *trafficTracker) observe(key wgtypes.Key, receive, transmit int64) (int64, int64) {
	previous := t.last[key]
	t.last[key] = byteCounters{receive: receive, transmit: transmit}
	return counterDelta(previous.receive, receive), counterDelta(previous.transmit, transmit)
}

// forgetAllBut drops peers that are gone from the interface, so a device that
// is deleted and later re-added starts counting from zero again.
func (t *trafficTracker) forgetAllBut(peers []wgtypes.Peer) {
	present := make(map[wgtypes.Key]struct{}, len(peers))
	for _, peer := range peers {
		present[peer.PublicKey] = struct{}{}
	}
	for key := range t.last {
		if _, ok := present[key]; !ok {
			delete(t.last, key)
		}
	}
}

// counterDelta returns how much a byte counter grew. A counter below its
// previous value was reset - the peer was removed and re-added between two
// syncs - so everything it shows now is new traffic.
func counterDelta(previous, current int64) int64 {
	if current < previous {
		return current
	}
	return current - previous
}
