package devices

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key.PublicKey()
}

func peer(key wgtypes.Key, receive, transmit int64, handshake time.Time, endpoint string) wgtypes.Peer {
	p := wgtypes.Peer{PublicKey: key, ReceiveBytes: receive, TransmitBytes: transmit, LastHandshakeTime: handshake}
	if endpoint != "" {
		p.Endpoint = &net.UDPAddr{IP: net.ParseIP(endpoint), Port: 51820}
	}
	return p
}

func TestCounterDelta(t *testing.T) {
	require.Equal(t, int64(0), counterDelta(100, 100), "no traffic")
	require.Equal(t, int64(50), counterDelta(100, 150), "growth")
	require.Equal(t, int64(30), counterDelta(100, 30), "a reset counts in full")
	require.Equal(t, int64(0), counterDelta(100, 0), "reset without new traffic")
}

func TestTrafficTracker(t *testing.T) {
	key := mustKey(t)
	tracker := newTrafficTracker()

	rx, tx := tracker.observe(key, 1000, 200)
	require.Equal(t, [2]int64{1000, 200}, [2]int64{rx, tx}, "first sight counts in full - the interface is fresh")

	rx, tx = tracker.observe(key, 1500, 250)
	require.Equal(t, [2]int64{500, 50}, [2]int64{rx, tx}, "only the growth since last time")

	rx, tx = tracker.observe(key, 1500, 250)
	require.Equal(t, [2]int64{0, 0}, [2]int64{rx, tx}, "idle peer")

	// the device was deleted and re-created with the same key between syncs
	rx, tx = tracker.observe(key, 40, 4)
	require.Equal(t, [2]int64{40, 4}, [2]int64{rx, tx}, "a reset counter counts in full")
}

func TestTrafficTrackerForgetsRemovedPeers(t *testing.T) {
	kept, removed := mustKey(t), mustKey(t)
	tracker := newTrafficTracker()
	tracker.observe(kept, 10, 10)
	tracker.observe(removed, 99, 99)

	tracker.forgetAllBut([]wgtypes.Peer{{PublicKey: kept}})

	require.Contains(t, tracker.last, kept)
	require.NotContains(t, tracker.last, removed)
}

func TestCollectMetadata(t *testing.T) {
	now := time.Now()
	connected, stale, idle, neverSeen := mustKey(t), mustKey(t), mustKey(t), mustKey(t)
	tracker := newTrafficTracker()
	// idle has been observed before and has not moved since
	tracker.observe(idle, 70, 7)

	updates := collectMetadata([]wgtypes.Peer{
		peer(connected, 100, 10, now.Add(-30*time.Second), "192.0.2.1"),
		// the client moved to another replica ten minutes ago: its traffic is
		// still reported, its old connection is not
		peer(stale, 300, 30, now.Add(-10*time.Minute), "192.0.2.2"),
		peer(idle, 70, 7, now.Add(-10*time.Minute), "192.0.2.3"),
		// configured on this replica but never connected to it
		peer(neverSeen, 0, 0, time.Time{}, ""),
	}, tracker)

	byKey := map[string]storage.MetadataUpdate{}
	for _, update := range updates {
		byKey[update.PublicKey] = update
	}

	require.Len(t, updates, 2, "idle and never-connected peers need no write")

	c := byKey[connected.String()]
	require.Equal(t, int64(100), c.ReceiveBytes)
	require.NotNil(t, c.Connection, "the serving replica reports the connection")
	require.Equal(t, "192.0.2.1", c.Connection.Endpoint)

	s := byKey[stale.String()]
	require.Equal(t, int64(300), s.ReceiveBytes)
	require.Nil(t, s.Connection, "a replica the client left must not overwrite the connection")

	require.NotContains(t, byKey, idle.String())
	require.NotContains(t, byKey, neverSeen.String())
}

// Issue #208 end to end: two replicas share one database, the client roams
// from one to the other, and the stored totals and connection stay right.
func TestMetadataAcrossReplicas(t *testing.T) {
	store := storage.NewMemoryStorage()
	key := mustKey(t)
	require.NoError(t, store.Save(&storage.Device{Owner: "alice", Name: "phone", PublicKey: key.String()}))

	replicaA, replicaB := newTrafficTracker(), newTrafficTracker()
	record := func(tracker *trafficTracker, peers ...wgtypes.Peer) {
		require.NoError(t, store.RecordMetadata(collectMetadata(peers, tracker)))
	}
	now := time.Now()

	// the client is on replica A
	record(replicaA, peer(key, 1000, 100, now.Add(-20*time.Second), "192.0.2.1"))
	record(replicaB, peer(key, 0, 0, time.Time{}, ""))
	record(replicaA, peer(key, 1800, 180, now.Add(-10*time.Second), "192.0.2.1"))

	// it roams to replica B; A's handshake ages, its counters stop moving
	record(replicaB, peer(key, 400, 40, now.Add(-5*time.Second), "198.51.100.7"))
	record(replicaA, peer(key, 1800, 180, now.Add(-4*time.Minute), "192.0.2.1"))
	record(replicaB, peer(key, 900, 90, now, "198.51.100.7"))
	record(replicaA, peer(key, 1800, 180, now.Add(-4*time.Minute), "192.0.2.1"))

	device, err := store.Get("alice", "phone")
	require.NoError(t, err)
	require.Equal(t, int64(1800+900), device.ReceiveBytes, "A's and B's traffic both count, once each")
	require.Equal(t, int64(180+90), device.TransmitBytes)
	require.Equal(t, "198.51.100.7", device.Endpoint, "replica A must not drag the endpoint back")
	require.NotNil(t, device.LastHandshakeTime)
	require.True(t, device.LastHandshakeTime.Equal(now), "last handshake comes from the serving replica")
}
