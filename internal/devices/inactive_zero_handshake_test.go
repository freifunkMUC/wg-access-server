package devices

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func mustGet(t *testing.T, s storage.Storage, owner, name string) *storage.Device {
	t.Helper()
	dev, err := s.Get(owner, name)
	if err != nil {
		t.Fatalf("Get(%s/%s): %v", owner, name, err)
	}
	return dev
}

// TestCheckAndRemoveZeroHandshakeTime verifies that a device whose
// LastHandshakeTime is a non-nil pointer to the zero time.Time (a peer that
// has an endpoint but never completed a handshake) is treated like a device
// that never connected: the CreatedAt-based grace period applies instead of
// time.Since(time.Time{}) which would delete it immediately.
func TestCheckAndRemoveZeroHandshakeTime(t *testing.T) {
	mem := storage.NewMemoryStorage()
	dm := New(&fakeWgInterface{}, mem, "10.44.0.0/24", "")

	now := time.Now()
	gracePeriod := time.Hour

	// Non-nil but zero handshake time, created just now: must survive.
	zero := time.Time{}
	if err := mem.Save(&storage.Device{
		Owner:             "alice",
		Name:              "fresh-zero-handshake",
		PublicKey:         testPublicKey(1),
		Address:           "10.44.0.2/32",
		CreatedAt:         now,
		LastHandshakeTime: &zero,
	}); err != nil {
		t.Fatal(err)
	}

	// Nil handshake time, created just now: must survive (grace period).
	if err := mem.Save(&storage.Device{
		Owner:     "alice",
		Name:      "fresh-never-connected",
		PublicKey: testPublicKey(2),
		Address:   "10.44.0.3/32",
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Genuine handshake time beyond the grace period: must be deleted.
	oldHandshake := now.Add(-2 * time.Hour)
	if err := mem.Save(&storage.Device{
		Owner:             "alice",
		Name:              "stale",
		PublicKey:         testPublicKey(3),
		Address:           "10.44.0.4/32",
		CreatedAt:         now.Add(-3 * time.Hour),
		LastHandshakeTime: &oldHandshake,
	}); err != nil {
		t.Fatal(err)
	}

	checkAndRemove(t.Context(), dm, gracePeriod)

	if _, err := mem.Get("alice", "fresh-zero-handshake"); err != nil {
		t.Errorf("device with zero (non-nil) LastHandshakeTime and recent CreatedAt was deleted: %v", err)
	}
	if _, err := mem.Get("alice", "fresh-never-connected"); err != nil {
		t.Errorf("device with nil LastHandshakeTime and recent CreatedAt was deleted: %v", err)
	}
	if _, err := mem.Get("alice", "stale"); err == nil {
		t.Error("device with LastHandshakeTime beyond the grace period was not deleted")
	}
}

// TestSyncMetricsDoesNotPersistZeroHandshakeTime verifies that syncMetrics
// only persists LastHandshakeTime when the peer actually completed a
// handshake; a peer with an endpoint but a zero handshake time must leave the
// stored device's LastHandshakeTime nil. Older versions did store the zero
// time, which is why checkAndRemove has to cope with it.
func TestSyncMetricsDoesNotPersistZeroHandshakeTime(t *testing.T) {
	mem := storage.NewMemoryStorage()
	wg := &fakeWgInterface{}
	dm := New(wg, mem, "10.44.0.0/24", "")

	keyNever := wgtypes.Key{1}
	keyActive := wgtypes.Key{2}

	if err := mem.Save(&storage.Device{
		Owner:     "alice",
		Name:      "never-handshaked",
		PublicKey: keyNever.String(),
		Address:   "10.44.0.2/32",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := mem.Save(&storage.Device{
		Owner:     "alice",
		Name:      "active",
		PublicKey: keyActive.String(),
		Address:   "10.44.0.3/32",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	handshake := time.Now().Add(-30 * time.Second)
	wg.peers = []wgtypes.Peer{
		{
			PublicKey:         keyNever,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
			LastHandshakeTime: time.Time{}, // endpoint known, but never handshaked
			ReceiveBytes:      1,
			TransmitBytes:     2,
		},
		{
			PublicKey:         keyActive,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 51820},
			LastHandshakeTime: handshake,
			ReceiveBytes:      3,
			TransmitBytes:     4,
		},
	}

	syncMetrics(dm, newTrafficTracker())

	never := mustGet(t, mem, "alice", "never-handshaked")
	if never.LastHandshakeTime != nil {
		t.Errorf("expected LastHandshakeTime to stay nil for a zero handshake time, got %v", *never.LastHandshakeTime)
	}

	active := mustGet(t, mem, "alice", "active")
	if active.LastHandshakeTime == nil {
		t.Fatal("expected LastHandshakeTime to be persisted for a genuine handshake, got nil")
	}
	if !active.LastHandshakeTime.Equal(handshake) {
		t.Errorf("expected LastHandshakeTime %v, got %v", handshake, *active.LastHandshakeTime)
	}
}
