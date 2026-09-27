package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// accessManager returns a manager whose storage events are wired up, as
// StartSync does it in the server, together with the interface it configures.
func accessManager(t *testing.T, devicesInStorage ...*storage.Device) (*DeviceManager, *recordingInterface) {
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

	wg := &recordingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]bool{}}
	manager := New(wg, s, "10.44.0.0/24", "")

	// The interval stays as it is: the loop makes one pass right away, which
	// is the same reconciliation these tests expect, and then sleeps far
	// beyond the end of the test. Changing the var while it reads it would be
	// a data race, not a shorter test.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := manager.StartSync(ctx, false, false, 0); err != nil {
		t.Fatal(err)
	}

	return manager, wg
}

// Disabling a device has to take its peer away right there: as long as the
// peer is configured, the client keeps its tunnel.
func TestDisablingADeviceRemovesItsPeer(t *testing.T) {
	key := testDeviceKey(t, 1)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: key, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	if !wg.has(key) {
		t.Fatal("the device has no peer before it was disabled")
	}

	disabled := true
	device, err := manager.SetDeviceAccess("alice", "laptop", AccessChange{Disabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if !device.Disabled {
		t.Error("the device is not disabled after disabling it")
	}
	if wg.has(key) {
		t.Error("a disabled device kept its peer")
	}
}

// ... and lifting the block has to give it back, without the user setting the
// device up again: the key and the address never changed.
func TestEnablingADeviceGivesThePeerBack(t *testing.T) {
	key := testDeviceKey(t, 1)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: key, Address: "10.44.0.2/32",
		CreatedAt: time.Now(), Disabled: true,
	})

	if wg.has(key) {
		t.Fatal("a device that is stored as disabled got a peer on startup")
	}

	disabled := false
	if _, err := manager.SetDeviceAccess("alice", "laptop", AccessChange{Disabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	if !wg.has(key) {
		t.Error("the device has no peer after the block was lifted")
	}
}

// A device whose access has run out must not be configured again - not by a
// sync after a storage reconnect either.
func TestSyncLeavesBlockedDevicesWithoutAPeer(t *testing.T) {
	expired := time.Now().Add(-time.Hour)
	manager, wg := accessManager(t,
		&storage.Device{
			Owner: "alice", Name: "expired", PublicKey: testDeviceKey(t, 1),
			Address: "10.44.0.2/32", CreatedAt: time.Now(), ExpiresAt: &expired,
		},
		&storage.Device{
			Owner: "bob", Name: "blocked", PublicKey: testDeviceKey(t, 2),
			Address: "10.44.0.3/32", CreatedAt: time.Now(), Disabled: true,
		},
		&storage.Device{
			Owner: "carol", Name: "laptop", PublicKey: testDeviceKey(t, 3),
			Address: "10.44.0.4/32", CreatedAt: time.Now(),
		},
	)

	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}

	if wg.has(testDeviceKey(t, 1)) {
		t.Error("an expired device got a peer")
	}
	if wg.has(testDeviceKey(t, 2)) {
		t.Error("a disabled device got a peer")
	}
	if !wg.has(testDeviceKey(t, 3)) {
		t.Error("a device that may connect has no peer")
	}
}

// An expiry date that passes writes nothing, so no event announces it. Without
// this pass a device would keep its peer until the server is restarted.
func TestExpiredDevicesLoseTheirPeer(t *testing.T) {
	key := testDeviceKey(t, 1)
	expires := time.Now().Add(50 * time.Millisecond)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: key, Address: "10.44.0.2/32",
		CreatedAt: time.Now(), ExpiresAt: &expires,
	})

	if !wg.has(key) {
		t.Fatal("a device whose expiry has not passed yet has no peer")
	}

	time.Sleep(100 * time.Millisecond)
	removeBlockedPeers(context.Background(), manager)

	if wg.has(key) {
		t.Error("a device kept its peer after its expiry date passed")
	}
}

// Extending the expiry gives the device its access back.
func TestPostponingTheExpiryGivesThePeerBack(t *testing.T) {
	key := testDeviceKey(t, 1)
	expired := time.Now().Add(-time.Hour)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: key, Address: "10.44.0.2/32",
		CreatedAt: time.Now(), ExpiresAt: &expired,
	})

	later := time.Now().Add(time.Hour)
	if _, err := manager.SetDeviceAccess("alice", "laptop", AccessChange{ExpiresAt: &later}); err != nil {
		t.Fatal(err)
	}
	if !wg.has(key) {
		t.Error("the device has no peer after its expiry was moved into the future")
	}
}

// Each of the two can be changed on its own: an admin who only blocks a device
// must not clear an expiry somebody else set in the meantime.
func TestSetDeviceAccessChangesOnlyWhatItWasGiven(t *testing.T) {
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	manager, _ := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1),
		Address: "10.44.0.2/32", CreatedAt: time.Now(), ExpiresAt: &expires,
	})

	disabled := true
	device, err := manager.SetDeviceAccess("alice", "laptop", AccessChange{Disabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if device.ExpiresAt == nil || !device.ExpiresAt.Equal(expires) {
		t.Errorf("expiresAt = %v, want it unchanged at %v", device.ExpiresAt, expires)
	}

	device, err = manager.SetDeviceAccess("alice", "laptop", AccessChange{ClearExpiresAt: true})
	if err != nil {
		t.Fatal(err)
	}
	if device.ExpiresAt != nil {
		t.Errorf("expiresAt = %v, want it cleared", device.ExpiresAt)
	}
	if !device.Disabled {
		t.Error("clearing the expiry lifted the block")
	}
}

// An expiry in the past would be a way to end access with a date instead of
// saying so - and a typo in a date would silently cut a user off.
func TestSetDeviceAccessRejectsAnExpiryInThePast(t *testing.T) {
	manager, _ := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1),
		Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	past := time.Now().Add(-time.Minute)
	_, err := manager.SetDeviceAccess("alice", "laptop", AccessChange{ExpiresAt: &past})
	if err == nil {
		t.Fatal("an expiry date in the past was accepted")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Errorf("err = %v, want a validation error the user is shown", err)
	}
}

// The interval is left alone here on purpose: a cancelled context has to end
// the loop at its select, whatever the ticker was set to, and writing the var
// would race with the loops the tests above have running.
func TestAccessLoopStopsWhenTheContextIsCancelled(t *testing.T) {
	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if !returnsWithin(t, time.Second, func() { accessLoop(ctx, manager) }) {
		t.Error("accessLoop kept running after its context was cancelled")
	}
}
