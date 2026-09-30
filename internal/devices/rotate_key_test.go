package devices

import (
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// Rotating a key is only worth anything if the old one stops reaching the VPN
// at once: the reason to do it is that somebody else may hold it.
func TestRotatingAKeyReplacesThePeer(t *testing.T) {
	old := testDeviceKey(t, 1)
	fresh := testDeviceKey(t, 2)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: old, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	if !wg.has(old) {
		t.Fatal("the device has no peer to begin with")
	}

	device, err := manager.RotateDeviceKey("alice", "laptop", fresh, "")
	if err != nil {
		t.Fatal(err)
	}
	if device.PublicKey != fresh {
		t.Errorf("public key = %q, want the new one", device.PublicKey)
	}

	if wg.has(old) {
		t.Error("the replaced key still has a peer")
	}
	if !wg.has(fresh) {
		t.Error("the new key has no peer")
	}
}

// Everything the device is known by stays, which is the difference between
// rotating a key and deleting the device to add it again.
func TestRotatingAKeyKeepsEverythingElse(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour)
	manager, _ := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32",
		CreatedAt: time.Now(), Routes: "192.168.5.0/24", ExpiresAt: &expires,
	})

	device, err := manager.RotateDeviceKey("alice", "laptop", testDeviceKey(t, 2), "")
	if err != nil {
		t.Fatal(err)
	}

	if device.Name != "laptop" || device.Address != "10.44.0.2/32" {
		t.Errorf("device = %+v, want the same name and address", device)
	}
	if device.Routes != "192.168.5.0/24" || device.ExpiresAt == nil {
		t.Errorf("device = %+v, want the networks and the expiry it had", device)
	}
}

// A blocked device must not come back to life through a key change: whoever
// is blocked would only have to rotate to be let in again.
func TestRotatingAKeyOfABlockedDeviceGivesNoPeer(t *testing.T) {
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32",
		CreatedAt: time.Now(), Disabled: true,
	})

	fresh := testDeviceKey(t, 2)
	device, err := manager.RotateDeviceKey("alice", "laptop", fresh, "")
	if err != nil {
		t.Fatal(err)
	}
	if !device.Disabled {
		t.Error("the device is no longer blocked")
	}
	if wg.has(fresh) {
		t.Error("a blocked device got a peer for its new key")
	}
}

func TestRotatingAKeyChecksTheKey(t *testing.T) {
	old := testDeviceKey(t, 1)
	manager, wg := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: old, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})
	// somebody else's device, whose key must stay theirs
	if _, err := manager.storage.Get("alice", "laptop"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		publicKey    string
		presharedKey string
	}{
		{"not a key at all", "nonsense", ""},
		{"empty", "", ""},
		{"the key it already has", old, ""},
		{"a broken pre-shared key", testDeviceKey(t, 2), "nonsense"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := manager.RotateDeviceKey("alice", "laptop", tc.publicKey, tc.presharedKey); err == nil {
				t.Fatal("the change went through")
			}
			if !wg.has(old) {
				t.Error("the device lost its peer over a refused change")
			}
			device, err := manager.storage.Get("alice", "laptop")
			if err != nil {
				t.Fatal(err)
			}
			if device.PublicKey != old {
				t.Errorf("public key = %q, want the one it had", device.PublicKey)
			}
		})
	}
}

// Taking a key another device uses would take that device's peer with it.
func TestRotatingToSomebodyElsesKeyIsRefused(t *testing.T) {
	mine := testDeviceKey(t, 1)
	theirs := testDeviceKey(t, 2)
	manager, wg := accessManager(t,
		&storage.Device{Owner: "alice", Name: "laptop", PublicKey: mine, Address: "10.44.0.2/32", CreatedAt: time.Now()},
		&storage.Device{Owner: "bob", Name: "phone", PublicKey: theirs, Address: "10.44.0.3/32", CreatedAt: time.Now()},
	)

	if _, err := manager.RotateDeviceKey("alice", "laptop", theirs, ""); err == nil {
		t.Fatal("a device took the key of another one")
	}

	if !wg.has(theirs) {
		t.Error("the other device lost its peer")
	}
	bobs, err := manager.storage.Get("bob", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if bobs.PublicKey != theirs {
		t.Errorf("the other device's key changed to %q", bobs.PublicKey)
	}
}

// A device of somebody else is not yours to rotate - the owner decides who
// reaches it, and the storage is what says whose it is.
func TestRotatingADeviceOfSomebodyElseFails(t *testing.T) {
	manager, _ := accessManager(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	if _, err := manager.RotateDeviceKey("bob", "laptop", testDeviceKey(t, 2), ""); err == nil {
		t.Fatal("somebody rotated a device that is not theirs")
	}
}
