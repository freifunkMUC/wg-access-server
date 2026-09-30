package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Replacing the key material of a device is how somebody whose private key
// may be in the wrong hands keeps their device - so everything else about it
// has to survive, and every backend has to report the change.
func TestSetKeys(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "keys.db"),
		"postgres": freshPostgres(t),
		"mysql":    os.Getenv("WG_TEST_MYSQL_URI"),
	}

	for name, uri := range backends {
		if uri == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			owner := "keys-owner-" + name
			t.Cleanup(func() { _, _ = s.DeleteForOwner(owner) })

			expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
			device := &Device{
				Owner: owner, Name: "laptop", PublicKey: testKey(owner + "old"),
				PresharedKey: testKey(owner + "psk"), Address: "10.44.0.2/32",
				CreatedAt: time.Now(), Routes: "192.168.5.0/24", ExpiresAt: &expires,
			}
			if err := s.Save(device); err != nil {
				t.Fatal(err)
			}

			events := (&collector{}).watch(s, s.OnAdd, s.OnUpdate)
			events.reset()

			newKey := testKey(owner + "new")
			newPSK := testKey(owner + "newpsk")
			changed, err := s.SetKeys(device, newKey, newPSK)
			if err != nil {
				t.Fatal(err)
			}
			if changed.PublicKey != newKey || changed.PresharedKey != newPSK {
				t.Errorf("the returned device still has the old keys: %+v", changed)
			}

			stored, err := s.Get(owner, "laptop")
			if err != nil {
				t.Fatal(err)
			}
			if stored.PublicKey != newKey || stored.PresharedKey != newPSK {
				t.Errorf("stored keys = %q/%q, want the new ones", stored.PublicKey, stored.PresharedKey)
			}
			// what a key change must not touch: everything the device is
			// known by, and everything built around it
			if stored.Address != "10.44.0.2/32" || stored.Routes != "192.168.5.0/24" || stored.ExpiresAt == nil {
				t.Errorf("the device lost something in the rotation: %+v", stored)
			}

			// the old key must not still find the device
			if _, err := s.GetByPublicKey(testKey(owner + "old")); err == nil {
				t.Error("the replaced key still names the device")
			}
			if found, err := s.GetByPublicKey(newKey); err != nil || found.Name != "laptop" {
				t.Errorf("the new key does not name the device: %+v %v", found, err)
			}

			// the replicas have to hear about it, or they keep the old peer
			if !events.reported(t, 5*time.Second, func(d *Device) bool {
				return d.Owner == owner && d.Name == "laptop" && d.PublicKey == newKey
			}) {
				t.Error("the new key was not reported")
			}
		})
	}
}

// Two devices sharing a public key share a WireGuard peer, so the second one
// to claim it has to be refused - by the unique index in SQL, and by the same
// rule in memory.
func TestSetKeysRefusesAKeyAnotherDeviceUses(t *testing.T) {
	backends := map[string]string{
		"memory":  "memory://",
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "keys-clash.db"),
	}

	for name, uri := range backends {
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			taken := testKey("taken" + name)
			seedDevices(t, s, "alice", "laptop")
			if err := s.Save(&Device{
				Owner: "bob", Name: "phone", PublicKey: taken,
				Address: "10.44.0.3/32", CreatedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			laptop, err := s.Get("alice", "laptop")
			if err != nil {
				t.Fatal(err)
			}
			before := laptop.PublicKey

			if _, err := s.SetKeys(laptop, taken, ""); err == nil {
				t.Fatal("two devices were given the same public key")
			}

			stored, err := s.Get("alice", "laptop")
			if err != nil {
				t.Fatal(err)
			}
			if stored.PublicKey != before {
				t.Errorf("the refused change went through anyway: %q", stored.PublicKey)
			}
		})
	}
}
