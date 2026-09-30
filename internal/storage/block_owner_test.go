package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Blocking everything a user has is how an admin takes their access away.
// Every backend has to do it, and every one has to report the changes: that
// is how the other replicas remove the WireGuard peers.
func TestBlockForOwner(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "block.db"),
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

			owner := "block-owner-" + name
			other := "block-other-" + name
			t.Cleanup(func() {
				_, _ = s.DeleteForOwner(owner)
				_, _ = s.DeleteForOwner(other)
			})

			events := (&collector{}).watch(s, s.OnAdd, s.OnUpdate)

			seedDevices(t, s, owner, "laptop", "phone")
			seedDevices(t, s, other, "desktop")

			// one of them is blocked already, and must not be counted again
			laptop, err := s.Get(owner, "laptop")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.SetAccess(laptop, true, nil); err != nil {
				t.Fatal(err)
			}
			events.reset()

			blocked, err := s.BlockForOwner(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(blocked) != 1 || blocked[0].Name != "phone" {
				t.Errorf("reported %+v, want the one device that could still connect", blocked)
			}
			if !blocked[0].Disabled {
				t.Error("the reported device does not say it is blocked")
			}

			devices, err := s.List(owner)
			if err != nil {
				t.Fatal(err)
			}
			if len(devices) != 2 {
				t.Fatalf("%d devices left, want both of them: blocking deletes nothing", len(devices))
			}
			for _, device := range devices {
				if !device.Disabled {
					t.Errorf("device %q can still connect", device.Name)
				}
				if device.PublicKey == "" || device.Address == "" {
					t.Errorf("device %q lost its key or address: %+v", device.Name, device)
				}
			}

			left, err := s.List(other)
			if err != nil {
				t.Fatal(err)
			}
			if len(left) != 1 || left[0].Disabled {
				t.Errorf("another user's devices were touched: %+v", left)
			}

			// the change has to reach the other replicas, as the device
			// itself or as a request to read the devices again
			if !events.reported(t, 5*time.Second, func(device *Device) bool {
				return device.Owner == owner && device.Name == "phone" && device.Disabled
			}) {
				t.Error("blocking the device was not reported")
			}
		})
	}
}

func TestBlockForOwnerWithoutDevices(t *testing.T) {
	s := NewMemoryStorage()
	blocked, err := s.BlockForOwner("nobody")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 0 {
		t.Errorf("reported %d blocked devices, want none", len(blocked))
	}
}
