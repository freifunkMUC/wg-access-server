package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Blocking a device has to reach every replica: the one holding the client's
// tunnel is the one that has to drop the peer, and it may not be the one the
// admin is talking to.
func TestSetAccessEmitsAnUpdate(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "access.db"),
		"postgres": os.Getenv("WG_TEST_POSTGRES_URI"),
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

			updates := (&collector{}).watch(s, s.OnUpdate)

			device := &Device{
				Owner: "access-events-" + name, Name: "laptop",
				PublicKey: testKey("access-events-" + name), Address: "10.44.0.2/32", CreatedAt: time.Now(),
			}
			t.Cleanup(func() {
				devices, _ := s.List(device.Owner)
				for _, d := range devices {
					_ = s.Delete(d)
				}
			})
			if err := s.Save(device); err != nil {
				t.Fatal(err)
			}

			expires := time.Now().Add(time.Hour).Truncate(time.Second)
			changed, err := s.SetAccess(device, true, &expires)
			if err != nil {
				t.Fatal(err)
			}
			if !changed.Disabled || changed.ExpiresAt == nil {
				t.Errorf("returned device = %+v, want it disabled and with an expiry", changed)
			}

			if !updates.reported(t, 5*time.Second, func(d *Device) bool { return d.Disabled && d.ExpiresAt != nil }) {
				t.Error("the access change was not reported")
			}

			// and it has to be what the next replica reads, not only what the
			// event carried
			stored, err := s.Get(device.Owner, device.Name)
			if err != nil {
				t.Fatal(err)
			}
			if !stored.Disabled {
				t.Error("the stored device is not disabled")
			}
			if stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(expires.UTC()) {
				t.Errorf("stored expiresAt = %v, want %v", stored.ExpiresAt, expires.UTC())
			}

			// clearing it has to stick as well - an UPDATE that skips zero
			// values would leave the expiry in place forever
			if _, err := s.SetAccess(stored, false, nil); err != nil {
				t.Fatal(err)
			}
			stored, err = s.Get(device.Owner, device.Name)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Disabled || stored.ExpiresAt != nil {
				t.Errorf("stored device = %+v, want the block and the expiry gone", stored)
			}
		})
	}
}

// A device deleted in the meantime must not come back as a row with only the
// access columns set.
func TestSetAccessOnADeviceThatIsGone(t *testing.T) {
	s, err := NewStorage("sqlite3://" + filepath.Join(t.TempDir(), "gone.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	device := &Device{
		Owner: "alice", Name: "laptop", PublicKey: testKey("access-gone"),
		Address: "10.44.0.2/32", CreatedAt: time.Now(),
	}

	if _, err := s.SetAccess(device, true, nil); err == nil {
		t.Fatal("changing the access of a device that does not exist succeeded")
	}

	if devices, err := s.List(""); err != nil {
		t.Fatal(err)
	} else if len(devices) != 0 {
		t.Errorf("storage holds %d devices, want none", len(devices))
	}
}
