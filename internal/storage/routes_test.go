package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The networks behind a device have to reach every replica: the one holding
// the client's tunnel is the one that has to route them.
func TestSetRoutesEmitsAnUpdate(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "routes.db"),
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
				Owner: "routes-events-" + name, Name: "site",
				PublicKey: testKey("routes-events-" + name), Address: "10.44.0.2/32", CreatedAt: time.Now(),
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

			routes := "192.168.5.0/24, 2001:db8:5::/48"
			changed, err := s.SetRoutes(device, routes)
			if err != nil {
				t.Fatal(err)
			}
			if changed.Routes != routes {
				t.Errorf("returned routes = %q, want %q", changed.Routes, routes)
			}
			if allowed := changed.AllowedIPs(); len(allowed) != 3 {
				t.Errorf("allowed IPs = %v, want the address and both networks", allowed)
			}

			if !updates.reported(t, 5*time.Second, func(d *Device) bool { return d.Routes == routes }) {
				t.Error("the change of the routes was not reported")
			}

			stored, err := s.Get(device.Owner, device.Name)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Routes != routes {
				t.Errorf("stored routes = %q, want %q", stored.Routes, routes)
			}

			// and removing them has to stick, not be skipped as a zero value
			if _, err := s.SetRoutes(stored, ""); err != nil {
				t.Fatal(err)
			}
			stored, err = s.Get(device.Owner, device.Name)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Routes != "" || len(stored.RouteList()) != 0 {
				t.Errorf("stored routes = %q, want them gone", stored.Routes)
			}
		})
	}
}

// A device that is gone must not come back as a row with only routes in it.
func TestSetRoutesOnADeviceThatIsGone(t *testing.T) {
	s, err := NewStorage("sqlite3://" + filepath.Join(t.TempDir(), "gone-routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	device := &Device{
		Owner: "alice", Name: "site", PublicKey: testKey("routes-gone"),
		Address: "10.44.0.2/32", CreatedAt: time.Now(),
	}

	if _, err := s.SetRoutes(device, "192.168.5.0/24"); err == nil {
		t.Fatal("routing a network to a device that does not exist succeeded")
	}
	if devices, err := s.List(""); err != nil {
		t.Fatal(err)
	} else if len(devices) != 0 {
		t.Errorf("storage holds %d devices, want none", len(devices))
	}
}
