package storage

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testKey builds a valid WireGuard public key (32 bytes, base64) from a seed.
// Tests share the database with the tests of other packages, and those hand
// every device's key to a WireGuard interface - junk keys make them fail.
func testKey(seed string) string {
	var key [32]byte
	copy(key[:], seed)
	return base64.StdEncoding.EncodeToString(key[:])
}

// collector records what a watcher reports. A change arrives in one of two
// shapes: the in-process backends - memory, SQLite, MySQL - hand over the
// device itself, while Postgres notifies without the row (see PgWatcher) and a
// replica only learns that it has to read the devices again. Counting both
// keeps a test as strict as it was: a backend that carries devices cannot
// resynchronize, and the other way round.
type collector struct {
	mu      sync.Mutex
	devices []*Device
	resyncs int
}

// watch records both shapes of a change: register is OnUpdate or OnDelete.
func (c *collector) watch(s Storage, register func(Callback)) *collector {
	register(c.record)
	s.OnReconnect(c.recordResync)
	return c
}

func (c *collector) recordResync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resyncs++
}

// reported waits until the change arrived - as a device the test recognizes,
// or as a request to read the devices again.
func (c *collector) reported(t *testing.T, timeout time.Duration, matches func(*Device) bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, device := range c.devices {
			if matches(device) {
				c.mu.Unlock()
				return true
			}
		}
		resynced := c.resyncs > 0
		c.mu.Unlock()
		if resynced {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// changes is how many changes were reported, in either shape.
func (c *collector) changes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.devices) + c.resyncs
}

func (c *collector) record(device *Device) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = append(c.devices, device)
}

func (c *collector) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.devices))
	for _, device := range c.devices {
		names = append(names, device.Name)
	}
	return names
}

// Renaming a device has to reach whoever keeps a copy of the names - the
// authoritative DNS zone - on every backend.
func TestRenameEmitsAnUpdate(t *testing.T) {
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "rename.db"),
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
			// registered first, so it runs after the cleanup that deletes the
			// devices - a deferred Close would run before every t.Cleanup
			t.Cleanup(func() { _ = s.Close() })

			updates := (&collector{}).watch(s, s.OnUpdate)

			device := &Device{
				Owner: "rename-events-" + name, Name: "laptop",
				PublicKey: testKey("rename-events-" + name), Address: "10.44.0.2/32", CreatedAt: time.Now(),
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

			if _, err := s.Rename(device, "work laptop"); err != nil {
				t.Fatal(err)
			}

			if !updates.reported(t, 5*time.Second, func(d *Device) bool { return d.Name == "work laptop" }) {
				t.Errorf("the rename was not reported, got %q", updates.names())
			}
		})
	}
}

// The metadata sync writes every active device every 30 seconds on every
// replica. If those writes produced events, a busy server would do nothing
// but rebuild zones.
func TestMetadataWritesEmitNoUpdate(t *testing.T) {
	backends := map[string]string{
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "metadata.db"),
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

			device := &Device{
				Owner: "metadata-events-" + name, Name: "laptop",
				PublicKey: testKey("metadata-events-" + name), Address: "10.44.0.2/32", CreatedAt: time.Now(),
			}
			t.Cleanup(func() { _ = s.Delete(device) })
			if err := s.Save(device); err != nil {
				t.Fatal(err)
			}

			// subscribe only now, so the insert is not counted
			updates := (&collector{}).watch(s, s.OnUpdate)

			handshake := time.Now()
			if err := s.RecordMetadata([]MetadataUpdate{{
				PublicKey:    device.PublicKey,
				ReceiveBytes: 1000, TransmitBytes: 2000,
				Connection: &PeerConnection{Endpoint: "198.51.100.7", LastHandshakeTime: handshake},
			}}); err != nil {
				t.Fatal(err)
			}

			// give an event that should not exist the time to show up
			time.Sleep(500 * time.Millisecond)
			if got := updates.changes(); got != 0 {
				t.Errorf("the metadata write produced %d change(s) (%q), want none", got, updates.names())
			}
		})
	}
}

// The point of the database trigger: a rename on one replica has to reach the
// others, because each of them keeps its own copy of the DNS zone.
func TestRenameReachesAnotherReplica(t *testing.T) {
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}

	open := func() Storage {
		s, err := NewStorage(uri)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Open(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}

	first, second := open(), open()

	updates := &collector{}
	updates.watch(second, second.OnUpdate)

	device := &Device{
		Owner: "replica-rename", Name: "laptop",
		PublicKey: testKey("replica-rename"), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	}
	t.Cleanup(func() {
		devices, _ := first.List(device.Owner)
		for _, d := range devices {
			_ = first.Delete(d)
		}
	})
	if err := first.Save(device); err != nil {
		t.Fatal(err)
	}

	if _, err := first.Rename(device, "work laptop"); err != nil {
		t.Fatal(err)
	}

	if !updates.reported(t, 5*time.Second, func(d *Device) bool { return d.Name == "work laptop" }) {
		t.Errorf("the other replica never heard about the rename, got %q", updates.names())
	}
}
