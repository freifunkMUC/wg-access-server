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

// collector records the devices a watcher reports.
type collector struct {
	mu      sync.Mutex
	devices []*Device
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

func (c *collector) waitFor(t *testing.T, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, name := range c.names() {
			if name == want {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
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

			updates := &collector{}
			s.OnUpdate(updates.record)

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

			if !updates.waitFor(t, "work laptop", 5*time.Second) {
				t.Errorf("no update event for the renamed device, got %q", updates.names())
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
			updates := &collector{}
			s.OnUpdate(updates.record)

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
			if got := updates.names(); len(got) != 0 {
				t.Errorf("the metadata write produced %d update events (%q), want none", len(got), got)
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
	second.OnUpdate(updates.record)

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

	if !updates.waitFor(t, "work laptop", 5*time.Second) {
		t.Errorf("the other replica never heard about the rename, got %q", updates.names())
	}
}
