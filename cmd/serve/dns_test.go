package serve

import (
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/dnsproxy"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// testKey is a public key in the form the server expects: 32 bytes, base64.
func testKey(i int) string {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], uint64(i)+1)
	return base64.StdEncoding.EncodeToString(key[:])
}

// TestZoneUpdaterCoalesces covers what the updater is for: an import that
// adds many devices must not rebuild the zone once per device.
func TestZoneUpdaterCoalesces(t *testing.T) {
	var mu sync.Mutex
	rebuilds := 0
	running := make(chan struct{})
	release := make(chan struct{})

	updater := newZoneUpdater(func() {
		mu.Lock()
		rebuilds++
		first := rebuilds == 1
		mu.Unlock()
		if first {
			// hold the first rebuild while the changes pile up
			close(running)
			<-release
		}
	})
	defer updater.stop()

	updater.notify(nil)
	<-running
	for range 100 {
		updater.notify(nil)
	}
	close(release)

	// the 100 changes during the first rebuild are worth one more
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		count := rebuilds
		mu.Unlock()
		if count >= 2 {
			if count > 3 {
				t.Fatalf("rebuilt the zone %d times for 101 changes", count)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the zone was rebuilt %d times, expected a second rebuild", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestZoneUpdaterNotifyDoesNotBlock makes sure a storage event is never held
// up by a rebuild - the event reaches us while the device creation holds the
// allocation lock.
func TestZoneUpdaterNotifyDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	updater := newZoneUpdater(func() { <-release })
	// stop waits for the rebuild in flight, so let that one finish first
	defer updater.stop()
	defer close(release)

	updater.notify(nil) // starts the blocking rebuild
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			updater.notify(nil)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("notify blocked while a rebuild was running")
	}
}

// TestZoneUpdaterStopsRebuilding makes sure nothing is left running, and that
// a change arriving after the stop is harmless.
func TestZoneUpdaterStopsRebuilding(t *testing.T) {
	var mu sync.Mutex
	rebuilds := 0
	updater := newZoneUpdater(func() {
		mu.Lock()
		rebuilds++
		mu.Unlock()
	})

	updater.notify(nil)
	updater.stop()

	mu.Lock()
	before := rebuilds
	mu.Unlock()

	updater.notify(nil) // a device deleted while the server shuts down
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if rebuilds != before {
		t.Errorf("the zone was rebuilt %d times after the stop", rebuilds-before)
	}
}

// TestZoneUpdaterFollowsDeviceChanges wires the updater to storage the way
// the server does and checks that the zone ends up matching the devices,
// whichever way they changed.
func TestZoneUpdaterFollowsDeviceChanges(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	manager := devices.New(wgembed.NewNoOpInterface(), s, "10.44.0.0/24", "")
	serverIP := netip.MustParseAddr("10.44.0.1")

	var mu sync.Mutex
	var zone dnsproxy.Zone
	updater := newZoneUpdater(func() {
		built := generateZone(manager, []netip.Addr{serverIP})
		mu.Lock()
		zone = built
		mu.Unlock()
	})
	defer updater.stop()
	s.OnAdd(updater.notify)
	s.OnUpdate(updater.notify)
	s.OnDelete(updater.notify)

	// waitFor gives the rebuild its moment - it happens in the background now
	waitFor := func(what string, ok func(dnsproxy.Zone) bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			current := zone
			mu.Unlock()
			if ok(current) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the zone never %s: %v", what, current)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	has := func(owner, name string) func(dnsproxy.Zone) bool {
		return func(z dnsproxy.Zone) bool {
			_, found := z[dnsproxy.ZoneKey{Owner: owner, Name: name}]
			return found
		}
	}

	identity := &authsession.Identity{Provider: "simple", Subject: "alice", Name: "alice"}
	if _, err := manager.AddDevice(identity, "laptop", testKey(1), "", false, "", ""); err != nil {
		t.Fatal(err)
	}
	waitFor("learned the new device", has("alice", "laptop"))

	if _, err := manager.RenameDevice("alice", "laptop", "notebook"); err != nil {
		t.Fatal(err)
	}
	waitFor("learned the new name", func(z dnsproxy.Zone) bool {
		return has("alice", "notebook")(z) && !has("alice", "laptop")(z)
	})

	if err := manager.DeleteDevice("alice", "notebook"); err != nil {
		t.Fatal(err)
	}
	waitFor("forgot the deleted device", func(z dnsproxy.Zone) bool { return !has("alice", "notebook")(z) })
}
