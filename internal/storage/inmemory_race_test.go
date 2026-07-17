package storage

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestInMemoryStorageConcurrentAccess hammers a single InMemoryStorage with
// concurrent writers and readers. Before InMemoryStorage was guarded by a
// mutex this crashed with a fatal "concurrent map read and map write" runtime
// error (and is reliably flagged by `go test -race`), because the metadata
// sync goroutine calls Save while gRPC handlers read via List/Get/
// GetByPublicKey.
func TestInMemoryStorageConcurrentAccess(t *testing.T) {
	const (
		iterations = 500
		owners     = 2
		names      = 10
	)

	s := NewMemoryStorage()

	// exercise the watcher path too: EmitAdd/EmitDelete run on every
	// Save/Delete and must be safe when called from many goroutines
	var adds, deletes int64
	s.OnAdd(func(d *Device) {
		if d == nil {
			t.Error("OnAdd called with nil device")
		}
		atomic.AddInt64(&adds, 1)
	})
	s.OnDelete(func(d *Device) {
		if d == nil {
			t.Error("OnDelete called with nil device")
		}
		atomic.AddInt64(&deletes, 1)
	})

	owner := func(i int) string { return fmt.Sprintf("user%d", i%owners) }
	name := func(i int) string { return fmt.Sprintf("device%d", i%names) }
	publicKey := func(i int) string { return fmt.Sprintf("pub-%s-%s", owner(i), name(i)) }

	var wg sync.WaitGroup
	run := func(fn func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				fn(i)
			}
		}()
	}

	// writers
	for g := 0; g < 4; g++ {
		run(func(i int) {
			err := s.Save(&Device{
				Owner:     owner(i),
				Name:      name(i),
				PublicKey: publicKey(i),
				Address:   "10.44.0.2/32",
			})
			if err != nil {
				t.Errorf("Save failed: %v", err)
			}
		})
	}

	// deleters
	for g := 0; g < 2; g++ {
		run(func(i int) {
			err := s.Delete(&Device{Owner: owner(i), Name: name(i)})
			if err != nil {
				t.Errorf("Delete failed: %v", err)
			}
		})
	}

	// readers
	run(func(i int) {
		if _, err := s.List(""); err != nil {
			t.Errorf("List(\"\") failed: %v", err)
		}
	})
	run(func(i int) {
		if _, err := s.List(owner(i)); err != nil {
			t.Errorf("List(%q) failed: %v", owner(i), err)
		}
	})
	run(func(i int) {
		// Get legitimately errors when the device is currently deleted;
		// we only care that it doesn't crash or race
		_, _ = s.Get(owner(i), name(i))
	})
	run(func(i int) {
		_, _ = s.GetByPublicKey(publicKey(i))
	})

	wg.Wait()

	// sanity-check the final state: the keyspace is bounded, so the store
	// can never contain more than owners*names devices
	devices, err := s.List("")
	if err != nil {
		t.Fatalf("List after concurrent access failed: %v", err)
	}
	if len(devices) > owners*names {
		t.Fatalf("expected at most %d devices, got %d", owners*names, len(devices))
	}
	for _, d := range devices {
		if d == nil {
			t.Fatal("List returned a nil device")
		}
	}

	if got := atomic.LoadInt64(&adds); got != 4*iterations {
		t.Fatalf("expected %d OnAdd events, got %d", 4*iterations, got)
	}
	if got := atomic.LoadInt64(&deletes); got != 2*iterations {
		t.Fatalf("expected %d OnDelete events, got %d", 2*iterations, got)
	}

	// the store must still be fully usable afterwards
	sentinel := &Device{Owner: "sentinel", Name: "laptop", PublicKey: "sentinel-pub"}
	if err := s.Save(sentinel); err != nil {
		t.Fatalf("Save after concurrent access failed: %v", err)
	}
	got, err := s.Get("sentinel", "laptop")
	if err != nil {
		t.Fatalf("Get after concurrent access failed: %v", err)
	}
	if got.PublicKey != "sentinel-pub" {
		t.Fatalf("expected public key %q, got %q", "sentinel-pub", got.PublicKey)
	}
	byKey, err := s.GetByPublicKey("sentinel-pub")
	if err != nil {
		t.Fatalf("GetByPublicKey after concurrent access failed: %v", err)
	}
	if byKey.Owner != "sentinel" || byKey.Name != "laptop" {
		t.Fatalf("GetByPublicKey returned wrong device: %s/%s", byKey.Owner, byKey.Name)
	}
}
