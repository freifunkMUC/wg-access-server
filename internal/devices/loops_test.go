package devices

import (
	"context"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// waitFor runs fn in the background and reports whether it returned in time.
func returnsWithin(t *testing.T, timeout time.Duration, fn func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// The loops used to sleep forever, so a shutdown left them running against a
// storage backend that was about to be closed.
func TestMetadataLoopStopsWhenTheContextIsCancelled(t *testing.T) {
	previous := metadataSyncInterval
	metadataSyncInterval = time.Millisecond
	t.Cleanup(func() { metadataSyncInterval = previous })

	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if !returnsWithin(t, time.Second, func() { metadataLoop(ctx, manager) }) {
		t.Error("metadataLoop kept running after its context was cancelled")
	}
}

func TestInactiveLoopStopsWhenTheContextIsCancelled(t *testing.T) {
	previous := inactiveCheckInterval
	inactiveCheckInterval = time.Millisecond
	t.Cleanup(func() { inactiveCheckInterval = previous })

	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if !returnsWithin(t, time.Second, func() { inactiveLoop(ctx, manager, time.Hour) }) {
		t.Error("inactiveLoop kept running after its context was cancelled")
	}
}

// StartSync must hand the context to the loops it starts.
func TestStartSyncStopsItsLoops(t *testing.T) {
	previous := metadataSyncInterval
	metadataSyncInterval = time.Millisecond
	t.Cleanup(func() { metadataSyncInterval = previous })

	wg := &fakeWgInterface{}
	manager := New(wg, storage.NewMemoryStorage(), "10.44.0.0/24", "")
	ctx, cancel := context.WithCancel(context.Background())

	if err := manager.StartSync(ctx, true, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()

	// once stopped, the loop must not read the interface any more
	time.Sleep(10 * time.Millisecond)
	before := wg.listCalls()
	time.Sleep(20 * time.Millisecond)
	if after := wg.listCalls(); after != before {
		t.Errorf("ListPeers was called %d more times after the shutdown", after-before)
	}
}
