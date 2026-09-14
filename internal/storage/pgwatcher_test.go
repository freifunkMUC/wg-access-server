package storage

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/pg-events/pkg/pgevents"
	"github.com/stretchr/testify/require"
)

const pgWatcherTestOwner = "pgwatcher-test-"

func openPgStorage(t *testing.T) (*SQLStorage, *PgWatcher) {
	t.Helper()
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}
	s, err := NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	sql := s.(*SQLStorage)
	t.Cleanup(func() {
		if devices, err := sql.List(""); err == nil {
			for _, d := range devices {
				if strings.HasPrefix(d.Owner, pgWatcherTestOwner) {
					_ = sql.Delete(d)
				}
			}
		}
		_ = sql.Close()
	})
	return sql, sql.Watcher.(*PgWatcher)
}

// ownActions records the actions of events for this test's devices only; other
// test packages write to the same table at the same time.
func ownActions(w *PgWatcher, owner string) func() []string {
	var mu sync.Mutex
	var actions []string
	w.OnEvent(func(e *pgevents.TableEvent) {
		var d Device
		if json.Unmarshal([]byte(e.Data), &d) == nil && d.Owner == owner {
			mu.Lock()
			actions = append(actions, e.Action)
			mu.Unlock()
		}
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), actions...)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		require.True(t, time.Now().Before(deadline), "timed out waiting for %s", what)
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPgWatcherIgnoresMetadataUpdates(t *testing.T) {
	s, w := openPgStorage(t)
	owner := pgWatcherTestOwner + "updates"
	actions := ownActions(w, owner)

	device := &Device{Owner: owner, Name: "phone", PublicKey: "pgwatcher-updates-key", Address: "10.77.0.2/32"}
	require.NoError(t, s.Save(device))
	require.NoError(t, s.RecordMetadata([]MetadataUpdate{{PublicKey: device.PublicKey, ReceiveBytes: 1}}))
	require.NoError(t, s.RecordMetadata([]MetadataUpdate{{PublicKey: device.PublicKey, TransmitBytes: 1}}))
	require.NoError(t, s.Delete(device))

	eventually(t, "insert and delete", func() bool { return len(actions()) >= 2 })
	time.Sleep(300 * time.Millisecond) // room for a stray UPDATE event
	require.Equal(t, []string{"INSERT", "DELETE"}, actions())
}

// Databases of existing installations carry the old trigger that also fires on
// UPDATE. Opening the storage must replace it, or the change does nothing there.
func TestPgWatcherReplacesTriggerOfOlderVersions(t *testing.T) {
	s, _ := openPgStorage(t)
	table := s.db.NewScope(&Device{}).TableName()
	// what pg-events v0.4.x installed
	require.NoError(t, s.db.Exec("DROP TRIGGER IF EXISTS "+table+"_events ON "+table).Error)
	require.NoError(t, s.db.Exec("CREATE TRIGGER "+table+"_events AFTER INSERT OR UPDATE OR DELETE ON "+table+" FOR EACH ROW EXECUTE PROCEDURE pgevents_notify_event()").Error)
	require.NoError(t, s.Close())

	s, w := openPgStorage(t)
	owner := pgWatcherTestOwner + "upgrade"
	actions := ownActions(w, owner)
	device := &Device{Owner: owner, Name: "laptop", PublicKey: "pgwatcher-upgrade-key", Address: "10.77.0.3/32"}
	require.NoError(t, s.Save(device))
	require.NoError(t, s.RecordMetadata([]MetadataUpdate{{PublicKey: device.PublicKey, ReceiveBytes: 5}}))
	require.NoError(t, s.Delete(device))

	eventually(t, "insert and delete", func() bool { return len(actions()) >= 2 })
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, []string{"INSERT", "DELETE"}, actions())
}

// A device row too large for a notification arrives without its data. It must
// neither be dropped silently nor break the insert: the watcher resynchronizes.
func TestPgWatcherResyncsOnTruncatedEvent(t *testing.T) {
	s, w := openPgStorage(t)

	var mu sync.Mutex
	resyncs, adds := 0, 0
	w.OnAdd(func(d *Device) {
		if strings.HasPrefix(d.Owner, pgWatcherTestOwner) {
			mu.Lock()
			adds++
			mu.Unlock()
		}
	})
	w.OnReconnect(func() {
		mu.Lock()
		resyncs++
		mu.Unlock()
	})

	device := &Device{
		Owner:     pgWatcherTestOwner + "truncated",
		OwnerName: strings.Repeat("a very long display name ", 400), // ~10 KB
		Name:      "tablet", PublicKey: "pgwatcher-truncated-key", Address: "10.77.0.4/32",
	}
	require.NoError(t, s.Save(device), "a large row must still be insertable")

	eventually(t, "a resync", func() bool { mu.Lock(); defer mu.Unlock(); return resyncs >= 1 })
	mu.Lock()
	defer mu.Unlock()
	require.Zero(t, adds, "an event without data cannot be applied as an add")
}
