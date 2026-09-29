package storage

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/pg-events/pkg/pgevents"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const pgWatcherTestOwner = "pgwatcher-test-"

// freshPostgres returns a database of this test's own, or "" when there is no
// server to create it on.
//
// A test that counts the changes a backend reports needs one: a Postgres
// notification carries no row, so an event cannot be attributed to the device
// it is about - and every test in this package, as well as the other packages,
// writes to the same server at the same time.
func freshPostgres(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		return ""
	}
	return createDatabase(t, "pgx", uri, fmt.Sprintf("wgtest_events_%d", time.Now().UnixNano()))
}

func pgWatcherDatabase(t *testing.T) string {
	t.Helper()
	uri := freshPostgres(t)
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}
	return uri
}

func openPgStorage(t *testing.T) (*SQLStorage, *PgWatcher) {
	t.Helper()
	return openPgStorageAt(t, pgWatcherDatabase(t))
}

func openPgStorageAt(t *testing.T, uri string) (*SQLStorage, *PgWatcher) {
	t.Helper()
	s, err := NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	sql := s.(*SQLStorage)
	t.Cleanup(func() { _ = sql.Close() })
	return sql, sql.Watcher.(*PgWatcher)
}

// actions records what the events reported, in order. The database belongs to
// the test, so every event on the channel is one it caused.
func actionsOf(w *PgWatcher) func() []string {
	var mu sync.Mutex
	var actions []string
	w.OnEvent(func(e *pgevents.TableEvent) {
		mu.Lock()
		actions = append(actions, e.Action)
		mu.Unlock()
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
	actions := actionsOf(w)

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
	uri := pgWatcherDatabase(t)
	s, _ := openPgStorageAt(t, uri)
	table, err := deviceTable(s.db)
	require.NoError(t, err)
	// what pg-events v0.4.x installed
	require.NoError(t, s.db.Exec("DROP TRIGGER IF EXISTS "+table+"_events ON "+table).Error)
	require.NoError(t, s.db.Exec("CREATE TRIGGER "+table+"_events AFTER INSERT OR UPDATE OR DELETE ON "+table+" FOR EACH ROW EXECUTE PROCEDURE pgevents_notify_event()").Error)
	require.NoError(t, s.Close())

	s, w := openPgStorageAt(t, uri)
	owner := pgWatcherTestOwner + "upgrade"
	actions := actionsOf(w)
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

// A notification reaches every connection that listens on the channel, and
// Postgres applies no table privileges to it: a user who may connect to this
// database but may not read the devices would see every one of them as it is
// written. The row must not be in there.
func TestPgWatcherNotificationsCarryNoDeviceRow(t *testing.T) {
	uri := pgWatcherDatabase(t)
	s, _ := openPgStorageAt(t, uri)

	// a connection of our own, listening like any other client on that
	// database could
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer func() { _ = conn.Close(context.Background()) }()
	_, err = conn.Exec(ctx, `LISTEN "pgevents_event"`)
	require.NoError(t, err)

	device := &Device{
		Owner: pgWatcherTestOwner + "payload", OwnerName: "Alice Example",
		OwnerEmail: "alice@example.com", Name: "laptop",
		PublicKey: "pgwatcher-payload-public-key", PresharedKey: "pgwatcher-payload-preshared-key",
		Address: "10.77.0.5/32",
	}
	require.NoError(t, s.Save(device))
	_, err = s.SetAccess(device, true, nil)
	require.NoError(t, err)

	secrets := []string{
		device.PublicKey, device.PresharedKey, device.Owner,
		device.OwnerName, device.OwnerEmail, device.Address,
	}

	// the insert and the access change, both of which reach every listener
	for _, want := range []string{"INSERT", "UPDATE"} {
		waitCtx, cancelWait := context.WithTimeout(ctx, 10*time.Second)
		notification, err := conn.WaitForNotification(waitCtx)
		cancelWait()
		require.NoError(t, err, "no %s notification arrived", want)

		require.Contains(t, notification.Payload, want)
		for _, secret := range secrets {
			require.NotContains(t, notification.Payload, secret,
				"the notification carries the device: %s", notification.Payload)
		}
		require.Contains(t, notification.Payload, `"truncated" : true`,
			"the notification does not say that the row is missing: %s", notification.Payload)
	}
}
