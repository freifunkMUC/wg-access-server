package storage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// The allocation lock is database-wide on purpose. Other test packages that
	// share the test database - running in parallel under `go test ./...` -
	// take the real lock, so this package's lock tests use their own.
	allocationLockName = "wg-access-server/ip-allocation/storage-tests"
	os.Exit(m.Run())
}

// lockBackends are the backends whose allocation lock is shared by several
// server instances. Each needs a real server, see metadataBackends.
func lockBackends() map[string]string {
	backends := map[string]string{}
	if uri := os.Getenv("WG_TEST_POSTGRES_URI"); uri != "" {
		backends["postgres"] = uri
	}
	if uri := os.Getenv("WG_TEST_MYSQL_URI"); uri != "" {
		backends["mysql"] = uri
	}
	return backends
}

func openLockStorage(t *testing.T, uri string) *SQLStorage {
	t.Helper()
	s, err := NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	t.Cleanup(func() { _ = s.Close() })
	return s.(*SQLStorage)
}

// heldDatabaseLocks counts allocation locks currently held in the database.
func heldDatabaseLocks(t *testing.T, s *SQLStorage) int {
	t.Helper()
	db, err := s.sqlDB()
	require.NoError(t, err)
	var n int
	switch s.sqlType {
	case "postgres":
		// a bigint advisory key is split into classid (high) and objid (low)
		rows, err := db.Query("SELECT classid::bigint, objid::bigint FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1")
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var high, low uint64
			require.NoError(t, rows.Scan(&high, &low))
			if high<<32|low == uint64(lockKey(allocationLockName)) {
				n++
			}
		}
		require.NoError(t, rows.Err())
	case "mysql":
		var owner *int64
		require.NoError(t, db.QueryRow("SELECT IS_USED_LOCK(?)", allocationLockName).Scan(&owner))
		if owner != nil {
			n = 1
		}
	}
	return n
}

func TestAllocationLockSerializesWithinProcess(t *testing.T) {
	uris := map[string]string{
		"memory":  "memory://",
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "lock.db"),
	}
	for name, uri := range lockBackends() {
		uris[name] = uri
	}
	for name, uri := range uris {
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			require.NoError(t, err)
			require.NoError(t, s.Open())
			defer s.Close()
			assertSerialized(t, s, s)
		})
	}
}

// Two storage instances stand in for two replicas: separate connection pools
// and separate in-process mutexes, one shared database.
func TestAllocationLockSerializesAcrossInstances(t *testing.T) {
	for name, uri := range lockBackends() {
		t.Run(name, func(t *testing.T) {
			a, b := openLockStorage(t, uri), openLockStorage(t, uri)
			assertSerialized(t, a, b)
			require.Zero(t, heldDatabaseLocks(t, a), "no lock may outlive WithAllocationLock")
		})
	}
}

func assertSerialized(t *testing.T, a, b Storage) {
	t.Helper()
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, s.WithAllocationLock(func() error {
				now := inside.Add(1)
				for {
					prev := maxInside.Load()
					if now <= prev || maxInside.CompareAndSwap(prev, now) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				inside.Add(-1)
				return nil
			}))
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), maxInside.Load(), "more than one caller was inside the lock at once")
}

func TestAllocationLockTimesOut(t *testing.T) {
	for name, uri := range lockBackends() {
		t.Run(name, func(t *testing.T) {
			holder, waiter := openLockStorage(t, uri), openLockStorage(t, uri)

			acquired, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- holder.WithAllocationLock(func() error {
					close(acquired)
					<-release
					return nil
				})
			}()
			<-acquired

			previous := allocationLockTimeout
			allocationLockTimeout = 2 * time.Second
			defer func() { allocationLockTimeout = previous }()

			began := time.Now()
			ran := false
			err := waiter.WithAllocationLock(func() error { ran = true; return nil })
			require.Error(t, err, "the waiter must give up instead of hanging")
			require.False(t, ran)
			require.Contains(t, err.Error(), "IP allocation lock")
			require.Less(t, time.Since(began), 10*time.Second)

			close(release)
			require.NoError(t, <-done)

			// once the holder is done the waiter gets through, so the failed
			// attempt did not leave a lock behind in its pool
			require.NoError(t, waiter.WithAllocationLock(func() error { return nil }))
			require.Zero(t, heldDatabaseLocks(t, holder))
		})
	}
}

const lockHolderEnv = "WG_TEST_LOCK_HOLDER_URI"

// A replica that dies while holding the lock must not block device creation
// on the others: the database releases the lock when the session ends.
func TestAllocationLockSurvivesCrashedHolder(t *testing.T) {
	for name, uri := range lockBackends() {
		t.Run(name, func(t *testing.T) {
			observer := openLockStorage(t, uri)

			holder := exec.Command(os.Args[0], "-test.run=^TestAllocationLockHolder$")
			holder.Env = append(os.Environ(), lockHolderEnv+"="+uri)
			stdout, err := holder.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, holder.Start())
			defer func() { _ = holder.Process.Kill(); _ = holder.Wait() }()

			// wait for the subprocess to report that it holds the lock
			buf := make([]byte, 4096)
			var out strings.Builder
			deadline := time.Now().Add(30 * time.Second)
			for !strings.Contains(out.String(), "LOCK HELD") {
				require.True(t, time.Now().Before(deadline), "holder never took the lock: %s", out.String())
				n, readErr := stdout.Read(buf)
				out.Write(buf[:n])
				require.NoError(t, readErr, "holder output so far: %s", out.String())
			}
			require.Equal(t, 1, heldDatabaseLocks(t, observer))

			// kill -9: no deferred unlock runs, only the dropped connection
			require.NoError(t, holder.Process.Kill())
			_ = holder.Wait()

			began := time.Now()
			require.NoError(t, observer.WithAllocationLock(func() error { return nil }))
			require.Less(t, time.Since(began), 10*time.Second, "the crashed holder's lock should be gone quickly")
		})
	}
}

// TestAllocationLockHolder takes the lock and never lets go. It only runs as a
// subprocess of TestAllocationLockSurvivesCrashedHolder.
func TestAllocationLockHolder(t *testing.T) {
	uri := os.Getenv(lockHolderEnv)
	if uri == "" {
		t.Skip("only runs as a subprocess of TestAllocationLockSurvivesCrashedHolder")
	}
	s := openLockStorage(t, uri)
	_ = s.WithAllocationLock(func() error {
		_, _ = os.Stdout.WriteString("LOCK HELD\n")
		select {}
	})
}
