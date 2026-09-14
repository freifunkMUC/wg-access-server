package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"hash/fnv"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// allocationLockTimeout bounds how long device creation waits for another
// replica to finish. A var so tests can shorten it.
var allocationLockTimeout = 30 * time.Second

// allocationLockName names the lock in MySQL and derives the Postgres key.
// A var so tests can use their own lock (see TestMain).
var allocationLockName = "wg-access-server/ip-allocation"

// allocationLockKey is the Postgres advisory lock key. Advisory locks are
// shared by the whole database, so derive the key from a name specific to
// this application rather than picking a small number that might collide.
var allocationLockKey = lockKey(allocationLockName)

func lockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}

// databaseLock acquires and releases a session-level lock on one connection.
type databaseLock struct {
	acquire func(ctx context.Context, conn *sql.Conn) error
	release func(ctx context.Context, conn *sql.Conn) error
}

var databaseLocks = map[string]databaseLock{
	"postgres": {
		acquire: func(ctx context.Context, conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", allocationLockKey)
			return err
		},
		release: func(ctx context.Context, conn *sql.Conn) error {
			var released bool
			if err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", allocationLockKey).Scan(&released); err != nil {
				return err
			}
			if !released {
				return errors.New("the lock was not held by this session")
			}
			return nil
		},
	},
	"mysql": {
		acquire: func(ctx context.Context, conn *sql.Conn) error {
			// GET_LOCK waits by itself, so hand it the time left on the context.
			// It takes whole seconds; round up so a short remainder does not
			// become 0, which makes GET_LOCK give up immediately.
			remaining := allocationLockTimeout
			if deadline, ok := ctx.Deadline(); ok {
				remaining = time.Until(deadline)
			}
			seconds := int(math.Ceil(remaining.Seconds()))
			var acquired sql.NullInt64
			if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", allocationLockName, seconds).Scan(&acquired); err != nil {
				return err
			}
			if !acquired.Valid || acquired.Int64 != 1 {
				return errors.New("timed out waiting for the lock")
			}
			return nil
		},
		release: func(ctx context.Context, conn *sql.Conn) error {
			var released sql.NullInt64
			if err := conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", allocationLockName).Scan(&released); err != nil {
				return err
			}
			if !released.Valid || released.Int64 != 1 {
				return errors.New("the lock was not held by this session")
			}
			return nil
		},
	},
}

// WithAllocationLock serializes device creation. Within the process a mutex
// does that; for Postgres and MySQL a database lock additionally makes it hold
// across every replica that shares the database. SQLite is a single-instance
// backend, so the mutex alone suffices there.
//
// The mutex is taken first, so a busy replica keeps a single connection
// waiting on the database lock instead of one per concurrent request.
func (s *SQLStorage) WithAllocationLock(fn func() error) error {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()

	lock, distributed := databaseLocks[s.sqlType]
	if !distributed {
		return fn()
	}

	ctx, cancel := context.WithTimeout(context.Background(), allocationLockTimeout)
	defer cancel()

	// Session-level locks belong to one database connection. database/sql
	// hands out an arbitrary pooled connection per statement, so reserve one
	// for the lock's whole lifetime; otherwise the unlock could run elsewhere.
	conn, err := s.db.DB().Conn(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to reserve a database connection for the IP allocation lock")
	}

	if err := lock.acquire(ctx, conn); err != nil {
		// Whether the lock was taken is unknown after an error (e.g. a timeout
		// racing the grant), so never return this session to the pool.
		discardConn(conn)
		return errors.Wrap(err, "failed to acquire the IP allocation lock")
	}

	defer func() {
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), allocationLockTimeout)
		defer cancelRelease()
		if err := lock.release(releaseCtx, conn); err != nil {
			logrus.Warn(errors.Wrap(err, "failed to release the IP allocation lock - closing its connection instead"))
			discardConn(conn)
			return
		}
		_ = conn.Close()
	}()

	return fn()
}

// discardConn closes the session behind conn instead of returning it to the
// pool. Ending the session releases every lock it may still hold; handing it
// back would let whoever gets that connection next inherit the lock and block
// all device creation.
func discardConn(conn *sql.Conn) {
	// database/sql closes a connection whose Raw callback reports ErrBadConn
	// ("Don't reuse bad connections" in putConn).
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}
