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

// lockKey derives the Postgres advisory lock key from a lock name. Advisory
// locks are shared by the whole database, so the key comes from a name
// specific to this application rather than a small number that might collide.
func lockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}

// databaseLock acquires and releases a named session-level lock on one
// connection.
type databaseLock struct {
	acquire func(ctx context.Context, conn *sql.Conn, name string) error
	release func(ctx context.Context, conn *sql.Conn, name string) error
}

var databaseLocks = map[string]databaseLock{
	"postgres": {
		acquire: func(ctx context.Context, conn *sql.Conn, name string) error {
			_, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockKey(name))
			return err
		},
		release: func(ctx context.Context, conn *sql.Conn, name string) error {
			var released bool
			if err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", lockKey(name)).Scan(&released); err != nil {
				return err
			}
			if !released {
				return errors.New("the lock was not held by this session")
			}
			return nil
		},
	},
	"mysql": {
		acquire: func(ctx context.Context, conn *sql.Conn, name string) error {
			// GET_LOCK waits by itself, so hand it the time left on the context.
			// It takes whole seconds; round up so a short remainder does not
			// become 0, which makes GET_LOCK give up immediately.
			remaining := allocationLockTimeout
			if deadline, ok := ctx.Deadline(); ok {
				remaining = time.Until(deadline)
			}
			seconds := int(math.Ceil(remaining.Seconds()))
			var acquired sql.NullInt64
			if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", name, seconds).Scan(&acquired); err != nil {
				return err
			}
			if !acquired.Valid || acquired.Int64 != 1 {
				return errors.New("timed out waiting for the lock")
			}
			return nil
		},
		release: func(ctx context.Context, conn *sql.Conn, name string) error {
			var released sql.NullInt64
			if err := conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", name).Scan(&released); err != nil {
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

	return s.withDatabaseLock(allocationLockName, "IP allocation lock", allocationLockTimeout, fn)
}

// withDatabaseLock runs fn while holding the named lock in the database, so
// that it holds across every replica sharing the database. SQLite is a
// single-instance backend and has no such lock; fn just runs. what names the
// lock in error messages.
func (s *SQLStorage) withDatabaseLock(name string, what string, timeout time.Duration, fn func() error) error {
	lock, distributed := databaseLocks[s.sqlType]
	if !distributed {
		return fn()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Session-level locks belong to one database connection. database/sql
	// hands out an arbitrary pooled connection per statement, so reserve one
	// for the lock's whole lifetime; otherwise the unlock could run elsewhere.
	db, err := s.sqlDB()
	if err != nil {
		return errors.Wrapf(err, "failed to reserve a database connection for the %s", what)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to reserve a database connection for the %s", what)
	}

	if err := lock.acquire(ctx, conn, name); err != nil {
		// Whether the lock was taken is unknown after an error (e.g. a timeout
		// racing the grant), so never return this session to the pool.
		discardConn(conn)
		return errors.Wrapf(err, "failed to acquire the %s", what)
	}

	defer func() {
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), allocationLockTimeout)
		defer cancelRelease()
		if err := lock.release(releaseCtx, conn, name); err != nil {
			logrus.Warn(errors.Wrapf(err, "failed to release the %s - closing its connection instead", what))
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
