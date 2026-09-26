package authconfig

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
)

// Login throttling slows down password guessing without ever locking anyone
// out. A failed attempt makes the next attempt for that username wait, and the
// wait doubles with every further failure up to a cap.
//
// A delay rather than a lockout, and keyed by username rather than by client
// address, is a deliberate choice:
//
//   - A lockout after N failures lets anyone keep the admin account locked by
//     failing to log in on purpose.
//   - The client address is not usable as a key here: wg-access-server is
//     commonly reached through a reverse proxy, where every user shares one
//     address, and trusting X-Forwarded-For would let a client pick its own
//     key and skip the throttle entirely.
//
// The throttle lives in the process, so several replicas each keep their own
// counters - an attacker spreading attempts over replicas gets the delay
// divided by their number, which still leaves password hashing (bcrypt) as the
// per-attempt cost.
var (
	// loginThrottleBase is the wait after the first failed attempt.
	loginThrottleBase = 250 * time.Millisecond
	// loginThrottleMax caps the wait, so a user who mistyped their password a
	// few times is not locked out for minutes.
	loginThrottleMax = 10 * time.Second
	// loginThrottleReset drops the counter of a username that has not been
	// tried for this long.
	loginThrottleReset = 15 * time.Minute
	// loginThrottleSize bounds how many usernames are tracked. Usernames come
	// from whoever is knocking, so the map needs a limit; the least recently
	// used entry is dropped.
	loginThrottleSize = 4096

	// sleep is time.Sleep, replaced in tests.
	sleep = time.Sleep
)

type attempts struct {
	failures int
	last     time.Time
}

// loginThrottle tracks failed login attempts per username.
type loginThrottle struct {
	cache *lru.Cache[string, *attempts]
}

func newLoginThrottle() *loginThrottle {
	cache, err := lru.New[string, *attempts](loginThrottleSize)
	if err != nil {
		// only returned for a size <= 0, which is a constant here
		logrus.Error(err)
		return &loginThrottle{}
	}
	return &loginThrottle{cache: cache}
}

// wait blocks for as long as the previous failures for this username demand.
// It is called before the credentials are checked, so a caller cannot tell
// from the timing whether the username exists.
func (t *loginThrottle) wait(username string) {
	if delay := t.delay(username); delay > 0 {
		logrus.Warnf("Delaying login attempt for user '%s' by %s after %d failed attempts", username, delay, t.failures(username))
		sleep(delay)
	}
}

func (t *loginThrottle) delay(username string) time.Duration {
	failures := t.failures(username)
	if failures == 0 {
		return 0
	}

	delay := loginThrottleBase
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= loginThrottleMax {
			return loginThrottleMax
		}
	}
	return delay
}

func (t *loginThrottle) failures(username string) int {
	if t.cache == nil {
		return 0
	}
	record, found := t.cache.Get(username)
	if !found {
		return 0
	}
	if time.Since(record.last) > loginThrottleReset {
		t.cache.Remove(username)
		return 0
	}
	return record.failures
}

func (t *loginThrottle) recordFailure(username string) {
	if t.cache == nil {
		return
	}
	record, found := t.cache.Get(username)
	if !found || time.Since(record.last) > loginThrottleReset {
		record = &attempts{}
	}
	record.failures++
	record.last = time.Now()
	t.cache.Add(username, record)
}

func (t *loginThrottle) recordSuccess(username string) {
	if t.cache == nil {
		return
	}
	t.cache.Remove(username)
}
