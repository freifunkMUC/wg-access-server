package authconfig

import (
	"sync"
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

	// maxSecondFactorFailures is how many wrong codes or passkeys an account
	// gets before the second step is refused for secondFactorLockout.
	maxSecondFactorFailures = 10
	// secondFactorLockout is how long the second step stays refused, counted
	// from the last wrong answer.
	secondFactorLockout = 15 * time.Minute

	// sleep is time.Sleep, replaced in tests.
	sleep = time.Sleep
)

// maxUsernameLength is longer than any username worth configuring. A longer
// one cannot be right, and would otherwise be kept by the throttle and
// written to the log in full - a form field can hold megabytes.
const maxUsernameLength = 256

type attempts struct {
	failures int
	last     time.Time
}

// loginThrottle tracks failed login attempts per username.
type loginThrottle struct {
	// mu guards the records in cache, which the cache hands out by pointer.
	mu    sync.Mutex
	cache *lru.Cache[string, *attempts]

	// secondFactor counts wrong answers to the second step. The delay above
	// is not enough there: whoever has the password can send guesses in
	// parallel and reset the delay with the password, and six digits are only
	// a million guesses. A hard limit is fine for this step, where it cannot
	// lock anybody out who does not know the password.
	secondFactor map[string]*attempts
}

func newLoginThrottle() *loginThrottle {
	cache, err := lru.New[string, *attempts](loginThrottleSize)
	if err != nil {
		// only returned for a size <= 0, which is a constant here
		logrus.Error(err)
		return &loginThrottle{secondFactor: map[string]*attempts{}}
	}
	return &loginThrottle{cache: cache, secondFactor: map[string]*attempts{}}
}

// beginSecondFactor reserves an attempt at the second step for username, or
// says that there are none left. The attempt counts as wrong until
// secondFactorSucceeded says otherwise, so that parallel requests cannot get
// past the limit.
func (t *loginThrottle) beginSecondFactor(username string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	record, found := t.secondFactor[username]
	if !found || time.Since(record.last) > secondFactorLockout {
		record = &attempts{}
		t.secondFactor[username] = record
	}
	if record.failures >= maxSecondFactorFailures {
		return false
	}
	record.failures++
	record.last = time.Now()
	return true
}

// secondFactorSucceeded forgets the wrong answers of username.
func (t *loginThrottle) secondFactorSucceeded(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.secondFactor, username)
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
