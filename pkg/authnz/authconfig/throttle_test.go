package authconfig

import (
	"sync"
	"testing"
	"time"
)

// recordSleeps replaces the throttle's sleep with one that records the
// requested delays instead of waiting, and restores it afterwards.
func recordSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	slept := []time.Duration{}
	previous := sleep
	sleep = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		slept = append(slept, d)
	}
	t.Cleanup(func() { sleep = previous })
	return &slept
}

func TestDelayGrowsWithEveryFailure(t *testing.T) {
	throttle := newLoginThrottle()

	if got := throttle.delay("alice"); got != 0 {
		t.Errorf("first attempt is delayed by %s, want no delay", got)
	}

	want := loginThrottleBase
	for attempt := 1; attempt <= 4; attempt++ {
		throttle.recordFailure("alice")
		if got := throttle.delay("alice"); got != want {
			t.Errorf("after %d failures the delay is %s, want %s", attempt, got, want)
		}
		want *= 2
	}
}

func TestDelayIsCapped(t *testing.T) {
	throttle := newLoginThrottle()
	for i := 0; i < 50; i++ {
		throttle.recordFailure("alice")
	}

	if got := throttle.delay("alice"); got != loginThrottleMax {
		t.Errorf("delay = %s, want the cap %s", got, loginThrottleMax)
	}
}

// Someone who mistypes their password and then gets it right must not stay
// slowed down.
func TestSuccessClearsTheDelay(t *testing.T) {
	throttle := newLoginThrottle()
	throttle.recordFailure("alice")
	throttle.recordFailure("alice")

	throttle.recordSuccess("alice")

	if got := throttle.delay("alice"); got != 0 {
		t.Errorf("delay after a successful login is %s, want none", got)
	}
}

func TestFailuresOfOneUserDoNotDelayAnother(t *testing.T) {
	throttle := newLoginThrottle()
	for i := 0; i < 5; i++ {
		throttle.recordFailure("alice")
	}

	if got := throttle.delay("bob"); got != 0 {
		t.Errorf("bob is delayed by %s because of alice's failures", got)
	}
}

// The counter is forgotten after a while, so a user is not still being slowed
// down hours after a typo.
func TestFailuresExpire(t *testing.T) {
	previous := loginThrottleReset
	loginThrottleReset = time.Millisecond
	t.Cleanup(func() { loginThrottleReset = previous })

	throttle := newLoginThrottle()
	throttle.recordFailure("alice")
	time.Sleep(5 * time.Millisecond)

	if got := throttle.delay("alice"); got != 0 {
		t.Errorf("delay = %s after the reset window, want none", got)
	}
}

// Usernames come from whoever is knocking, so the number of tracked entries
// must be bounded.
func TestTrackedUsernamesAreBounded(t *testing.T) {
	previous := loginThrottleSize
	loginThrottleSize = 4
	t.Cleanup(func() { loginThrottleSize = previous })

	throttle := newLoginThrottle()
	for _, username := range []string{"a", "b", "c", "d", "e", "f"} {
		throttle.recordFailure(username)
	}

	if got := throttle.cache.Len(); got > 4 {
		t.Errorf("throttle tracks %d usernames, want at most 4", got)
	}
}

func TestWaitSleepsForTheDelay(t *testing.T) {
	slept := recordSleeps(t)
	throttle := newLoginThrottle()

	throttle.wait("alice")
	if len(*slept) != 0 {
		t.Errorf("waited %v without a previous failure", *slept)
	}

	throttle.recordFailure("alice")
	throttle.wait("alice")
	if len(*slept) != 1 || (*slept)[0] != loginThrottleBase {
		t.Errorf("waits = %v, want one wait of %s", *slept, loginThrottleBase)
	}
}
