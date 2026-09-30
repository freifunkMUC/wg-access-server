package users

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A code sent twice at once must sign in only once, whether it is from the
// app or a recovery code.
func TestACodeCountsOnceWhenSentTwiceAtOnce(t *testing.T) {
	tf, _ := twoFactor(t)
	recovery := enrol(t, tf, "alice")

	user, err := tf.storage.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	// a step after the one the enrolment used
	code, err := TOTPCode(user.TotpSecret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	tf.now = func() time.Time { return time.Now().Add(30 * time.Second) }

	for name, given := range map[string]string{"app": code, "recovery": recovery[0]} {
		var accepted atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tf.Check("alice", given) {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := accepted.Load(); got != 1 {
			t.Errorf("%s code signed in %d times, want once", name, got)
		}
	}
}
