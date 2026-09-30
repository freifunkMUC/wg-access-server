package users

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Guessing the password through an account's own actions stops after a few
// wrong ones, even for the right password.
func TestWrongPasswordsAreLimited(t *testing.T) {
	p, _ := passwords(t, entry(t, "right"))

	for i := 0; i < maxWrongPasswords; i++ {
		if err := p.Verify("alice", "wrong"); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("wrong password %d: %v, want ErrWrongPassword", i+1, err)
		}
	}
	if err := p.Verify("alice", "right"); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("right password after too many wrong ones: %v, want ErrTooManyAttempts", err)
	}

	// the limit ends
	later := time.Now().Add(wrongPasswordsFor + time.Second)
	p.now = func() time.Time { return later }
	if err := p.Verify("alice", "right"); err != nil {
		t.Fatalf("right password after the limit ended: %v", err)
	}
}

// The right password clears the wrong ones before it.
func TestRightPasswordClearsTheLimit(t *testing.T) {
	p, _ := passwords(t, entry(t, "right"))

	for i := 0; i < maxWrongPasswords-1; i++ {
		_ = p.Verify("alice", "wrong")
	}
	if err := p.Verify("alice", "right"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxWrongPasswords-1; i++ {
		_ = p.Verify("alice", "wrong")
	}
	if err := p.Verify("alice", "right"); err != nil {
		t.Fatalf("the earlier wrong passwords were still counted: %v", err)
	}
}

// Passwords sent in parallel do not get past the limit.
func TestPasswordLimitHoldsForParallelGuesses(t *testing.T) {
	p, _ := passwords(t, entry(t, "right"))

	var checked atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Verify("alice", "wrong"); errors.Is(err, ErrWrongPassword) {
				checked.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := checked.Load(); int(got) != maxWrongPasswords {
		t.Errorf("passwords checked = %d, want %d", got, maxWrongPasswords)
	}
}
