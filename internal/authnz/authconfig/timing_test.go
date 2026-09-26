package authconfig

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A wrong username must not be answered measurably faster than a wrong
// password: the difference would tell an attacker which accounts exist.
// Both paths run one bcrypt comparison, so they land in the same order of
// magnitude - exact equality is not achievable, the cost of the stored hash
// is the operator's choice.
func TestUnknownUserCostsAboutAsMuchAsAWrongPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	users := []string{"alice:" + string(hash)}

	measure := func(username string) time.Duration {
		// one warm-up, then take the best of three to keep scheduling noise out
		checkCreds(users, username, "wrong password")
		best := time.Hour
		for i := 0; i < 3; i++ {
			start := time.Now()
			checkCreds(users, username, "wrong password")
			if elapsed := time.Since(start); elapsed < best {
				best = elapsed
			}
		}
		return best
	}

	known := measure("alice")
	unknown := measure("nobody")
	t.Logf("wrong password: %s, unknown user: %s", known, unknown)

	if unknown < known/4 {
		t.Errorf("an unknown user is answered in %s while a wrong password takes %s: the difference reveals which accounts exist", unknown, known)
	}
}
