package metrics

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func basicAuthServer(t *testing.T) (http.Handler, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost+2)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	return basicAuthHandler(ok, "metrics", "prometheus", string(hash)), string(hash)
}

func requestAs(h http.Handler, user, password string) int {
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.SetBasicAuth(user, password)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestBasicAuth(t *testing.T) {
	h, _ := basicAuthServer(t)
	for _, tc := range []struct {
		user, password string
		want           int
	}{
		{"prometheus", "secret", http.StatusOK},
		{"prometheus", "wrong", http.StatusUnauthorized},
		{"wrong", "secret", http.StatusUnauthorized},
	} {
		if got := requestAs(h, tc.user, tc.password); got != tc.want {
			t.Errorf("%s/%s: status %d, want %d", tc.user, tc.password, got, tc.want)
		}
	}
}

// A wrong username has to take as long as a wrong password. If it skipped
// bcrypt, the answer would come a few milliseconds early and tell an
// attacker which usernames exist.
func TestBasicAuthTakesAsLongForAWrongUsername(t *testing.T) {
	h, _ := basicAuthServer(t)
	median := func(user, password string) time.Duration {
		var runs []time.Duration
		for range 5 {
			start := time.Now()
			requestAs(h, user, password)
			runs = append(runs, time.Since(start))
		}
		sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
		return runs[len(runs)/2]
	}

	wrongPassword := median("prometheus", "wrong")
	wrongUser := median("nobody", "wrong")
	// bcrypt takes milliseconds, a string comparison microseconds: a third is
	// far from both, whatever else the machine is doing.
	if wrongUser < wrongPassword/3 {
		t.Errorf("a wrong username is answered in %s, a wrong password in %s", wrongUser, wrongPassword)
	}
}
