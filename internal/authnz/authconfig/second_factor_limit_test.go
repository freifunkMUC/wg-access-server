package authconfig

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

// codeTwoFactor accepts one code and counts how often a code was checked.
type codeTwoFactor struct {
	code   string
	checks atomic.Int32
}

func (c *codeTwoFactor) Enabled(string) bool      { return true }
func (c *codeTwoFactor) CodesEnabled(string) bool { return true }
func (c *codeTwoFactor) Check(_ string, code string) bool {
	c.checks.Add(1)
	return code == c.code
}

func secondFactorHandler(t *testing.T) (http.HandlerFunc, *loginThrottle, *codeTwoFactor) {
	t.Helper()
	recordSleeps(t)
	config := &SimpleAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), testSessions())
	twoFactor := &codeTwoFactor{code: "123456"}
	runtime.UseTwoFactor(twoFactor)
	throttle := newLoginThrottle()
	return simpleAuthPostEndpoint(config, runtime, throttle), throttle, twoFactor
}

// passwordStep signs in with the password and returns the cookie of the
// pending login.
func passwordStep(t *testing.T, handler http.HandlerFunc) []*http.Cookie {
	t.Helper()
	rr := postLogin(t, handler, "alice", "s3cret")
	if rr.Code != http.StatusOK {
		t.Fatalf("password step answered with %d, want the code page", rr.Code)
	}
	return rr.Result().Cookies()
}

func postCode(handler http.HandlerFunc, cookies []*http.Cookie, code string) int {
	form := url.Values{"code": {code}}
	req := httptest.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr.Code
}

// Six digits are only a million guesses: after a few wrong codes the second
// step is refused, even for the right code.
func TestSecondFactorIsRefusedAfterTooManyWrongCodes(t *testing.T) {
	handler, _, twoFactor := secondFactorHandler(t)
	cookies := passwordStep(t, handler)

	for i := 0; i < maxSecondFactorFailures; i++ {
		if code := postCode(handler, cookies, "000000"); code != http.StatusForbidden {
			t.Fatalf("wrong code %d answered with %d, want %d", i+1, code, http.StatusForbidden)
		}
	}
	if code := postCode(handler, cookies, "123456"); code != http.StatusTooManyRequests {
		t.Fatalf("the right code after too many wrong ones answered with %d, want %d", code, http.StatusTooManyRequests)
	}
	if got := twoFactor.checks.Load(); int(got) != maxSecondFactorFailures {
		t.Errorf("codes checked = %d, want %d", got, maxSecondFactorFailures)
	}
}

// The right password must not give the code guesses back.
func TestPasswordDoesNotResetTheSecondFactorLimit(t *testing.T) {
	handler, _, _ := secondFactorHandler(t)
	cookies := passwordStep(t, handler)
	for i := 0; i < maxSecondFactorFailures; i++ {
		postCode(handler, cookies, "000000")
	}

	cookies = passwordStep(t, handler)
	if code := postCode(handler, cookies, "123456"); code != http.StatusTooManyRequests {
		t.Fatalf("the right code after signing in with the password again answered with %d, want %d", code, http.StatusTooManyRequests)
	}
}

// Guesses sent in parallel must not get past the limit.
func TestSecondFactorLimitHoldsForParallelGuesses(t *testing.T) {
	handler, _, twoFactor := secondFactorHandler(t)
	cookies := passwordStep(t, handler)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			postCode(handler, cookies, "000000")
		}()
	}
	wg.Wait()

	if got := twoFactor.checks.Load(); int(got) > maxSecondFactorFailures {
		t.Errorf("codes checked = %d, want at most %d", got, maxSecondFactorFailures)
	}
}

// The limit ends, and the right code clears it.
func TestSecondFactorLimitEnds(t *testing.T) {
	handler, throttle, _ := secondFactorHandler(t)
	cookies := passwordStep(t, handler)
	for i := 0; i < maxSecondFactorFailures; i++ {
		postCode(handler, cookies, "000000")
	}

	throttle.mu.Lock()
	throttle.secondFactor["alice"].last = time.Now().Add(-secondFactorLockout - time.Second)
	throttle.mu.Unlock()

	cookies = passwordStep(t, handler)
	if code := postCode(handler, cookies, "123456"); code != http.StatusSeeOther {
		t.Fatalf("the right code after the lockout answered with %d, want %d", code, http.StatusSeeOther)
	}
	throttle.mu.Lock()
	defer throttle.mu.Unlock()
	if _, found := throttle.secondFactor["alice"]; found {
		t.Error("the right code did not clear the wrong answers")
	}
}

// A username longer than anybody's is neither kept by the throttle nor
// counted as an attempt.
func TestOversizedUsernameIsNotKept(t *testing.T) {
	handler, throttle := simpleAuthHandler(t, "alice", "s3cret")
	long := strings.Repeat("a", maxUsernameLength+1)

	if code := postLogin(t, handler, long, "x").Code; code != http.StatusForbidden {
		t.Fatalf("oversized username answered with %d, want %d", code, http.StatusForbidden)
	}
	if throttle.cache.Contains(long) {
		t.Error("the throttle keeps the oversized username")
	}
}
