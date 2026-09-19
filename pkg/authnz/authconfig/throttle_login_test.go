package authconfig

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
)

func simpleAuthHandler(t *testing.T, username, password string) (http.HandlerFunc, *loginThrottle) {
	t.Helper()
	config := &SimpleAuthConfig{Users: []string{username + ":" + testHash(t, password)}}
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
	throttle := newLoginThrottle()
	return simpleAuthPostEndpoint(config, runtime, throttle), throttle
}

func postLogin(t *testing.T, handler http.HandlerFunc, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// Guessing passwords through the login endpoint gets slower with every wrong
// answer.
func TestSimpleAuthLoginIsThrottledAfterAFailure(t *testing.T) {
	slept := recordSleeps(t)
	handler, _ := simpleAuthHandler(t, "alice", "s3cret")

	if code := postLogin(t, handler, "alice", "wrong").Code; code != http.StatusForbidden {
		t.Fatalf("wrong password answered with %d, want %d", code, http.StatusForbidden)
	}
	if len(*slept) != 0 {
		t.Errorf("the first attempt already waited: %v", *slept)
	}

	postLogin(t, handler, "alice", "wrong-again")
	if len(*slept) != 1 || (*slept)[0] != loginThrottleBase {
		t.Errorf("waits = %v, want one wait of %s before the second attempt", *slept, loginThrottleBase)
	}
}

// The right password clears the delay, so a user who mistyped once is not
// slowed down on their next login.
func TestSimpleAuthLoginResetsAfterSuccess(t *testing.T) {
	slept := recordSleeps(t)
	handler, throttle := simpleAuthHandler(t, "alice", "s3cret")

	postLogin(t, handler, "alice", "wrong")
	postLogin(t, handler, "alice", "s3cret")

	if got := throttle.delay("alice"); got != 0 {
		t.Errorf("delay after a successful login is %s, want none", got)
	}
	// only the one wait caused by the earlier failure
	if len(*slept) != 1 {
		t.Errorf("waits = %v, want exactly one", *slept)
	}
}

// An empty form is not a password attempt and must not build up a delay.
func TestSimpleAuthEmptyFormIsNotAnAttempt(t *testing.T) {
	handler, throttle := simpleAuthHandler(t, "alice", "s3cret")

	postLogin(t, handler, "", "")

	if got := throttle.delay(""); got != 0 {
		t.Errorf("an empty form created a delay of %s", got)
	}
}
