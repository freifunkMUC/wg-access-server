package authconfig

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

// fakeTwoFactor gives the listed subjects a second factor.
type fakeTwoFactor map[string]bool

func (f fakeTwoFactor) Enabled(subject string) bool      { return f[subject] }
func (f fakeTwoFactor) CodesEnabled(subject string) bool { return f[subject] }
func (f fakeTwoFactor) Check(string, string) bool        { return false }

func basicAuthHandler(t *testing.T, twoFactor fakeTwoFactor) http.HandlerFunc {
	t.Helper()
	config := &BasicAuthConfig{Users: []string{
		"alice:" + testHash(t, "s3cret"),
		"bob:" + testHash(t, "s3cret"),
	}}
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), testSessions())
	runtime.UseTwoFactor(twoFactor)
	return basicAuthLogin(config, runtime, newLoginThrottle())
}

// signedIn says whether the response finished a sign-in: a session cookie and
// the way to the web UI.
func signedIn(rr *httptest.ResponseRecorder) bool {
	if rr.Code < 300 || rr.Code >= 400 || rr.Header().Get("Location") != "/" {
		return false
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "auth-session" && cookie.Value != "" && cookie.MaxAge >= 0 {
			return true
		}
	}
	return false
}

// Basic auth has nowhere to ask for a second factor, so the password alone
// must not sign in somebody who set one up.
func TestBasicAuthRefusesAccountsWithASecondFactor(t *testing.T) {
	handler := basicAuthHandler(t, fakeTwoFactor{"alice": true})

	challenge := httptest.NewRequest(http.MethodGet, "/signin/0", nil)
	challenge.SetBasicAuth("alice", "s3cret")
	rr := httptest.NewRecorder()
	handler(rr, challenge)
	if signedIn(rr) {
		t.Fatal("the basic auth challenge signed in an account with a second factor")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("challenge answered with %d, want %d", rr.Code, http.StatusForbidden)
	}

	form := url.Values{"username": {"alice"}, "password": {"s3cret"}}
	post := httptest.NewRequest(http.MethodPost, "/signin/0", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler(rr, post)
	if signedIn(rr) {
		t.Fatal("the basic auth form signed in an account with a second factor")
	}

	// somebody without a second factor still signs in with the password
	challenge = httptest.NewRequest(http.MethodGet, "/signin/0", nil)
	challenge.SetBasicAuth("bob", "s3cret")
	rr = httptest.NewRecorder()
	handler(rr, challenge)
	if !signedIn(rr) {
		t.Fatalf("bob was not signed in: %d %v", rr.Code, rr.Header())
	}
}
