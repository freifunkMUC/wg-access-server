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

// Signing in again in the same browser replaces the cookie, and with it the
// session it named: that one must not stay usable for whoever copied it.
func TestSigningInAgainEndsTheSessionTheCookieNamed(t *testing.T) {
	recordSleeps(t)
	config := &SimpleAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), testSessions())
	handler := simpleAuthPostEndpoint(config, runtime, newLoginThrottle())

	login := func(cookies []*http.Cookie) []*http.Cookie {
		form := url.Values{"username": {"alice"}, "password": {"s3cret"}}
		req := httptest.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("login answered with %d", rr.Code)
		}
		return rr.Result().Cookies()
	}
	signedIn := func(cookies []*http.Cookie) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		session, err := runtime.GetSession(req)
		return err == nil && session.Identity != nil
	}

	first := login(nil)
	if !signedIn(first) {
		t.Fatal("the first login did not sign in")
	}
	second := login(first)
	if !signedIn(second) {
		t.Fatal("the second login did not sign in")
	}
	if signedIn(first) {
		t.Error("the session of the replaced cookie still signs in")
	}
}
