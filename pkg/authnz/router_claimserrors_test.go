package authnz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// signIn logs in through the basic auth provider and returns the session
// cookie, so a follow-up request arrives with a valid session.
func signIn(t *testing.T, m *AuthMiddleware) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest("POST", "/signin/0", nil)
	req.SetBasicAuth("admin", "s3cret")
	rr := httptest.NewRecorder()
	m.Middleware(http.NotFoundHandler()).ServeHTTP(rr, req)
	return findSessionCookie(t, rr)
}

func requestWithSession(t *testing.T, m *AuthMiddleware, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	return rr
}

// A user whose account has no access is signed in already, so sending them to
// the sign-in page helps nobody - they get a 403 that says so.
func TestNotAuthorizedIsAnswered(t *testing.T) {
	plain := newBasicAuthMiddleware(t, "admin", "s3cret")
	cookie := signIn(t, plain)

	m, err := New(authconfig.AuthConfig{
		ProviderConfig: plain.config.ProviderConfig,
		SessionStore:   plain.config.SessionStore,
	}, func(*authsession.Identity) error {
		return &LoginError{msg: "no access", code: NotAuthorized}
	})
	if err != nil {
		t.Fatal(err)
	}
	m.runtime = plain.runtime

	rr := requestWithSession(t, m, cookie)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if location := rr.Header().Get("Location"); location != "" {
		t.Errorf("response carries Location %q: a 403 is not a redirect", location)
	}
	if body := rr.Body.String(); !strings.Contains(body, "not allowed") {
		t.Errorf("body %q does not explain the refusal", body)
	}
}

// Anything else sends the user to the sign-in page - with a status a browser
// actually follows. A redirect with 401 leaves the user on a blank page.
func TestOtherClaimsErrorsRedirectToSignIn(t *testing.T) {
	plain := newBasicAuthMiddleware(t, "admin", "s3cret")
	cookie := signIn(t, plain)

	m, err := New(authconfig.AuthConfig{
		ProviderConfig: plain.config.ProviderConfig,
		SessionStore:   plain.config.SessionStore,
	}, func(*authsession.Identity) error {
		return &LoginError{msg: "not logged in", code: NotAuthenticated}
	})
	if err != nil {
		t.Fatal(err)
	}
	m.runtime = plain.runtime

	rr := requestWithSession(t, m, cookie)

	if rr.Code < 300 || rr.Code >= 400 {
		t.Errorf("status = %d, want a 3xx a browser follows", rr.Code)
	}
	if location := rr.Header().Get("Location"); location != "/signin" {
		t.Errorf("Location = %q, want /signin", location)
	}
}
