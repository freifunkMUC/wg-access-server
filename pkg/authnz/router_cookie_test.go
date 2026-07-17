package authnz

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
)

const sessionCookieName = "auth-session"

// newBasicAuthMiddleware builds an AuthMiddleware with a single basic auth
// provider so we can drive a real login through the router and inspect the
// resulting Set-Cookie header.
func newBasicAuthMiddleware(t *testing.T, username, password string) *AuthMiddleware {
	t.Helper()
	hash := sha1.Sum([]byte(password))
	htpasswdEntry := fmt.Sprintf("%s:{SHA}%s", username, base64.StdEncoding.EncodeToString(hash[:]))
	m, err := New(authconfig.AuthConfig{
		ProviderConfig: authconfig.ProviderConfig{
			Basic: &authconfig.BasicAuthConfig{
				Users: []string{htpasswdEntry},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	return m
}

// findSessionCookie returns the session cookie from a recorded response.
func findSessionCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("no %q cookie found in response; Set-Cookie headers: %v", sessionCookieName, rr.Result().Header.Values("Set-Cookie"))
	return nil
}

func TestSessionCookieAttributes(t *testing.T) {
	m := newBasicAuthMiddleware(t, "admin", "s3cret")

	// log in via the basic auth provider so a session cookie gets set
	req := httptest.NewRequest("POST", "/signin/0", nil)
	req.SetBasicAuth("admin", "s3cret")
	rr := httptest.NewRecorder()
	m.Middleware(http.NotFoundHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected successful login to redirect (307), got %d", rr.Code)
	}

	cookie := findSessionCookie(t, rr)

	if !cookie.HttpOnly {
		t.Error("session cookie is missing the HttpOnly attribute")
	}
	if !cookie.Secure {
		t.Error("session cookie is missing the Secure attribute")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want SameSite=Lax (%v)", cookie.SameSite, http.SameSiteLaxMode)
	}
	if cookie.Path != "/" {
		t.Errorf("session cookie Path = %q, want %q", cookie.Path, "/")
	}
	if want := 86400 * 30; cookie.MaxAge != want {
		t.Errorf("session cookie Max-Age = %d, want %d", cookie.MaxAge, want)
	}
}

// TestSignoutStillExpiresSessionCookie guards the assumption documented in
// New(): ClearSession relies on mutating the session's MaxAge to -1, which
// must keep working with the explicitly configured store options.
func TestSignoutStillExpiresSessionCookie(t *testing.T) {
	m := newBasicAuthMiddleware(t, "admin", "s3cret")

	req := httptest.NewRequest("GET", "/signout", nil)
	rr := httptest.NewRecorder()
	m.Middleware(http.NotFoundHandler()).ServeHTTP(rr, req)

	cookie := findSessionCookie(t, rr)
	if cookie.MaxAge >= 0 {
		t.Errorf("signout session cookie Max-Age = %d, want < 0 (deletion)", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Error("signout session cookie is missing the HttpOnly attribute")
	}
}
