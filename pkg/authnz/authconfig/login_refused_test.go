package authconfig

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

const refusalReason = "This account already signs in another way here."

func refuseEverybody(runtime *authruntime.ProviderRuntime) {
	runtime.OnLoginCheck(func(identity *authsession.Identity) error {
		return &authruntime.RefusedError{Reason: refusalReason, Detail: "refused in a test"}
	})
}

// assertRefused checks that a sign-in the server refused says so, says why,
// and left no session behind.
func assertRefused(t *testing.T, rec *httptest.ResponseRecorder, runtime *authruntime.ProviderRuntime) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Errorf("answered with %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), refusalReason) {
		t.Errorf("body = %q, want the reason in it", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "refused in a test") {
		t.Error("the details for the log were shown to the browser")
	}

	req := httptest.NewRequest("GET", "http://wg-access-server.test/", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if s, err := runtime.GetSession(req); err == nil && s.Identity != nil {
		t.Errorf("a refused sign-in left a session for %q", s.Identity.Subject)
	}
}

func testUsers(t *testing.T) []string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return []string{"alice:" + string(hash)}
}

func TestSimpleAuthRefusedSignIn(t *testing.T) {
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
	refuseEverybody(runtime)

	form := url.Values{"username": {"alice"}, "password": {"s3cret"}}
	req := httptest.NewRequest(http.MethodPost, "/signin/0", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	simpleAuthPostEndpoint(&SimpleAuthConfig{Users: testUsers(t)}, runtime)(rec, req)

	assertRefused(t, rec, runtime)
}

func TestBasicAuthRefusedSignIn(t *testing.T) {
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
	refuseEverybody(runtime)

	req := httptest.NewRequest(http.MethodPost, "/signin/0", nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	basicAuthLogin(&BasicAuthConfig{Users: testUsers(t)}, runtime)(rec, req)

	assertRefused(t, rec, runtime)
}

func TestOIDCRefusedSignIn(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlow(t)
	refuseEverybody(runtime)

	state, nonce, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = nonce
	rec := doCallback(t, router, state, cookies)

	assertRefused(t, rec, runtime)
}
