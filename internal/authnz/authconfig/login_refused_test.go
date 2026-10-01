package authconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
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

func TestSimpleAuthRefusedSignIn(t *testing.T) {
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), testSessions())
	refuseEverybody(runtime)
	config := &SimpleAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}

	rec := postLogin(t, simpleAuthPostEndpoint(config, runtime, newLoginThrottle()), "alice", "s3cret")

	assertRefused(t, rec, runtime)
}

func TestBasicAuthRefusedSignIn(t *testing.T) {
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), testSessions())
	refuseEverybody(runtime)
	config := &BasicAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}

	req := httptest.NewRequest(http.MethodPost, postURL, nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	basicAuthLogin(config, runtime, newLoginThrottle())(rec, req)

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

func TestGithubRefusedSignIn(t *testing.T) {
	gh := newFakeGithub(t)
	gh.orgs["ffmuc"] = "active"
	config := gh.config()
	config.Organizations = []string{"ffmuc"}
	provider, runtime, router := newGithubFlow(t, config)
	refuseEverybody(runtime)

	state, _, cookies := doLogin(t, provider, runtime)
	rec := doCallback(t, router, state, cookies)

	require.NotEqual(t, http.StatusSeeOther, rec.Code, "the refused sign-in went through")
	assertRefused(t, rec, runtime)
}
