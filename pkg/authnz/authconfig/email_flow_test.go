package authconfig

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
)

func restrictToExample(config *OIDCConfig) {
	config.EmailDomains = []string{"example.com"}
}

// Restricting by email domain is only meaningful if the address was verified
// by the provider - otherwise anyone who claims an address of the domain gets
// in.
func TestOIDCCallbackRejectsAnUnverifiedEmail(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlowWith(t, restrictToExample)
	idp.extraClaims = map[string]interface{}{"email_verified": false}

	state, nonce, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = nonce

	rec := doCallback(t, router, state, cookies)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "not verified")
}

func TestOIDCCallbackAcceptsAVerifiedEmail(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlowWith(t, restrictToExample)
	idp.extraClaims = map[string]interface{}{"email_verified": true}

	state, nonce, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = nonce

	rec := doCallback(t, router, state, cookies)

	require.Equal(t, http.StatusTemporaryRedirect, rec.Code, "body: %s", rec.Body.String())
}

// A provider that says nothing about verification must not lock everybody out.
func TestOIDCCallbackAcceptsASilentProvider(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlowWith(t, restrictToExample)

	state, nonce, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = nonce

	rec := doCallback(t, router, state, cookies)

	require.Equal(t, http.StatusTemporaryRedirect, rec.Code, "body: %s", rec.Body.String())
}

func TestOIDCLoginRequestsTheEmailScope(t *testing.T) {
	_, provider, runtime, _ := newOIDCFlowWith(t, restrictToExample)

	scopes := requestedScopes(t, provider, runtime)

	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "email", "emailDomains needs the email claim")
}

// The GitLab backend used to ask for "openid" only, so with emailDomains
// configured GitLab never sent an address and every login was refused.
func TestGitlabLoginRequestsTheEmailScope(t *testing.T) {
	idp := newFakeIDP(t)
	config := &GitlabConfig{
		Name:         "test-gitlab",
		BaseURL:      idp.server.URL,
		ClientID:     idp.clientID,
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://wg-access-server.test/callback",
		EmailDomains: []string{"example.com"},
	}

	provider := config.Provider()
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("test-session-key")))

	scopes := requestedScopes(t, provider, runtime)

	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "email")
}

func TestGitlabWithoutEmailDomainsAsksForOpenIDOnly(t *testing.T) {
	idp := newFakeIDP(t)
	config := &GitlabConfig{
		Name:         "test-gitlab",
		BaseURL:      idp.server.URL,
		ClientID:     idp.clientID,
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://wg-access-server.test/callback",
	}

	provider := config.Provider()
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("test-session-key")))

	assert.Equal(t, []string{"openid"}, requestedScopes(t, provider, runtime))
}

// requestedScopes drives the login handler and reads the scopes it sends to
// the authorization endpoint.
func requestedScopes(t *testing.T, provider *authruntime.Provider, runtime *authruntime.ProviderRuntime) []string {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://wg-access-server.test/signin/0", nil)
	provider.Invoke(rec, req, runtime)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)

	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)

	return strings.Fields(location.Query().Get("scope"))
}
