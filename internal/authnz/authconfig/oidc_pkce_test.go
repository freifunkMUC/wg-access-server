package authconfig

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

// oidcFlowFor builds the flow against an identity provider set up first.
func oidcFlowFor(t *testing.T, idp *fakeIDP) (*authruntime.Provider, *authruntime.ProviderRuntime, *mux.Router) {
	t.Helper()
	config := &OIDCConfig{
		Name:         "test-oidc",
		Issuer:       idp.server.URL,
		ClientID:     idp.clientID,
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://wg-access-server.test/callback",
		// the fake provider has no UserInfo endpoint
		ClaimsFromIDToken: true,
	}
	provider := config.Provider()
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("test-session-key")), testSessions())
	router := mux.NewRouter()
	require.NoError(t, provider.RegisterRoutes(router, runtime))
	return provider, runtime, router
}

func loginLocation(t *testing.T, provider *authruntime.Provider, runtime *authruntime.ProviderRuntime) (url.Values, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	provider.Invoke(rec, httptest.NewRequest("GET", "http://wg-access-server.test/signin/0", nil), runtime)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return location.Query(), rec.Result().Cookies()
}

// A provider that offers PKCE gets a code challenge, and the code is only
// redeemed with the verifier that belongs to it.
func TestOIDCUsesPKCEWhenTheProviderOffersIt(t *testing.T) {
	idp := newFakeIDP(t)
	idp.pkce = true
	provider, runtime, router := oidcFlowFor(t, idp)

	query, cookies := loginLocation(t, provider, runtime)
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	challenge := query.Get("code_challenge")
	require.NotEmpty(t, challenge)
	idp.tokenNonce = query.Get("nonce")

	rec := doCallback(t, router, query.Get("state"), cookies)
	require.Equal(t, http.StatusSeeOther, rec.Code, "body: %s", rec.Body.String())

	require.NotEmpty(t, idp.verifier, "the token endpoint got no code_verifier")
	sum := sha256.Sum256([]byte(idp.verifier))
	assert.Equal(t, challenge, base64.RawURLEncoding.EncodeToString(sum[:]))
}

// A provider that does not offer PKCE is not sent anything it would not know.
func TestOIDCLeavesPKCEOutWhenTheProviderDoesNotOfferIt(t *testing.T) {
	idp := newFakeIDP(t)
	provider, runtime, router := oidcFlowFor(t, idp)

	query, cookies := loginLocation(t, provider, runtime)
	assert.Empty(t, query.Get("code_challenge"))
	idp.tokenNonce = query.Get("nonce")

	rec := doCallback(t, router, query.Get("state"), cookies)
	require.Equal(t, http.StatusSeeOther, rec.Code, "body: %s", rec.Body.String())
	assert.Empty(t, idp.verifier)
}

// A code the provider refuses is an answer, not a crash.
func TestOIDCCallbackWithARefusedCode(t *testing.T) {
	idp := newFakeIDP(t)
	idp.tokenFails = true
	provider, runtime, router := oidcFlowFor(t, idp)

	query, cookies := loginLocation(t, provider, runtime)
	var rec *httptest.ResponseRecorder
	require.NotPanics(t, func() { rec = doCallback(t, router, query.Get("state"), cookies) })
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.NotContains(t, rec.Body.String(), "invalid_grant", "the provider's answer is not the browser's business")
}
