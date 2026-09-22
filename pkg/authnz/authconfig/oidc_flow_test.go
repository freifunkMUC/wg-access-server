package authconfig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// fakeIDP is a minimal OIDC identity provider serving the discovery document,
// a JWKS endpoint and a token endpoint that issues RS256-signed ID tokens.
type fakeIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	// tokenNonce is the nonce claim embedded in the next issued ID token
	tokenNonce string
	// extraClaims are merged into the next issued ID token
	extraClaims map[string]interface{}
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &fakeIDP{key: key, clientID: "test-client"}

	handler := http.NewServeMux()
	idp.server = httptest.NewServer(handler)
	t.Cleanup(idp.server.Close)

	handler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/auth",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/keys",
			"userinfo_endpoint":                     idp.server.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	handler.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "test-key",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	handler.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]interface{}{
			"iss":   idp.server.URL,
			"aud":   idp.clientID,
			"sub":   "test-subject",
			"email": "user@example.com",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"nonce": idp.tokenNonce,
		}
		for name, value := range idp.extraClaims {
			claims[name] = value
		}
		idToken := idp.signIDToken(t, claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	return idp
}

func (idp *fakeIDP) signIDToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, hashed[:])
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newOIDCFlow(t *testing.T) (*fakeIDP, *authruntime.Provider, *authruntime.ProviderRuntime, *mux.Router) {
	t.Helper()
	return newOIDCFlowWith(t, func(*OIDCConfig) {})
}

// newOIDCFlowWith builds the same flow, letting a test adjust the config
// before the provider is created.
func newOIDCFlowWith(t *testing.T, adjust func(*OIDCConfig)) (*fakeIDP, *authruntime.Provider, *authruntime.ProviderRuntime, *mux.Router) {
	t.Helper()

	idp := newFakeIDP(t)
	config := &OIDCConfig{
		Name:              "test-oidc",
		Issuer:            idp.server.URL,
		ClientID:          idp.clientID,
		ClientSecret:      "test-client-secret",
		RedirectURL:       "http://wg-access-server.test/callback",
		ClaimsFromIDToken: true,
	}
	adjust(config)

	provider := config.Provider()
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("test-session-key")))
	router := mux.NewRouter()
	require.NoError(t, provider.RegisterRoutes(router, runtime))

	return idp, provider, runtime, router
}

// doLogin invokes the login handler and returns the state and nonce sent to the
// authorization endpoint along with the session cookies.
func doLogin(t *testing.T, provider *authruntime.Provider, runtime *authruntime.ProviderRuntime) (string, string, []*http.Cookie) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://wg-access-server.test/signin/0", nil)
	provider.Invoke(rec, req, runtime)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)

	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	query := location.Query()

	return query.Get("state"), query.Get("nonce"), rec.Result().Cookies()
}

func doCallback(t *testing.T, router *mux.Router, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://wg-access-server.test/callback?state="+url.QueryEscape(state)+"&code=test-code", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(rec, req)

	return rec
}

func TestOIDCLoginSendsNonce(t *testing.T) {
	_, provider, runtime, _ := newOIDCFlow(t)

	state, nonce, _ := doLogin(t, provider, runtime)

	assert.NotEmpty(t, state)
	assert.NotEmpty(t, nonce)
	assert.NotEqual(t, state, nonce)
}

func TestOIDCCallbackAcceptsMatchingNonce(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlow(t)

	state, nonce, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = nonce

	rec := doCallback(t, router, state, cookies)

	require.Equal(t, http.StatusSeeOther, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "/", rec.Header().Get("Location"))

	// the session should now hold the authenticated identity
	req := httptest.NewRequest("GET", "http://wg-access-server.test/", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	session, err := runtime.GetSession(req)
	require.NoError(t, err)
	require.NotNil(t, session.Identity)
	assert.Equal(t, "test-subject", session.Identity.Subject)
}

func TestOIDCCallbackRejectsMismatchedNonce(t *testing.T) {
	idp, provider, runtime, router := newOIDCFlow(t)

	// a valid ID token issued for a different login session must be rejected
	state, _, cookies := doLogin(t, provider, runtime)
	idp.tokenNonce = "nonce-from-another-session"

	rec := doCallback(t, router, state, cookies)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Bad nonce value in ID token")
}

func TestOIDCCallbackRejectsSessionWithoutNonce(t *testing.T) {
	idp, _, runtime, router := newOIDCFlow(t)

	// a login session that never stored a nonce must not accept any ID token
	state := "test-state"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://wg-access-server.test/signin/0", nil)
	require.NoError(t, runtime.SetSession(rec, req, &authsession.AuthSession{State: &state}))
	idp.tokenNonce = "any-nonce"

	res := doCallback(t, router, state, rec.Result().Cookies())

	require.Equal(t, http.StatusBadRequest, res.Code)
	assert.Contains(t, res.Body.String(), "No nonce associated with session")
}

func TestOIDCCallbackRejectsMismatchedState(t *testing.T) {
	_, provider, runtime, router := newOIDCFlow(t)

	_, _, cookies := doLogin(t, provider, runtime)

	rec := doCallback(t, router, "wrong-state", cookies)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Bad state value")
}
