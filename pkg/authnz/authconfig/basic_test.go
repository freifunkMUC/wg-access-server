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
)

func basicAuthHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	config := &BasicAuthConfig{Users: []string{"bob:" + string(hash)}}
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
	return basicAuthLogin(config, runtime)
}

// signedIn reports whether the handler sent the browser on to the web UI.
func signedIn(rr *httptest.ResponseRecorder) bool {
	return rr.Code == http.StatusTemporaryRedirect && rr.Header().Get("Location") == "/"
}

// The form posts the credentials, and that is where they are read from.
func TestBasicAuthFormSignsIn(t *testing.T) {
	form := url.Values{"username": {"bob"}, "password": {"s3cret"}}
	req := httptest.NewRequest(http.MethodPost, "/signin/0", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	basicAuthHandler(t)(rr, req)
	if !signedIn(rr) {
		t.Fatalf("bob was not signed in: %d %v", rr.Code, rr.Header())
	}
}

// Credentials in the URL end up in proxy logs and the browser history, and a
// link carrying them signs whoever follows it in to somebody else's account.
func TestBasicAuthIgnoresCredentialsInTheURL(t *testing.T) {
	rr := httptest.NewRecorder()
	basicAuthHandler(t)(rr, httptest.NewRequest(http.MethodGet, "/signin/0?username=bob&password=s3cret", nil))
	if signedIn(rr) {
		t.Fatal("credentials in the URL signed in")
	}
}
