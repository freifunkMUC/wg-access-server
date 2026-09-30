package authconfig

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

// failingSessionStorage stores everything except a session, which is what a
// sessions column too narrow for the id did on Postgres and MySQL.
type failingSessionStorage struct {
	storage.Storage
}

func (failingSessionStorage) SaveSession(*storage.Session) error {
	return errors.New("value too long for type character varying(32)")
}

func runtimeThatCannotKeepSessions() *authruntime.ProviderRuntime {
	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	broken := failingSessionStorage{storage.NewMemoryStorage()}
	return authruntime.NewProviderRuntime(store, websessions.New(broken, time.Hour))
}

// A right password whose session cannot be stored is not a wrong password,
// and saying so sends whoever is debugging it after the wrong thing: this is
// how a sessions column that could hold no session at all looked like a
// mistyped password in every deployment on Postgres and MySQL.
func TestSimpleAuthDoesNotBlameTheCredentialsForAFailedSession(t *testing.T) {
	config := &SimpleAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}
	handler := simpleAuthPostEndpoint(config, runtimeThatCannotKeepSessions(), newLoginThrottle())

	rr := postLogin(t, handler, "alice", "s3cret")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("answered with %d, want %d - the password was right", rr.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rr.Body.String(), "Invalid username or password") {
		t.Error("the right password was reported as invalid")
	}
}

func TestBasicAuthDoesNotBlameTheCredentialsForAFailedSession(t *testing.T) {
	config := &BasicAuthConfig{Users: []string{"alice:" + testHash(t, "s3cret")}}
	handler := basicAuthLogin(config, runtimeThatCannotKeepSessions(), newLoginThrottle())

	req := httptest.NewRequest(http.MethodPost, postURL, nil)
	req.SetBasicAuth("alice", "s3cret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("answered with %d, want %d - the password was right", rr.Code, http.StatusInternalServerError)
	}
}
