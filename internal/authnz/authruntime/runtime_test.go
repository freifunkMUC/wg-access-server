package authruntime

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

// Every provider ends up in SetSession, which is why the server learns about a
// sign-in there. A session without an identity is a provider keeping state in
// the middle of its flow - the OIDC nonce - and nobody has signed in yet.
func TestSetSessionRecordsOnlyRealSignIns(t *testing.T) {
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), websessions.New(storage.NewMemoryStorage(), time.Hour))

	var recorded []string
	runtime.OnLogin(func(identity *authsession.Identity) {
		recorded = append(recorded, identity.Subject)
	})

	state := "the state of a flow in progress"
	for _, session := range []*authsession.AuthSession{
		{State: &state},
		{Identity: &authsession.Identity{Subject: "alice", Provider: "oidc"}},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		if err := runtime.SetSession(w, r, session); err != nil {
			t.Fatal(err)
		}
	}

	if len(recorded) != 1 || recorded[0] != "alice" {
		t.Errorf("recorded %v, want alice once", recorded)
	}
}

// Nothing may depend on somebody having registered interest in sign-ins.
func TestSetSessionWithoutARecorder(t *testing.T) {
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), websessions.New(storage.NewMemoryStorage(), time.Hour))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	if err := runtime.SetSession(w, r, &authsession.AuthSession{
		Identity: &authsession.Identity{Subject: "alice"},
	}); err != nil {
		t.Fatal(err)
	}
}

// A refused sign-in is not a sign-in: no session, and nothing recorded.
func TestSetSessionRefused(t *testing.T) {
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")), websessions.New(storage.NewMemoryStorage(), time.Hour))

	recorded := 0
	runtime.OnLogin(func(*authsession.Identity) { recorded++ })
	runtime.OnLoginCheck(func(identity *authsession.Identity) error {
		if identity.Subject == "alice" {
			return &RefusedError{Reason: "not here"}
		}
		return nil
	})

	w := httptest.NewRecorder()
	err := runtime.SetSession(w, httptest.NewRequest("GET", "/", nil), &authsession.AuthSession{
		Identity: &authsession.Identity{Subject: "alice", Provider: "oidc"},
	})
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("SetSession = %v, want the refusal", err)
	}
	if recorded != 0 {
		t.Error("a refused sign-in was recorded")
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a refused sign-in set cookies: %v", cookies)
	}

	// the state of a flow in progress is nobody signing in, and not checked
	state := "the state of a flow in progress"
	if err := runtime.SetSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), &authsession.AuthSession{State: &state}); err != nil {
		t.Errorf("SetSession of a flow in progress = %v", err)
	}
}
