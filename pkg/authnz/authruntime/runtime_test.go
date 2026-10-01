package authruntime

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// A refused sign-in is not a sign-in: no session cookie.
func TestSetSessionRefused(t *testing.T) {
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
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
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a refused sign-in set cookies: %v", cookies)
	}

	// the state of a flow in progress is nobody signing in, and not checked
	state := "the state of a flow in progress"
	if err := runtime.SetSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), &authsession.AuthSession{State: &state}); err != nil {
		t.Errorf("SetSession of a flow in progress = %v", err)
	}
	if err := runtime.SetSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), &authsession.AuthSession{
		Identity: &authsession.Identity{Subject: "bob", Provider: "oidc"},
	}); err != nil {
		t.Errorf("SetSession of somebody who is let in = %v", err)
	}
}
