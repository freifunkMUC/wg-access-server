package authruntime

import (
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

// Every provider ends up in SetSession, which is why the server learns about a
// sign-in there. A session without an identity is a provider keeping state in
// the middle of its flow - the OIDC nonce - and nobody has signed in yet.
func TestSetSessionRecordsOnlyRealSignIns(t *testing.T) {
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))

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
	runtime := NewProviderRuntime(sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef")))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	if err := runtime.SetSession(w, r, &authsession.AuthSession{
		Identity: &authsession.Identity{Subject: "alice"},
	}); err != nil {
		t.Fatal(err)
	}
}
