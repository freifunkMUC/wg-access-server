package websessions

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func testManager(t *testing.T) (*Manager, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	return New(s, time.Hour), s
}

func identityOf(subject string) *authsession.Identity {
	identity := &authsession.Identity{Subject: subject, Provider: "oidc", Name: subject}
	identity.Claims.MakeAdmin()
	return identity
}

func signIn(t *testing.T, m *Manager, subject string) string {
	t.Helper()
	r := httptest.NewRequest("GET", "http://wg-access-server.test/signin", nil)
	r.Header.Set("User-Agent", "a browser")
	r.RemoteAddr = "198.51.100.7:51234"

	id, err := m.Create(identityOf(subject), r)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The point of keeping sessions: the cookie says who, the server decides
// whether that still holds.
func TestSessionCarriesTheIdentity(t *testing.T) {
	m, _ := testManager(t)
	id := signIn(t, m, "alice")

	identity, err := m.Identity(id)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "alice" || !identity.Claims.IsAdmin() {
		t.Errorf("identity = %+v, want alice with her claims", identity)
	}
}

// What is stored must not be enough to use a session: whoever reads the
// database learns which sessions exist, not how to be somebody.
func TestOnlyTheHashIsStored(t *testing.T) {
	m, s := testManager(t)
	id := signIn(t, m, "alice")

	sessions, err := s.ListSessions("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("stored %d sessions, want one", len(sessions))
	}
	stored := sessions[0]
	if strings.Contains(stored.Hash, id) || stored.Hash == id {
		t.Error("the id from the cookie is in the database")
	}
	if stored.UserAgent != "a browser" || stored.RemoteAddr != "198.51.100.7" {
		t.Errorf("session = %+v, want the browser and the address it came from", stored)
	}
}

// Signing out has to end the session, not only drop the cookie: a cookie that
// was copied elsewhere would otherwise keep working.
func TestEndStopsTheSession(t *testing.T) {
	m, _ := testManager(t)
	id := signIn(t, m, "alice")

	if err := m.End(id); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Identity(id); err == nil {
		t.Error("the session still works after signing out")
	}

	// signing out twice is what a browser does, and it is not an error
	if err := m.End(id); err != nil {
		t.Errorf("ending a session that is gone failed: %v", err)
	}
}

// Deleting somebody, or taking their access away, ends every session they
// have - not the one they happen to be using.
func TestEndAllForOwner(t *testing.T) {
	m, _ := testManager(t)
	first := signIn(t, m, "alice")
	second := signIn(t, m, "alice")
	other := signIn(t, m, "bob")

	ended, err := m.EndAllForOwner("alice")
	if err != nil {
		t.Fatal(err)
	}
	if ended != 2 {
		t.Errorf("ended %d sessions, want both of alice's", ended)
	}
	for _, id := range []string{first, second} {
		if _, err := m.Identity(id); err == nil {
			t.Error("a session of the deleted user still works")
		}
	}
	if _, err := m.Identity(other); err != nil {
		t.Errorf("somebody else's session was ended: %v", err)
	}
}

func TestExpiredSessionsDoNotWork(t *testing.T) {
	s := storage.NewMemoryStorage()
	m := New(s, time.Hour)

	id := signIn(t, m, "alice")
	m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	if _, err := m.Identity(id); err == nil {
		t.Error("a session past its lifetime still works")
	}

	// ... and they are removed rather than kept forever
	removed, err := s.DeleteExpiredSessions(m.now())
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed %d expired sessions, want 1", removed)
	}
}

// An id that names nothing, an empty one and one that was ended are the same
// answer: there is nothing to tell apart.
func TestUnknownSessions(t *testing.T) {
	m, _ := testManager(t)
	for _, id := range []string{"", "not-a-session", strings.Repeat("a", 43)} {
		if _, err := m.Identity(id); err == nil {
			t.Errorf("the id %q was accepted", id)
		}
	}
}

// The last use is recorded, but a web UI that polls must not turn every read
// into a write.
func TestLastSeenIsNotWrittenOnEveryRequest(t *testing.T) {
	s := storage.NewMemoryStorage()
	m := New(s, time.Hour)
	id := signIn(t, m, "alice")

	sessions, _ := s.ListSessions("alice")
	first := sessions[0].LastSeenAt

	if _, err := m.Identity(id); err != nil {
		t.Fatal(err)
	}
	sessions, _ = s.ListSessions("alice")
	if !sessions[0].LastSeenAt.Equal(first) {
		t.Error("a second request right away wrote the last use again")
	}

	m.now = func() time.Time { return first.Add(2 * touchInterval) }
	if _, err := m.Identity(id); err != nil {
		t.Fatal(err)
	}
	sessions, _ = s.ListSessions("alice")
	if !sessions[0].LastSeenAt.After(first) {
		t.Error("the last use was not recorded after a while")
	}
}

// The cleanup has to stop with the rest of the server, and it has to have
// removed what it found before it does.
func TestCleanupRemovesExpiredSessionsAndStops(t *testing.T) {
	s := storage.NewMemoryStorage()
	m := New(s, time.Hour)
	signIn(t, m, "alice")
	m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	// a context that is already done: one pass, then out
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		m.cleanupLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the cleanup kept running after its context was cancelled")
	}

	if sessions, err := s.ListSessions("alice"); err != nil {
		t.Fatal(err)
	} else if len(sessions) != 0 {
		t.Errorf("%d expired session(s) are still stored", len(sessions))
	}
}
