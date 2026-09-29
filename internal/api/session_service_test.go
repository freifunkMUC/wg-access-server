package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// sessionService returns the service and a way to sign somebody in, which
// gives back the context a request with that session would carry.
func sessionService(t *testing.T) (*SessionService, func(subject string) context.Context) {
	t.Helper()
	sessions := websessions.New(storage.NewMemoryStorage(), time.Hour)

	signIn := func(subject string) context.Context {
		identity := &authsession.Identity{Subject: subject, Provider: "simple", Name: subject}
		id, err := sessions.Create(identity, httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
		if err != nil {
			t.Fatal(err)
		}
		return authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{ID: id, Identity: identity})
	}

	return &SessionService{Sessions: sessions}, signIn
}

// Somebody sees their own sessions and which one they are looking at them
// with - that is the one they must not end by accident.
func TestListSessionsMarksTheCurrentOne(t *testing.T) {
	service, signIn := sessionService(t)
	first := signIn("alice")
	second := signIn("alice")
	signIn("bob")

	res, err := service.ListSessions(second, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}

	items := res.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("listed %d sessions, want alice's two", len(items))
	}
	current := 0
	for _, session := range items {
		if session.GetCurrent() {
			current++
		}
		if session.GetId() == "" || session.GetCreatedAt() == nil {
			t.Errorf("session = %+v, want an id and when it started", session)
		}
	}
	if current != 1 {
		t.Errorf("%d sessions are marked as the current one, want exactly one", current)
	}

	// ... and the first one is the current one when asked through it
	res, err = service.ListSessions(first, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range res.Msg.GetItems() {
		if session.GetCurrent() {
			return
		}
	}
	t.Error("no session is marked as the current one")
}

// A session of somebody else is reported as missing: an id that exists must
// not be distinguishable from one that does not.
func TestDeleteSessionOfSomebodyElse(t *testing.T) {
	service, signIn := sessionService(t)
	alice := signIn("alice")
	bob := signIn("bob")

	res, err := service.ListSessions(bob, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	bobsSession := res.Msg.GetItems()[0].GetId()

	_, err = service.DeleteSession(alice, connect.NewRequest(&proto.DeleteSessionReq{Id: bobsSession}))
	if err == nil {
		t.Fatal("somebody ended another person's session")
	}
	if code := connect.CodeOf(err); code != connect.CodeNotFound {
		t.Errorf("code = %s, want %s", code, connect.CodeNotFound)
	}

	// and it still works
	if _, err := service.ListSessions(bob, connect.NewRequest(&proto.ListSessionsReq{})); err != nil {
		t.Errorf("the session was ended after all: %v", err)
	}
}

func TestDeleteOwnSession(t *testing.T) {
	service, signIn := sessionService(t)
	alice := signIn("alice")
	other := signIn("alice")

	res, err := service.ListSessions(other, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	var notCurrent string
	for _, session := range res.Msg.GetItems() {
		if !session.GetCurrent() {
			notCurrent = session.GetId()
		}
	}

	if _, err := service.DeleteSession(other, connect.NewRequest(&proto.DeleteSessionReq{Id: notCurrent})); err != nil {
		t.Fatal(err)
	}

	// what is left is the one that did the ending
	res, err = service.ListSessions(other, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if items := res.Msg.GetItems(); len(items) != 1 || !items[0].GetCurrent() {
		t.Errorf("sessions left = %+v, want only the current one", items)
	}

	// ... and the ended one no longer names a session, which is what the
	// middleware asks before a request gets this far
	if _, err := service.Sessions.Find(authsession.CurrentSessionID(alice)); err == nil {
		t.Error("the ended session can still be found")
	}
}

// "Sign out everywhere else" is for the browser somebody is holding: it keeps
// that one and ends the rest.
func TestDeleteOtherSessions(t *testing.T) {
	service, signIn := sessionService(t)
	first := signIn("alice")
	signIn("alice")
	third := signIn("alice")
	bob := signIn("bob")

	res, err := service.DeleteOtherSessions(third, connect.NewRequest(&proto.DeleteOtherSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetEnded() != 2 {
		t.Errorf("ended %d sessions, want the two others", res.Msg.GetEnded())
	}

	res2, err := service.ListSessions(third, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if items := res2.Msg.GetItems(); len(items) != 1 || !items[0].GetCurrent() {
		t.Errorf("sessions left = %+v, want only the one that did the ending", items)
	}
	if _, err := service.Sessions.Find(authsession.CurrentSessionID(first)); err == nil {
		t.Error("another session of the same user still exists")
	}
	if _, err := service.Sessions.Find(authsession.CurrentSessionID(bob)); err != nil {
		t.Errorf("somebody else's session was ended: %v", err)
	}
}

// A request with an API token has no session to keep, and ending somebody's
// sessions from a script is not what this is for.
func TestDeleteOtherSessionsNeedsASession(t *testing.T) {
	service, _ := sessionService(t)
	ctx := userContext("alice", false)

	_, err := service.DeleteOtherSessions(ctx, connect.NewRequest(&proto.DeleteOtherSessionsReq{}))
	if err == nil {
		t.Fatal("a request without a session ended sessions")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}
}
