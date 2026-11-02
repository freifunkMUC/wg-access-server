package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// adminIdentity is the admin, as the built-in provider knows them.
func adminIdentity() *authsession.Identity {
	id := identity("admin")
	id.Claims.MakeAdmin()
	return id
}

// An admin's token must not be able to strip somebody's second factor: the
// password would then be all that stands between a leaked token and the
// account.
func TestAnAdminsTokenCannotResetASecondFactor(t *testing.T) {
	a := newAccount(t)
	turnOn(t, a.service, a.signIn(t, "alice"))

	_, token, err := a.tokens.Create(adminIdentity(), "script", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withRequest(authsession.SetIdentityCtx(context.Background(),
		&authsession.AuthSession{Identity: adminIdentity(), APIToken: token.ID}))

	_, err = a.service.ResetTwoFactor(ctx, connect.NewRequest(&proto.ResetTwoFactorReq{Name: "alice"}))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied || err == nil || !strings.Contains(err.Error(), "API token") {
		t.Errorf("reset with an admin's token: %v, want it refused for being a token", err)
	}
	if !a.service.TwoFactor.Enabled("alice") {
		t.Error("an API token took the second factor away")
	}
}

// What was opened while the second factor was on is not trusted once an admin
// has removed it: the person's sessions end and their tokens are revoked.
// Nobody else's, and not the admin's own session.
func TestResettingASecondFactorEndsTheSessionsAndTokens(t *testing.T) {
	a := newAccount(t)
	turnOn(t, a.service, a.signIn(t, "alice"))

	// made after the second factor, as a signed-in person would have
	a.signIn(t, "alice")
	a.signIn(t, "alice")
	a.token(t, "alice")
	a.signIn(t, "bob")
	a.token(t, "bob")

	adminSession, err := a.service.Sessions.Create(adminIdentity(), httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx := withRequest(authsession.SetIdentityCtx(context.Background(),
		&authsession.AuthSession{ID: adminSession, Identity: adminIdentity()}))

	if _, err := a.service.ResetTwoFactor(ctx, connect.NewRequest(&proto.ResetTwoFactorReq{Name: "alice"})); err != nil {
		t.Fatal(err)
	}

	if a.service.TwoFactor.Enabled("alice") {
		t.Error("the second factor survived the reset")
	}
	if n := a.sessionCount(t, "alice"); n != 0 {
		t.Errorf("alice has %d sessions after the reset, want 0", n)
	}
	if n := a.tokenCount(t, "alice"); n != 0 {
		t.Errorf("alice has %d API tokens after the reset, want 0", n)
	}
	if n := a.sessionCount(t, "bob"); n != 1 {
		t.Errorf("bob has %d sessions, want 1: the reset reached somebody else", n)
	}
	if n := a.tokenCount(t, "bob"); n != 1 {
		t.Errorf("bob has %d API tokens, want 1: the reset reached somebody else", n)
	}
	if n := a.sessionCount(t, "admin"); n != 1 {
		t.Errorf("the admin has %d sessions, want 1: the reset ended their own", n)
	}
}
