package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// Basic auth cannot ask for a second factor, so somebody signed in with it
// must not be able to set one up and believe they are protected.
func TestNoSecondFactorForBasicAuth(t *testing.T) {
	service, _ := twoFactorService(t)
	service.Passkeys = &users.Passkeys{}

	identity := &authsession.Identity{Subject: "alice", Provider: "basic", Name: "alice"}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})

	_, err := service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("StartTwoFactor = %v, want failed precondition", err)
	}
	_, err = service.BeginPasskey(ctx, connect.NewRequest(&proto.BeginPasskeyReq{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("BeginPasskey = %v, want failed precondition", err)
	}
}
