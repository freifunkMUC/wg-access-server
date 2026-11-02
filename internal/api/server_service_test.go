package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

func infoFor(t *testing.T, identity *authsession.Identity) *proto.InfoRes {
	t.Helper()
	cfg := &config.AppConfig{}
	cfg.VPN.CIDR = "10.44.0.0/24"
	service := &ServerService{Config: cfg, Wg: noopWireGuardInterface{}}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})

	res, err := service.Info(ctx, connect.NewRequest(&proto.InfoReq{}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

// The account menu names who is signed in and how; the web UI cannot know
// either without the server telling it.
func TestInfoCarriesTheIdentity(t *testing.T) {
	info := infoFor(t, &authsession.Identity{Subject: "alice", Provider: "example-oidc", Name: "Alice Example"})

	if info.Subject != "alice" || info.UserDisplayName != "Alice Example" || info.UserProvider != "example-oidc" {
		t.Errorf("subject %q, display name %q, provider %q: want alice, Alice Example, example-oidc",
			info.Subject, info.UserDisplayName, info.UserProvider)
	}
}

// A provider that gives no name leaves the field empty; the UI falls back to
// the subject.
func TestInfoLeavesAMissingDisplayNameEmpty(t *testing.T) {
	info := infoFor(t, &authsession.Identity{Subject: "bob", Provider: "simple"})

	if info.UserDisplayName != "" || info.Subject != "bob" {
		t.Errorf("display name %q, subject %q: want empty and bob", info.UserDisplayName, info.Subject)
	}
}
