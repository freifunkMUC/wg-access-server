package services

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

func tokenService(t *testing.T) (*TokenService, *apitokens.Manager) {
	t.Helper()
	tokens := apitokens.New(storage.NewMemoryStorage(), nil)
	return &TokenService{Tokens: tokens, Enabled: true}, tokens
}

// tokenContext is a request authenticated with an API token rather than a
// browser session.
func tokenContext(subject string, tokenID string) context.Context {
	return authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{
		Identity: &authsession.Identity{Provider: "simple", Subject: subject},
		APIToken: tokenID,
	})
}

func createToken(t *testing.T, service *TokenService, ctx context.Context, name string) *proto.CreateTokenRes {
	t.Helper()
	res, err := service.CreateToken(ctx, connect.NewRequest(&proto.CreateTokenReq{Name: name}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

func TestCreateAndListTokens(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()
	service, tokens := tokenService(t)

	expires := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	res, err := service.CreateToken(userContext("alice", false), connect.NewRequest(&proto.CreateTokenReq{
		Name: "backup", ExpiresAt: timestamppb.New(expires),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.Secret == "" {
		t.Fatal("no secret in the response")
	}
	if got := res.Msg.Token.ExpiresAt.AsTime(); !got.Equal(expires) {
		t.Errorf("expires at %v, want %v", got, expires)
	}
	if _, _, err := tokens.Authenticate(res.Msg.Secret); err != nil {
		t.Errorf("the returned secret does not work: %v", err)
	}

	entries := auditEntries(hook, "api_token.create")
	if len(entries) != 1 || entries[0].Data["token"] != res.Msg.Token.Id {
		t.Errorf("audit entries = %v, want one for the token", entries)
	}

	createToken(t, service, userContext("bob", false), "bob's")

	list, err := service.ListTokens(userContext("alice", false), connect.NewRequest(&proto.ListTokensReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.Items) != 1 || list.Msg.Items[0].Name != "backup" {
		t.Errorf("alice sees %v, want only her own token", list.Msg.Items)
	}
	if list.Msg.Items[0].OwnerName != "alice" {
		t.Errorf("owner name = %q, want alice", list.Msg.Items[0].OwnerName)
	}
}

func TestTokenCannotCreateTokens(t *testing.T) {
	service, _ := tokenService(t)
	_, err := service.CreateToken(tokenContext("alice", "abc"), connect.NewRequest(&proto.CreateTokenReq{Name: "child"}))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v", code, connect.CodePermissionDenied)
	}
}

func TestTokenValidationReachesTheClient(t *testing.T) {
	service, _ := tokenService(t)
	_, err := service.CreateToken(userContext("alice", false), connect.NewRequest(&proto.CreateTokenReq{Name: ""}))
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want %v", code, connect.CodeInvalidArgument)
	}
}

func TestTokensDisabled(t *testing.T) {
	service, _ := tokenService(t)
	service.Enabled = false
	_, err := service.ListTokens(userContext("alice", false), connect.NewRequest(&proto.ListTokensReq{}))
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %v, want %v", code, connect.CodeFailedPrecondition)
	}
}

func TestListAllTokensIsForAdmins(t *testing.T) {
	service, _ := tokenService(t)
	createToken(t, service, userContext("alice", false), "a")
	createToken(t, service, userContext("bob", false), "b")

	_, err := service.ListAllTokens(userContext("alice", false), connect.NewRequest(&proto.ListAllTokensReq{}))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("non-admin: code = %v, want %v", code, connect.CodePermissionDenied)
	}

	all, err := service.ListAllTokens(userContext("admin", true), connect.NewRequest(&proto.ListAllTokensReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Msg.Items) != 2 {
		t.Errorf("admin sees %d tokens, want 2", len(all.Msg.Items))
	}
}

func TestDeleteToken(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()
	service, _ := tokenService(t)
	token := createToken(t, service, userContext("alice", false), "a").Token

	_, err := service.DeleteToken(userContext("mallory", false), connect.NewRequest(&proto.DeleteTokenReq{Id: token.Id}))
	if code := connect.CodeOf(err); code != connect.CodeNotFound {
		t.Errorf("another user: code = %v, want %v", code, connect.CodeNotFound)
	}

	if _, err := service.DeleteToken(userContext("alice", false), connect.NewRequest(&proto.DeleteTokenReq{Id: token.Id})); err != nil {
		t.Fatal(err)
	}
	if entries := auditEntries(hook, "api_token.delete"); len(entries) != 1 {
		t.Errorf("%d audit entries for the delete, want 1", len(entries))
	}
}

// Deleting a user is how an admin revokes their access. A token that
// outlived it would keep that access alive.
func TestDeletingAUserRevokesTheirTokens(t *testing.T) {
	service, tokens := tokenService(t)
	secret := createToken(t, service, userContext("alice", false), "a").Secret

	users := &UserService{
		DeviceManager: devices.New(noopWireGuardInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", ""),
		Tokens:        tokens,
	}
	if _, err := users.DeleteUser(userContext("admin", true), connect.NewRequest(&proto.DeleteUserReq{Name: "alice"})); err != nil {
		t.Fatal(err)
	}

	if _, _, err := tokens.Authenticate(secret); err == nil {
		t.Error("the token of the deleted user still works")
	}
}
