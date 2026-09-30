package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

const configuredPassword = "the-configured-one"

func configuredEntry(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

// passwordService returns the service, the sessions behind it, and a way to
// sign somebody in that gives back the context their requests would carry.
func passwordService(t *testing.T) (*UserService, *websessions.Manager, func(string) context.Context) {
	t.Helper()
	s := storage.NewMemoryStorage()
	entry := configuredEntry(t, configuredPassword)

	sessions := websessions.New(s, time.Hour)
	service := &UserService{
		DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""),
		Sessions:      sessions,
		Passwords: users.NewPasswords(s, func(subject string) (string, bool) {
			if subject == "alice" {
				return entry, true
			}
			return "", false
		}, func(configured string, password string) bool {
			return bcrypt.CompareHashAndPassword([]byte(configured), []byte(password)) == nil
		}),
	}

	signIn := func(subject string) context.Context {
		identity := &authsession.Identity{Subject: subject, Provider: "simple", Name: subject}
		if err := s.SaveUser(&storage.User{
			Subject: subject, Provider: "simple", Name: subject, LastLogin: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		id, err := sessions.Create(identity, httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
		if err != nil {
			t.Fatal(err)
		}
		ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{ID: id, Identity: identity})
		return audit.WithRemoteAddr(ctx, "198.51.100.7:51234")
	}

	return service, sessions, signIn
}

func TestChangePassword(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, _, signIn := passwordService(t)
	ctx := signIn("alice")

	res, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "a-longer-new-one",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetSessionsEnded() != 0 {
		t.Errorf("ended %d sessions, want none: there were no others", res.Msg.GetSessionsEnded())
	}

	// the new password is now the password
	if err := service.Passwords.Change("alice", "a-longer-new-one", "another-one-again"); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}

	entries := auditEntries(hook, audit.UserPassword)
	if len(entries) != 1 {
		t.Fatalf("%d audit records, want one", len(entries))
	}
	// neither password belongs in the log
	for field, value := range entries[0].Data {
		if s, ok := value.(string); ok && (s == configuredPassword || s == "a-longer-new-one") {
			t.Errorf("the audit record carries a password in %q", field)
		}
	}
}

// Whoever knew the old password may be holding a session made with it.
func TestChangePasswordEndsTheOtherSessions(t *testing.T) {
	service, sessions, signIn := passwordService(t)
	elsewhere := signIn("alice")
	here := signIn("alice")
	bob := signIn("bob")

	res, err := service.ChangePassword(here, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "a-longer-new-one",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetSessionsEnded() != 1 {
		t.Errorf("ended %d sessions, want the one other", res.Msg.GetSessionsEnded())
	}

	if _, err := sessions.Find(authsession.CurrentSessionID(elsewhere)); err == nil {
		t.Error("the other session of the same user still exists")
	}
	if _, err := sessions.Find(authsession.CurrentSessionID(here)); err != nil {
		t.Error("the session that changed the password was ended")
	}
	if _, err := sessions.Find(authsession.CurrentSessionID(bob)); err != nil {
		t.Error("somebody else's session was ended")
	}
}

func TestChangePasswordNeedsTheCurrentOne(t *testing.T) {
	service, _, signIn := passwordService(t)
	ctx := signIn("alice")

	_, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: "not-it",
		NewPassword:     "a-longer-new-one",
	}))
	if err == nil {
		t.Fatal("the password changed without the current one")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}

	// ... and it is still the old one
	if err := service.Passwords.Change("alice", configuredPassword, "a-longer-new-one"); err != nil {
		t.Errorf("the password changed after all: %v", err)
	}
}

func TestChangePasswordRefusesAShortOne(t *testing.T) {
	service, _, signIn := passwordService(t)
	ctx := signIn("alice")

	_, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "short",
	}))
	if err == nil {
		t.Fatal("a short password was accepted")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %s, want %s", code, connect.CodeInvalidArgument)
	}
}

// With an identity provider the password is theirs, and this server has
// nothing to change.
func TestChangePasswordForAnIdentityProviderUser(t *testing.T) {
	service, _, _ := passwordService(t)
	identity := &authsession.Identity{Subject: "alice", Provider: "oidc", Name: "alice"}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})

	_, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "a-longer-new-one",
	}))
	if err == nil {
		t.Fatal("an identity provider's user changed a password here")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}
}

// A server with no built-in provider keeps no passwords at all.
func TestChangePasswordWithoutAnyBuiltInProvider(t *testing.T) {
	service := &UserService{DeviceManager: devices.New(noopWireGuardInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")}

	_, err := service.ChangePassword(userContext("alice", false), connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "a-longer-new-one",
	}))
	if err == nil {
		t.Fatal("a password was changed on a server that keeps none")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}
}
