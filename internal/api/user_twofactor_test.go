package api

import (
	"context"
	"strings"
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
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// twoFactorService returns the service and a context for alice, who signs in
// with the built-in provider.
func twoFactorService(t *testing.T) (*UserService, context.Context) {
	t.Helper()
	s := storage.NewMemoryStorage()
	if err := s.SaveUser(&storage.User{
		Subject: "alice", Provider: "simple", Name: "alice", LastLogin: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	entry := configuredEntry(t, configuredPassword)
	passwords := users.NewPasswords(s, func(subject string) (string, bool) {
		if subject == "alice" {
			return entry, true
		}
		return "", false
	}, func(configured string, password string) bool {
		return bcrypt.CompareHashAndPassword([]byte(configured), []byte(password)) == nil
	})

	service := &UserService{
		DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""),
		Passwords:     passwords,
		TwoFactor:     users.NewTwoFactor(s, passwords, "vpn.example.com"),
	}

	identity := &authsession.Identity{Subject: "alice", Provider: "simple", Name: "alice"}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})
	return service, audit.WithRemoteAddr(ctx, "198.51.100.7:51234")
}

// turnOn does what the UI does: start, read the secret, confirm with a code.
func turnOn(t *testing.T, service *UserService, ctx context.Context) []string {
	t.Helper()
	start, err := service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := service.ConfirmTwoFactor(ctx, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	return confirmed.Msg.GetRecoveryCodes()
}

func TestTurningTheSecondFactorOn(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, ctx := twoFactorService(t)

	start, err := service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if start.Msg.GetSecret() == "" || start.Msg.GetUri() == "" {
		t.Fatalf("start = %+v, want a secret and a URI", start.Msg)
	}
	// the URI names this server, so two accounts in one app can be told apart
	if uri := start.Msg.GetUri(); !strings.Contains(uri, "vpn.example.com") || !strings.Contains(uri, start.Msg.GetSecret()) {
		t.Errorf("uri = %q, want the issuer and the secret in it", uri)
	}
	// nothing is asked of them yet
	if service.TwoFactor.Enabled("alice") {
		t.Error("starting the setup already asks for codes")
	}

	// a wrong code does not turn it on
	if _, err := service.ConfirmTwoFactor(ctx, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: "000000"})); err == nil {
		t.Fatal("a wrong code turned the second factor on")
	} else if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %s, want %s", code, connect.CodeInvalidArgument)
	}

	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := service.ConfirmTwoFactor(ctx, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Msg.GetRecoveryCodes()) == 0 {
		t.Error("no recovery codes were handed out")
	}
	if !service.TwoFactor.Enabled("alice") {
		t.Error("the second factor is not on")
	}

	entries := auditEntries(hook, audit.UserTwoFactor)
	if len(entries) != 1 || entries[0].Data["enabled"] != true {
		t.Errorf("audit records = %+v, want one saying it was turned on", entries)
	}
	// the secret and the codes are not the log's business
	for _, value := range entries[0].Data {
		if s, ok := value.(string); ok && s == start.Msg.GetSecret() {
			t.Error("the audit record carries the secret")
		}
	}
}

func TestTurningItOffNeedsThePassword(t *testing.T) {
	service, ctx := twoFactorService(t)
	turnOn(t, service, ctx)

	_, err := service.DisableTwoFactor(ctx, connect.NewRequest(&proto.DisableTwoFactorReq{Password: "not-it"}))
	if err == nil {
		t.Fatal("the second factor was turned off without the password")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}
	if !service.TwoFactor.Enabled("alice") {
		t.Fatal("the refused attempt turned it off anyway")
	}

	if _, err := service.DisableTwoFactor(ctx, connect.NewRequest(&proto.DisableTwoFactorReq{
		Password: configuredPassword,
	})); err != nil {
		t.Fatal(err)
	}
	if service.TwoFactor.Enabled("alice") {
		t.Error("it is still on")
	}
}

// Starting again while it is on would be a way to replace somebody's second
// factor from a browser they left signed in.
func TestStartingAgainWhileItIsOn(t *testing.T) {
	service, ctx := twoFactorService(t)
	turnOn(t, service, ctx)

	_, err := service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err == nil {
		t.Fatal("a second enrolment was started while one is set up")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}
}

// An admin helps somebody whose phone is gone.
func TestAnAdminResetsSomebodysSecondFactor(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, ctx := twoFactorService(t)
	turnOn(t, service, ctx)

	// a user may not do it to somebody else
	_, err := service.ResetTwoFactor(userContext("bob", false), connect.NewRequest(&proto.ResetTwoFactorReq{Name: "alice"}))
	if err == nil {
		t.Fatal("a user reset somebody else's second factor")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}
	if !service.TwoFactor.Enabled("alice") {
		t.Fatal("the refused reset took it away")
	}

	if _, err := service.ResetTwoFactor(userContext("admin", true), connect.NewRequest(&proto.ResetTwoFactorReq{
		Name: "alice",
	})); err != nil {
		t.Fatal(err)
	}
	if service.TwoFactor.Enabled("alice") {
		t.Error("the second factor survived the reset")
	}

	entries := auditEntries(hook, audit.UserTwoFactorReset)
	if len(entries) != 1 || entries[0].Data["target_user"] != "alice" {
		t.Errorf("audit records = %+v, want one naming alice", entries)
	}

	// and there is nothing left to reset
	_, err = service.ResetTwoFactor(userContext("admin", true), connect.NewRequest(&proto.ResetTwoFactorReq{Name: "alice"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("code = %s, want %s", connect.CodeOf(err), connect.CodeNotFound)
	}
}

// With an identity provider the second factor belongs there.
func TestTwoFactorForAnIdentityProviderUser(t *testing.T) {
	service, _ := twoFactorService(t)
	identity := &authsession.Identity{Subject: "alice", Provider: "oidc", Name: "alice"}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})

	_, err := service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err == nil {
		t.Fatal("an identity provider's user set up a second factor here")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}
}

// A recovery code signs in once, which is the whole point of them.
func TestARecoveryCodeWorksOnce(t *testing.T) {
	service, ctx := twoFactorService(t)
	codes := turnOn(t, service, ctx)

	if !service.TwoFactor.Check("alice", codes[0]) {
		t.Fatal("a recovery code was refused")
	}
	if service.TwoFactor.Check("alice", codes[0]) {
		t.Error("a recovery code worked twice")
	}
}
