package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// account is a server with everything somebody manages about themselves, and
// alice and bob signed in to it.
type account struct {
	service  *UserService
	sessions *SessionService
	tokens   *apitokens.Manager
}

func newAccount(t *testing.T) *account {
	t.Helper()
	s := storage.NewMemoryStorage()
	for _, subject := range []string{"alice", "bob"} {
		if err := s.SaveUser(&storage.User{
			Subject: subject, Provider: "simple", Name: subject, LastLogin: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	entry := configuredEntry(t, configuredPassword)
	passwords := users.NewPasswords(s, func(string) (string, bool) {
		return entry, true
	}, func(configured string, password string) bool {
		return bcrypt.CompareHashAndPassword([]byte(configured), []byte(password)) == nil
	})
	passkeys := users.NewPasskeys(s, users.RelyingPartyFromHost("vpn.example.com", true))
	twoFactor := users.NewTwoFactor(s, passwords, "vpn.example.com")
	twoFactor.UsePasskeys(passkeys)
	sessions := websessions.New(s, time.Hour)
	tokens := apitokens.New(s, nil)

	return &account{
		service: &UserService{
			DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""),
			Passwords:     passwords,
			TwoFactor:     twoFactor,
			Passkeys:      passkeys,
			Tokens:        tokens,
			Sessions:      sessions,
		},
		sessions: &SessionService{Sessions: sessions},
		tokens:   tokens,
	}
}

func identity(subject string) *authsession.Identity {
	return &authsession.Identity{Subject: subject, Provider: "simple", Name: subject}
}

// withRequest is what the API handler adds: passkeys need the site's name.
func withRequest(ctx context.Context) context.Context {
	r := httptest.NewRequest(http.MethodPost, "https://vpn.example.com/api", nil)
	return audit.WithRemoteAddr(users.WithRequest(ctx, r), "198.51.100.7:51234")
}

// signIn opens a browser session and returns the context its requests carry.
func (a *account) signIn(t *testing.T, subject string) context.Context {
	t.Helper()
	id, err := a.service.Sessions.Create(identity(subject), httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
	if err != nil {
		t.Fatal(err)
	}
	return withRequest(authsession.SetIdentityCtx(context.Background(),
		&authsession.AuthSession{ID: id, Identity: identity(subject)}))
}

// token issues an API token and returns the context its requests carry.
func (a *account) token(t *testing.T, subject string) context.Context {
	t.Helper()
	_, token, err := a.tokens.Create(identity(subject), "script", nil)
	if err != nil {
		t.Fatal(err)
	}
	return withRequest(authsession.SetIdentityCtx(context.Background(),
		&authsession.AuthSession{Identity: identity(subject), APIToken: token.ID}))
}

func (a *account) sessionCount(t *testing.T, subject string) int {
	t.Helper()
	sessions, err := a.service.Sessions.List(subject)
	if err != nil {
		t.Fatal(err)
	}
	return len(sessions)
}

// A token is for scripts that manage devices. Whoever holds one must not be
// able to make it the account: set a second factor the owner does not have,
// take theirs away, or sign the owner out of the sessions they would notice
// it from.
func TestATokenCannotManageTheAccount(t *testing.T) {
	a := newAccount(t)
	browser := a.signIn(t, "alice")
	ctx := a.token(t, "alice")

	// something to aim at for the calls that need an id
	start, err := a.service.StartTwoFactor(browser, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := a.sessions.ListSessions(browser, connect.NewRequest(&proto.ListSessionsReq{}))
	if err != nil {
		t.Fatal(err)
	}
	session := sessions.Msg.GetItems()[0].GetId()
	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	calls := []struct {
		name string
		call func() error
	}{
		{"ChangePassword", func() error {
			_, err := a.service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
				CurrentPassword: configuredPassword, NewPassword: "a-longer-new-one",
			}))
			return err
		}},
		{"StartTwoFactor", func() error {
			_, err := a.service.StartTwoFactor(ctx, connect.NewRequest(&proto.StartTwoFactorReq{}))
			return err
		}},
		{"ConfirmTwoFactor", func() error {
			_, err := a.service.ConfirmTwoFactor(ctx, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code}))
			return err
		}},
		{"DisableTwoFactor", func() error {
			_, err := a.service.DisableTwoFactor(ctx, connect.NewRequest(&proto.DisableTwoFactorReq{Password: configuredPassword}))
			return err
		}},
		{"NewRecoveryCodes", func() error {
			_, err := a.service.NewRecoveryCodes(ctx, connect.NewRequest(&proto.NewRecoveryCodesReq{Password: configuredPassword}))
			return err
		}},
		{"BeginPasskey", func() error {
			_, err := a.service.BeginPasskey(ctx, connect.NewRequest(&proto.BeginPasskeyReq{}))
			return err
		}},
		{"FinishPasskey", func() error {
			_, err := a.service.FinishPasskey(ctx, connect.NewRequest(&proto.FinishPasskeyReq{Name: "mine", Credential: "{}"}))
			return err
		}},
		{"RenamePasskey", func() error {
			_, err := a.service.RenamePasskey(ctx, connect.NewRequest(&proto.RenamePasskeyReq{Id: "some-id", Name: "mine"}))
			return err
		}},
		{"DeletePasskey", func() error {
			_, err := a.service.DeletePasskey(ctx, connect.NewRequest(&proto.DeletePasskeyReq{Id: "some-id"}))
			return err
		}},
		{"DeleteSession", func() error {
			_, err := a.sessions.DeleteSession(ctx, connect.NewRequest(&proto.DeleteSessionReq{Id: session}))
			return err
		}},
		{"DeleteOtherSessions", func() error {
			_, err := a.sessions.DeleteOtherSessions(ctx, connect.NewRequest(&proto.DeleteOtherSessionsReq{}))
			return err
		}},
	}
	for _, c := range calls {
		// The message matters too: a wrong password is refused with the
		// same code, and that is not the refusal this is about.
		err := c.call()
		if code := connect.CodeOf(err); code != connect.CodePermissionDenied || !strings.Contains(err.Error(), "API token") {
			t.Errorf("%s with a token: %v, want it refused for being a token", c.name, err)
		}
	}

	// none of it happened
	if a.service.TwoFactor.Enabled("alice") {
		t.Error("a token turned the second factor on")
	}
	if a.sessionCount(t, "alice") != 1 {
		t.Error("a token ended a session")
	}
	if err := a.service.Passwords.Change("alice", configuredPassword, "another-one-again"); err != nil {
		t.Errorf("a token changed the password: %v", err)
	}

	// looking stays allowed: it changes nothing
	if _, err := a.sessions.ListSessions(ctx, connect.NewRequest(&proto.ListSessionsReq{})); err != nil {
		t.Errorf("ListSessions with a token: %v", err)
	}
	if _, err := a.service.ListPasskeys(ctx, connect.NewRequest(&proto.ListPasskeysReq{})); err != nil {
		t.Errorf("ListPasskeys with a token: %v", err)
	}
}
