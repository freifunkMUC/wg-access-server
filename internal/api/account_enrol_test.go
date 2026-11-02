package api

import (
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// A session is not the password. Whoever holds one - a browser left signed in,
// a stolen cookie - must not be able to turn a second factor on: that ends the
// owner's other sessions and tokens, and leaves the owner locked out of an
// account whose second factor they do not have.
func TestEnrollingASecondFactorNeedsThePassword(t *testing.T) {
	a := newAccount(t)
	owner := a.signIn(t, "alice")
	stolen := a.signIn(t, "alice")
	a.token(t, "alice")

	untouched := func(what string) {
		t.Helper()
		if a.service.TwoFactor.Enabled("alice") || a.service.Passkeys.Has("alice") {
			t.Errorf("%s: a second factor was turned on", what)
		}
		if n := a.sessionCount(t, "alice"); n != 2 {
			t.Errorf("%s: alice has %d sessions, want both", what, n)
		}
		if n := a.tokenCount(t, "alice"); n != 1 {
			t.Errorf("%s: alice has %d tokens, want her one", what, n)
		}
	}

	// the authenticator app: the attacker can start it and has the secret,
	// and a right code does not make up for the password
	start, err := a.service.StartTwoFactor(stolen, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.service.ConfirmTwoFactor(stolen, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code}))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("ConfirmTwoFactor without the password = %v, want permission denied", err)
	}
	untouched("code from an app, no password")

	// the passkey: a credential the browser made for the challenge is
	// not enough either
	credential := passkeyCredential(t, a.service, stolen)
	_, err = a.service.FinishPasskey(stolen, connect.NewRequest(&proto.FinishPasskeyReq{
		Name: "attacker", Credential: credential,
	}))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("FinishPasskey without the password = %v, want permission denied", err)
	}
	untouched("passkey, no password")

	// the owner, with the password, can - the refusals above used up neither
	// the pending code nor the challenge
	if _, err := a.service.ConfirmTwoFactor(owner, connect.NewRequest(&proto.ConfirmTwoFactorReq{
		Code: code, Password: configuredPassword,
	})); err != nil {
		t.Errorf("ConfirmTwoFactor with the password: %v", err)
	}
}

// A wrong password is refused the way Disable refuses it, and counts towards
// the limit on wrong ones.
func TestEnrollingASecondFactorWithTheWrongPassword(t *testing.T) {
	a := newAccount(t)
	here := a.signIn(t, "alice")

	start, err := a.service.StartTwoFactor(here, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.service.ConfirmTwoFactor(here, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code, Password: "not-the-one"}))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("ConfirmTwoFactor with a wrong password = %v, want permission denied", err)
	}

	credential := passkeyCredential(t, a.service, here)
	_, err = a.service.FinishPasskey(here, connect.NewRequest(&proto.FinishPasskeyReq{
		Name: "laptop", Credential: credential, Password: "not-the-one",
	}))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("FinishPasskey with a wrong password = %v, want permission denied", err)
	}
	if a.service.TwoFactor.Enabled("alice") || a.service.Passkeys.Has("alice") {
		t.Error("a second factor was turned on with a wrong password")
	}

	// the refusal came before the challenge was used: the same answer
	// finishes the registration once the password is right
	if _, err := a.service.FinishPasskey(here, connect.NewRequest(&proto.FinishPasskeyReq{
		Name: "laptop", Credential: credential, Password: configuredPassword,
	})); err != nil {
		t.Errorf("FinishPasskey with the password after a wrong one: %v", err)
	}

	// the password check is the shared one: enough wrong ones lock it
	var last error
	for range 12 {
		_, last = a.service.ConfirmTwoFactor(here, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code, Password: "not-the-one"}))
	}
	if got := connect.CodeOf(last); got != connect.CodeResourceExhausted {
		t.Errorf("after many wrong passwords = %v, want resource exhausted", last)
	}
}
