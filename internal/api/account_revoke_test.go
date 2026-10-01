package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

func (a *account) tokenCount(t *testing.T, subject string) int {
	t.Helper()
	tokens, err := a.tokens.List(subject)
	if err != nil {
		t.Fatal(err)
	}
	return len(tokens)
}

// Whoever knew the old password may have made a token with it, and a token
// outlives the sessions that end with the change.
func TestChangePasswordRevokesTheTokens(t *testing.T) {
	a := newAccount(t)
	here := a.signIn(t, "alice")
	a.signIn(t, "alice")
	a.token(t, "alice")
	a.token(t, "bob")

	if _, err := a.service.ChangePassword(here, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword,
		NewPassword:     "a-longer-new-one",
	})); err != nil {
		t.Fatal(err)
	}

	if n := a.tokenCount(t, "alice"); n != 0 {
		t.Errorf("alice has %d tokens left, want none", n)
	}
	if n := a.sessionCount(t, "alice"); n != 1 {
		t.Errorf("alice has %d sessions left, want only the one she changed it in", n)
	}
	if n := a.tokenCount(t, "bob"); n != 1 {
		t.Errorf("bob has %d tokens, want his one untouched", n)
	}
}

// Turning a second factor on is what somebody does who wants the password to
// be not enough. A session or a token made with the password alone would
// stay a way in without it.
func TestTurningCodesOnEndsWhatThePasswordAloneOpened(t *testing.T) {
	a := newAccount(t)
	here := a.signIn(t, "alice")
	a.signIn(t, "alice")
	a.token(t, "alice")
	a.signIn(t, "bob")
	a.token(t, "bob")

	start, err := a.service.StartTwoFactor(here, connect.NewRequest(&proto.StartTwoFactorReq{}))
	if err != nil {
		t.Fatal(err)
	}
	// starting asks nothing of anybody yet, so it ends nothing either
	if n := a.tokenCount(t, "alice"); n != 1 {
		t.Errorf("starting the setup revoked tokens: %d left", n)
	}

	code, err := users.TOTPCode(start.Msg.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.service.ConfirmTwoFactor(here, connect.NewRequest(&proto.ConfirmTwoFactorReq{Code: code})); err != nil {
		t.Fatal(err)
	}

	if n := a.tokenCount(t, "alice"); n != 0 {
		t.Errorf("alice has %d tokens left, want none", n)
	}
	if n := a.sessionCount(t, "alice"); n != 1 {
		t.Errorf("alice has %d sessions left, want only the one she turned it on in", n)
	}
	if a.tokenCount(t, "bob") != 1 || a.sessionCount(t, "bob") != 1 {
		t.Error("bob lost a token or a session")
	}
}

// A passkey is a second factor too: the first one turns it on.
func TestTheFirstPasskeyEndsWhatThePasswordAloneOpened(t *testing.T) {
	a := newAccount(t)
	here := a.signIn(t, "alice")
	a.signIn(t, "alice")
	a.token(t, "alice")
	a.token(t, "bob")

	registerPasskey(t, a.service, here)

	if n := a.tokenCount(t, "alice"); n != 0 {
		t.Errorf("alice has %d tokens left, want none", n)
	}
	if n := a.sessionCount(t, "alice"); n != 1 {
		t.Errorf("alice has %d sessions left, want only the one she added it in", n)
	}
	if n := a.tokenCount(t, "bob"); n != 1 {
		t.Errorf("bob has %d tokens, want his one untouched", n)
	}

	// The second passkey changes nothing about what the password alone can
	// do: that was settled with the first.
	a.signIn(t, "alice")
	a.token(t, "alice")
	registerPasskey(t, a.service, here)
	if n := a.tokenCount(t, "alice"); n != 1 {
		t.Errorf("a second passkey revoked tokens: %d left", n)
	}
	if n := a.sessionCount(t, "alice"); n != 2 {
		t.Errorf("a second passkey ended sessions: %d left", n)
	}
}

// registerPasskey does what a browser does with a passkey that needs no
// attestation: make a key, and sign the challenge into a new credential.
func registerPasskey(t *testing.T, service *UserService, ctx context.Context) {
	t.Helper()
	begin, err := service.BeginPasskey(ctx, connect.NewRequest(&proto.BeginPasskeyReq{}))
	if err != nil {
		t.Fatal(err)
	}
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(begin.Msg.GetOptions()), &options); err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	public, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: key.X.FillBytes(make([]byte, 32)),
		YCoord: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rpID := sha256.Sum256([]byte("vpn.example.com"))
	authData := append(rpID[:], 0x45)                     // user present and verified, credential attached
	authData = binary.BigEndian.AppendUint32(authData, 0) // sign count
	authData = append(authData, make([]byte, 16)...)      // no AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(append(authData, id...), public...)

	attestation, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": options.PublicKey.Challenge,
		"origin":    "https://vpn.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	encode := base64.RawURLEncoding.EncodeToString
	credential, err := json.Marshal(map[string]any{
		"id":    encode(id),
		"rawId": encode(id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    encode(clientData),
			"attestationObject": encode(attestation),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.FinishPasskey(ctx, connect.NewRequest(&proto.FinishPasskeyReq{
		Name: "laptop", Credential: string(credential),
	})); err != nil {
		t.Fatal(err)
	}
}
