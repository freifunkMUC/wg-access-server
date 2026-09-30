package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// revokeService returns a user service with everything a revocation takes
// away, and the storage behind it.
func revokeService(t *testing.T, stored ...*storage.Device) (*UserService, storage.Storage, *apitokens.Manager, *websessions.Manager) {
	t.Helper()
	s := storage.NewMemoryStorage()
	for _, device := range stored {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	tokens := apitokens.New(s, nil)
	sessions := websessions.New(s, time.Hour)
	service := &UserService{
		DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""),
		Tokens:        tokens,
		Sessions:      sessions,
	}
	return service, s, tokens, sessions
}

func identityOf(subject string) *authsession.Identity {
	return &authsession.Identity{Subject: subject, Provider: "simple", Name: subject}
}

// The whole action in one go: the devices stop connecting, the tokens stop
// working and the browsers are signed out - and nothing is deleted, so the
// blocks can be lifted.
func TestRevokeAccessTakesEveryWayIn(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s, tokens, sessions := revokeService(t,
		&storage.Device{Owner: "alice", Name: "laptop", PublicKey: "key-1", Address: "10.44.0.2/32", CreatedAt: time.Now()},
		&storage.Device{Owner: "alice", Name: "phone", PublicKey: "key-2", Address: "10.44.0.3/32", CreatedAt: time.Now()},
		&storage.Device{Owner: "bob", Name: "laptop", PublicKey: "key-3", Address: "10.44.0.4/32", CreatedAt: time.Now()},
	)

	secret, _, err := tokens.Create(identityOf("alice"), "a script", nil)
	if err != nil {
		t.Fatal(err)
	}
	bobsSecret, _, err := tokens.Create(identityOf("bob"), "another script", nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.Create(identityOf("alice"), httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
	if err != nil {
		t.Fatal(err)
	}

	res, err := service.RevokeAccess(userContext("admin", true), connect.NewRequest(&proto.RevokeAccessReq{Name: "alice"}))
	if err != nil {
		t.Fatal(err)
	}

	if res.Msg.GetDevicesBlocked() != 2 || res.Msg.GetTokensDeleted() != 1 || res.Msg.GetSessionsEnded() != 1 {
		t.Errorf("revoked %+v, want two devices, one token and one session", res.Msg)
	}

	for _, name := range []string{"laptop", "phone"} {
		device, err := s.Get("alice", name)
		if err != nil {
			t.Fatal(err)
		}
		if !device.Disabled {
			t.Errorf("the device %q can still connect", name)
		}
		// nothing is deleted: the key and the address are what makes this
		// reversible without the user setting up their client anew
		if device.PublicKey == "" || device.Address == "" {
			t.Errorf("device %q lost its key or address: %+v", name, device)
		}
	}

	if _, _, err := tokens.Authenticate(secret); err == nil {
		t.Error("the API token still works")
	}
	if _, err := sessions.Identity(session); err == nil {
		t.Error("the browser session still works")
	}

	// ... and nobody else is touched
	bobsDevice, err := s.Get("bob", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if bobsDevice.Disabled {
		t.Error("somebody else's device was blocked")
	}
	if _, _, err := tokens.Authenticate(bobsSecret); err != nil {
		t.Errorf("somebody else's token was revoked: %v", err)
	}

	entries := auditEntries(hook, audit.UserRevoke)
	if len(entries) != 1 {
		t.Fatalf("%d audit records, want one", len(entries))
	}
	fields := entries[0].Data
	if fields["target_user"] != "alice" || fields["devices_blocked"] != int32(2) {
		t.Errorf("audit record = %+v, want alice and her two devices", fields)
	}
}

// Revoking twice is not an error: the second time there is nothing left to
// take, which is what an admin who is not sure should be able to do.
func TestRevokeAccessTwiceTakesNothing(t *testing.T) {
	service, _, _, _ := revokeService(t,
		&storage.Device{Owner: "alice", Name: "laptop", PublicKey: "key-1", Address: "10.44.0.2/32", CreatedAt: time.Now()},
	)

	if _, err := service.RevokeAccess(userContext("admin", true), connect.NewRequest(&proto.RevokeAccessReq{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	res, err := service.RevokeAccess(userContext("admin", true), connect.NewRequest(&proto.RevokeAccessReq{Name: "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetDevicesBlocked() != 0 || res.Msg.GetTokensDeleted() != 0 || res.Msg.GetSessionsEnded() != 0 {
		t.Errorf("the second revocation took %+v, want nothing", res.Msg)
	}
}

// A device that is already blocked is not counted again - the number is what
// this action changed, which is what the admin is told.
func TestRevokeAccessCountsWhatItChanged(t *testing.T) {
	service, _, _, _ := revokeService(t,
		&storage.Device{Owner: "alice", Name: "laptop", PublicKey: "key-1", Address: "10.44.0.2/32", CreatedAt: time.Now(), Disabled: true},
		&storage.Device{Owner: "alice", Name: "phone", PublicKey: "key-2", Address: "10.44.0.3/32", CreatedAt: time.Now()},
	)

	res, err := service.RevokeAccess(userContext("admin", true), connect.NewRequest(&proto.RevokeAccessReq{Name: "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetDevicesBlocked() != 1 {
		t.Errorf("blocked %d devices, want the one that could still connect", res.Msg.GetDevicesBlocked())
	}
}

// Taking somebody's access away is an admin action, and a user must not be
// able to aim it at anybody.
func TestRevokeAccessIsRefusedForUsers(t *testing.T) {
	service, _, _, _ := revokeService(t)

	_, err := service.RevokeAccess(userContext("alice", false), connect.NewRequest(&proto.RevokeAccessReq{Name: "bob"}))
	if err == nil {
		t.Fatal("a user revoked somebody's access")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}
}

// An admin aiming it at themselves would be signed out mid-action with their
// own devices blocked, so it is refused rather than half-done.
func TestRevokeAccessRefusesYourself(t *testing.T) {
	service, s, _, _ := revokeService(t,
		&storage.Device{Owner: "admin", Name: "laptop", PublicKey: "key-1", Address: "10.44.0.2/32", CreatedAt: time.Now()},
	)

	_, err := service.RevokeAccess(userContext("admin", true), connect.NewRequest(&proto.RevokeAccessReq{Name: "admin"}))
	if err == nil {
		t.Fatal("an admin revoked their own access")
	}
	if code := connect.CodeOf(err); code != connect.CodeFailedPrecondition {
		t.Errorf("code = %s, want %s", code, connect.CodeFailedPrecondition)
	}

	device, err := s.Get("admin", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if device.Disabled {
		t.Error("the refused revocation blocked a device anyway")
	}
}
