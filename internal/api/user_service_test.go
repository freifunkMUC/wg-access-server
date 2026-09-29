package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

func userService(t *testing.T) (*UserService, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	return &UserService{DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")}, s
}

// Deleting a user removes what is remembered about them. Their identity
// staying behind after their devices are gone is the one thing an admin
// deleting a user does not expect.
func TestDeleteUserForgetsThem(t *testing.T) {
	service, s := userService(t)
	if err := s.SaveUser(&storage.User{Subject: "alice", Name: "Alice Example", LastLogin: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.DeleteUser(userContext("admin", true), connect.NewRequest(&proto.DeleteUserReq{Name: "alice"})); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetUser("alice"); err == nil {
		t.Error("the user is still remembered")
	}
}

// The list an admin sees carries when somebody last signed in, which is also
// how old everything else about them is.
func TestListUsersReportsTheLastLogin(t *testing.T) {
	service, s := userService(t)
	login := time.Now().Truncate(time.Second)
	if err := s.SaveUser(&storage.User{Subject: "alice", Name: "Alice Example", LastLogin: login}); err != nil {
		t.Fatal(err)
	}

	res, err := service.ListUsers(userContext("admin", true), connect.NewRequest(&proto.ListUsersReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetItems()) != 1 {
		t.Fatalf("listed %d users, want one", len(res.Msg.GetItems()))
	}
	user := res.Msg.GetItems()[0]
	if user.GetName() != "alice" || user.GetDisplayName() != "Alice Example" {
		t.Errorf("user = %+v, want alice", user)
	}
	if user.GetLastLogin() == nil || !user.GetLastLogin().AsTime().Equal(login.UTC()) {
		t.Errorf("last login = %v, want %v", user.GetLastLogin(), login.UTC())
	}
}

// A user has to be an admin to see who else there is.
func TestListUsersIsRefusedForUsers(t *testing.T) {
	service, _ := userService(t)
	if _, err := service.ListUsers(userContext("alice", false), connect.NewRequest(&proto.ListUsersReq{})); err == nil {
		t.Fatal("a user listed the other users")
	} else if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}
}

// A deleted user's browser session has to stop working with them: otherwise
// whoever holds their cookie keeps the web UI, and with it the ability to add
// a device.
func TestDeleteUserEndsTheirSessions(t *testing.T) {
	s := storage.NewMemoryStorage()
	sessions := websessions.New(s, time.Hour)
	service := &UserService{
		DeviceManager: devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""),
		Sessions:      sessions,
	}

	identity := &authsession.Identity{Subject: "alice", Provider: "simple", Name: "alice"}
	id, err := sessions.Create(identity, httptest.NewRequest("GET", "http://wg-access-server.test/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Identity(id); err != nil {
		t.Fatal(err)
	}

	if _, err := service.DeleteUser(userContext("admin", true), connect.NewRequest(&proto.DeleteUserReq{Name: "alice"})); err != nil {
		t.Fatal(err)
	}

	if _, err := sessions.Identity(id); err == nil {
		t.Error("the session of the deleted user still works")
	}
}
