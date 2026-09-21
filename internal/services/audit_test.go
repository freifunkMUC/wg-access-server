package services

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// userContext builds a request context as the auth middleware would leave it.
func userContext(subject string, isAdmin bool) context.Context {
	identity := &authsession.Identity{Provider: "simple", Subject: subject, Name: subject}
	if isAdmin {
		identity.Claims.MakeAdmin()
	}
	ctx := authsession.SetIdentityCtx(context.Background(), &authsession.AuthSession{Identity: identity})
	return audit.WithRemoteAddr(ctx, "198.51.100.7:51234")
}

// auditEntries returns the audit records the hook captured.
func auditEntries(hook *logrustest.Hook, action string) []*logrus.Entry {
	var found []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Data["audit"] == action {
			found = append(found, entry)
		}
	}
	return found
}

func deviceServiceWith(t *testing.T, devicesInStorage ...*storage.Device) (*DeviceService, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	for _, device := range devicesInStorage {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	manager := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")
	return &DeviceService{DeviceManager: manager}, s
}

// An admin deleting somebody else's device must be distinguishable from the
// owner deleting their own - that is the whole point of the record.
func TestDeleteDeviceByAdminIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.DeleteDevice(userContext("admin", true), connect.NewRequest(&proto.DeleteDeviceReq{
		Name:  "laptop",
		Owner: wrapperspb.String("alice"),
	}))
	if err != nil {
		t.Fatal(err)
	}

	entries := auditEntries(hook, audit.DeviceDelete)
	if len(entries) != 1 {
		t.Fatalf("got %d audit records, want 1", len(entries))
	}
	data := entries[0].Data
	for field, want := range map[string]interface{}{
		"actor":          "admin",
		"actor_is_admin": true,
		"owner":          "alice",
		"device":         "laptop",
		"remote_addr":    "198.51.100.7",
	} {
		if data[field] != want {
			t.Errorf("audit field %q = %v, want %v", field, data[field], want)
		}
	}
}

func TestAddDeviceIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, _ := deviceServiceWith(t)

	_, err := service.AddDevice(userContext("alice", false), connect.NewRequest(&proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if err != nil {
		t.Fatal(err)
	}

	entries := auditEntries(hook, audit.DeviceCreate)
	if len(entries) != 1 {
		t.Fatalf("got %d audit records, want 1", len(entries))
	}
	if got := entries[0].Data["owner"]; got != "alice" {
		t.Errorf("owner = %v, want alice", got)
	}
	if got := entries[0].Data["actor_is_admin"]; got != false {
		t.Errorf("actor_is_admin = %v, want false", got)
	}
}

// A failed action must not show up as if it had happened.
func TestFailedDeleteIsNotAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, _ := deviceServiceWith(t)

	_, err := service.DeleteDevice(userContext("alice", false), connect.NewRequest(&proto.DeleteDeviceReq{Name: "does-not-exist"}))
	if err == nil {
		t.Fatal("deleting a device that does not exist succeeded")
	}

	if entries := auditEntries(hook, audit.DeviceDelete); len(entries) != 0 {
		t.Errorf("got %d audit records for a failed deletion, want none", len(entries))
	}
}

// A non-admin must not be able to delete another user's device, and nothing
// may be recorded as if they had.
func TestDeleteForeignDeviceIsRefusedAndNotAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.DeleteDevice(userContext("mallory", false), connect.NewRequest(&proto.DeleteDeviceReq{
		Name:  "laptop",
		Owner: wrapperspb.String("alice"),
	}))
	if err == nil {
		t.Fatal("a non-admin deleted somebody else's device")
	}
	if entries := auditEntries(hook, audit.DeviceDelete); len(entries) != 0 {
		t.Errorf("got %d audit records for a refused deletion, want none", len(entries))
	}
	if left, _ := s.List("alice"); len(left) != 1 {
		t.Error("the device was deleted although the request was refused")
	}
}

// Renaming somebody else's device is an admin action and must be recorded
// with both names.
func TestRenameDeviceByAdminIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	res, err := service.RenameDevice(userContext("admin", true), connect.NewRequest(&proto.RenameDeviceReq{
		Name:    "laptop",
		NewName: "alice laptop",
		Owner:   wrapperspb.String("alice"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.Name != "alice laptop" {
		t.Errorf("name = %q, want %q", res.Msg.Name, "alice laptop")
	}
	if _, err := s.Get("alice", "alice laptop"); err != nil {
		t.Errorf("the device was not stored under its new name: %v", err)
	}

	entries := auditEntries(hook, audit.DeviceRename)
	if len(entries) != 1 {
		t.Fatalf("got %d audit records, want 1", len(entries))
	}
	for field, want := range map[string]interface{}{
		"actor":    "admin",
		"owner":    "alice",
		"device":   "alice laptop",
		"previous": "laptop",
	} {
		if entries[0].Data[field] != want {
			t.Errorf("audit field %q = %v, want %v", field, entries[0].Data[field], want)
		}
	}
}

// A user may rename their own devices, but not somebody else's.
func TestRenameForeignDeviceIsRefused(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.RenameDevice(userContext("mallory", false), connect.NewRequest(&proto.RenameDeviceReq{
		Name:    "laptop",
		NewName: "mine now",
		Owner:   wrapperspb.String("alice"),
	}))
	if err == nil {
		t.Fatal("a non-admin renamed somebody else's device")
	}
	if entries := auditEntries(hook, audit.DeviceRename); len(entries) != 0 {
		t.Errorf("got %d audit records for a refused rename, want none", len(entries))
	}
	if _, err := s.Get("alice", "laptop"); err != nil {
		t.Error("the device was renamed although the request was refused")
	}
}
