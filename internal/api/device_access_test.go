package api

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// The whole point of a block is that the user it is aimed at cannot lift it.
func TestSetDeviceAccessIsRefusedForUsers(t *testing.T) {
	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32",
		CreatedAt: time.Now(), Disabled: true,
	})

	disabled := false
	_, err := service.SetDeviceAccess(userContext("alice", false), connect.NewRequest(&proto.SetDeviceAccessReq{
		Name:     "laptop",
		Disabled: wrapperspb.Bool(disabled),
	}))
	if err == nil {
		t.Fatal("a user lifted the block on their own device")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}

	device, err := s.Get("alice", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !device.Disabled {
		t.Error("the device is no longer disabled")
	}
}

// An admin blocks somebody else's device by naming its owner, as they do when
// deleting or renaming one.
func TestSetDeviceAccessByAdminIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	expires := time.Now().Add(24 * time.Hour)
	res, err := service.SetDeviceAccess(userContext("admin", true), connect.NewRequest(&proto.SetDeviceAccessReq{
		Name:      "laptop",
		Owner:     wrapperspb.String("alice"),
		ExpiresAt: timestamppb.New(expires),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetExpiresAt() == nil {
		t.Error("the device the admin got back has no expiry date")
	}

	device, err := s.Get("alice", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if device.ExpiresAt == nil || !device.ExpiresAt.Equal(expires.UTC()) {
		t.Errorf("stored expiresAt = %v, want %v", device.ExpiresAt, expires.UTC())
	}

	entries := auditEntries(hook, audit.DeviceAccess)
	if len(entries) != 1 {
		t.Fatalf("recorded %d access changes, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Data["actor"] != "admin" || entry.Data["owner"] != "alice" || entry.Data["device"] != "laptop" {
		t.Errorf("the record does not say who changed what: %v", entry.Data)
	}
	if entry.Data["expires_at"] == nil {
		t.Errorf("the record does not say what the expiry was set to: %v", entry.Data)
	}
}

// A device that may not connect has to look that way over the API, for the
// owner too: the UI has no other way to explain why the tunnel is dead.
func TestListDevicesReportsTheAccessState(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "key", Address: "10.44.0.2/32",
		CreatedAt: time.Now(), Disabled: true, ExpiresAt: &expires,
	})

	res, err := service.ListDevices(userContext("alice", false), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetItems()) != 1 {
		t.Fatalf("got %d devices, want 1", len(res.Msg.GetItems()))
	}
	device := res.Msg.GetItems()[0]
	if !device.GetDisabled() {
		t.Error("the device is not reported as disabled")
	}
	if device.GetExpiresAt() == nil {
		t.Error("the device is reported without its expiry date")
	}
}
