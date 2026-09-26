package api

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// What the user got wrong is worth telling them, and it is not an internal
// error either.
func TestValidationErrorsReachTheClient(t *testing.T) {
	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.AddDevice(userContext("alice", false), connect.NewRequest(&proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
	}))
	if err == nil {
		t.Fatal("adding a device with a name that is taken succeeded")
	}

	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %s, want %s", code, connect.CodeInvalidArgument)
	}
	if !strings.Contains(err.Error(), "already taken") {
		t.Errorf("message %q does not say what is wrong", err.Error())
	}
}

// A storage failure must not hand the client its details - the client gets a
// trace id to quote, the detail stays in the log.
func TestStorageErrorsStayInternal(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	manager := devices.New(noopWireGuardInterface{}, failingStorage{Storage: storage.NewMemoryStorage()}, "10.44.0.0/24", "")
	service := &DeviceService{DeviceManager: manager}

	_, err := service.AddDevice(userContext("alice", false), connect.NewRequest(&proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if err == nil {
		t.Fatal("adding a device succeeded although the storage failed")
	}

	if code := connect.CodeOf(err); code != connect.CodeInternal {
		t.Errorf("code = %s, want %s", code, connect.CodeInternal)
	}
	if strings.Contains(err.Error(), "storage unavailable") {
		t.Errorf("message %q leaks the storage error", err.Error())
	}
	if !strings.Contains(err.Error(), "trace = ") {
		t.Errorf("message %q carries no trace id", err.Error())
	}

	logged := false
	for _, entry := range hook.AllEntries() {
		if cause, ok := entry.Data[logrus.ErrorKey].(error); ok && strings.Contains(cause.Error(), "storage unavailable") {
			logged = true
		}
		if strings.Contains(entry.Message, "storage unavailable") {
			logged = true
		}
	}
	if !logged {
		t.Error("the storage error the client does not get is not in the log either")
	}
}
