package services

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

	_, err := service.AddDevice(userContext("alice", false), &proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
	})
	if err == nil {
		t.Fatal("adding a device with a name that is taken succeeded")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %s, want %s", st.Code(), codes.InvalidArgument)
	}
	if !strings.Contains(st.Message(), "already taken") {
		t.Errorf("message %q does not say what is wrong", st.Message())
	}
}

// A storage failure must not hand the client its details - the client gets a
// trace id to quote, the detail stays in the log.
func TestStorageErrorsStayInternal(t *testing.T) {
	manager := devices.New(noopWireGuardInterface{}, failingStorage{Storage: storage.NewMemoryStorage()}, "10.44.0.0/24", "")
	service := &DeviceService{DeviceManager: manager}

	_, err := service.AddDevice(userContext("alice", false), &proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if err == nil {
		t.Fatal("adding a device succeeded although the storage failed")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("code = %s, want %s", st.Code(), codes.Internal)
	}
	if strings.Contains(st.Message(), "storage unavailable") {
		t.Errorf("message %q leaks the storage error", st.Message())
	}
	if !strings.Contains(st.Message(), "trace = ") {
		t.Errorf("message %q carries no trace id", st.Message())
	}
}
