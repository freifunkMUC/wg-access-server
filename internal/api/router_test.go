package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
	"github.com/freifunkMUC/wg-access-server/proto/proto/protoconnect"
)

// connectServerFor starts the Connect API in front of a seeded storage. The
// session normally comes from the auth middleware, so the test puts one into
// the request context the same way.
func connectServerFor(t *testing.T, subject string, authenticated bool, seed ...*storage.Device) string {
	t.Helper()

	s := storage.NewMemoryStorage()
	for _, device := range seed {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	manager := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")

	api := Router(&Services{
		Config:        &config.AppConfig{},
		DeviceManager: manager,
		Wg:            noopWireGuardInterface{},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if authenticated {
			ctx = authsession.SetIdentityCtx(ctx, &authsession.AuthSession{
				Identity: &authsession.Identity{Provider: "test", Subject: subject, Name: subject},
			})
		}
		api.ServeHTTP(w, r.WithContext(ctx))
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func testDevice(owner, name string) *storage.Device {
	return &storage.Device{
		Owner: owner, Name: name, PublicKey: name + "-key",
		Address: "10.44.0.2/32", CreatedAt: time.Now(),
	}
}

// The web UI talks gRPC-Web, which Connect serves itself.
func TestConnectServesTheGrpcWebProtocol(t *testing.T) {
	url := connectServerFor(t, "alice", true, testDevice("alice", "laptop"))

	client := protoconnect.NewDevicesClient(http.DefaultClient, url, connect.WithGRPCWeb())

	res, err := client.ListDevices(context.Background(), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatalf("a gRPC-Web request failed: %v", err)
	}
	if len(res.Msg.Items) != 1 || res.Msg.Items[0].Name != "laptop" {
		t.Errorf("got %d devices, want the seeded one", len(res.Msg.Items))
	}
}

func TestConnectServesItsOwnProtocol(t *testing.T) {
	url := connectServerFor(t, "alice", true, testDevice("alice", "laptop"))

	client := protoconnect.NewDevicesClient(http.DefaultClient, url)

	res, err := client.ListDevices(context.Background(), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatalf("a Connect request failed: %v", err)
	}
	if len(res.Msg.Items) != 1 {
		t.Errorf("got %d devices, want 1", len(res.Msg.Items))
	}
}

// The status codes the services report have to reach the client, otherwise
// the UI cannot tell "not allowed" from "broken".
func TestConnectKeepsTheStatusCode(t *testing.T) {
	t.Run("without a session", func(t *testing.T) {
		url := connectServerFor(t, "", false)
		client := protoconnect.NewDevicesClient(http.DefaultClient, url, connect.WithGRPCWeb())

		_, err := client.ListDevices(context.Background(), connect.NewRequest(&proto.ListDevicesReq{}))
		if err == nil {
			t.Fatal("an unauthenticated request succeeded")
		}
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Errorf("code = %v, want %v", got, connect.CodePermissionDenied)
		}
	})

	t.Run("as a non-admin", func(t *testing.T) {
		url := connectServerFor(t, "alice", true)
		client := protoconnect.NewDevicesClient(http.DefaultClient, url, connect.WithGRPCWeb())

		_, err := client.ListAllDevices(context.Background(), connect.NewRequest(&proto.ListAllDevicesReq{}))
		if err == nil {
			t.Fatal("a non-admin listed all devices")
		}
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Errorf("code = %v, want %v", got, connect.CodePermissionDenied)
		}
	})

	t.Run("invalid argument", func(t *testing.T) {
		url := connectServerFor(t, "alice", true)
		client := protoconnect.NewDevicesClient(http.DefaultClient, url, connect.WithGRPCWeb())

		_, err := client.AddDevice(context.Background(), connect.NewRequest(&proto.AddDeviceReq{
			Name: "laptop", PublicKey: "not a key",
		}))
		if err == nil {
			t.Fatal("a device with an invalid public key was accepted")
		}
		if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
			t.Errorf("code = %v, want %v", got, connect.CodeInvalidArgument)
		}
	})
}

// A device added through Connect has to be a device like any other.
func TestConnectAddsADevice(t *testing.T) {
	url := connectServerFor(t, "alice", true)
	client := protoconnect.NewDevicesClient(http.DefaultClient, url, connect.WithGRPCWeb())

	added, err := client.AddDevice(context.Background(), connect.NewRequest(&proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if added.Msg.Address == "" {
		t.Error("the device got no address")
	}

	listed, err := client.ListDevices(context.Background(), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Items) != 1 {
		t.Errorf("got %d devices after adding one", len(listed.Msg.Items))
	}
}
