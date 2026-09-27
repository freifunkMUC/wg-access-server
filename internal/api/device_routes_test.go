package api

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// The networks in these tests are the ones reserved for documentation, so they
// cannot collide with a network the machine running the tests is in - which
// the validation refuses, for good reason.
const testRoute = "198.51.100.0/24"

// A route decides where everybody's traffic for that network goes. A user who
// could set one on their own device would be claiming it.
func TestSetDeviceRoutesIsRefusedForUsers(t *testing.T) {
	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.SetDeviceRoutes(userContext("alice", false), connect.NewRequest(&proto.SetDeviceRoutesReq{
		Name:   "site",
		Routes: []string{testRoute},
	}))
	if err == nil {
		t.Fatal("a user routed a network to their own device")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}

	device, err := s.Get("alice", "site")
	if err != nil {
		t.Fatal(err)
	}
	if device.Routes != "" {
		t.Errorf("routes = %q, want none", device.Routes)
	}
}

func TestSetDeviceRoutesByAdminIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	res, err := service.SetDeviceRoutes(userContext("admin", true), connect.NewRequest(&proto.SetDeviceRoutesReq{
		Name:   "site",
		Owner:  wrapperspb.String("alice"),
		Routes: []string{testRoute},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Msg.GetRoutes(); len(got) != 1 || got[0] != testRoute {
		t.Errorf("routes = %v, want %v", got, []string{testRoute})
	}

	device, err := s.Get("alice", "site")
	if err != nil {
		t.Fatal(err)
	}
	if device.Routes != testRoute {
		t.Errorf("stored routes = %q, want %q", device.Routes, testRoute)
	}

	entries := auditEntries(hook, audit.DeviceRoutes)
	if len(entries) != 1 {
		t.Fatalf("recorded %d route changes, want 1", len(entries))
	}
	if entry := entries[0]; entry.Data["actor"] != "admin" || entry.Data["owner"] != "alice" || entry.Data["routes"] != testRoute {
		t.Errorf("the record does not say who routed what: %v", entry.Data)
	}
}

// What the user cannot change they can at least see: their device carries
// traffic for a network, and the client configuration has to match.
func TestListDevicesReportsTheRoutes(t *testing.T) {
	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: "key", Address: "10.44.0.2/32",
		Routes: testRoute + ", 203.0.113.0/24", CreatedAt: time.Now(),
	})

	res, err := service.ListDevices(userContext("alice", false), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetItems()) != 1 {
		t.Fatalf("got %d devices, want 1", len(res.Msg.GetItems()))
	}
	if routes := res.Msg.GetItems()[0].GetRoutes(); len(routes) != 2 {
		t.Errorf("routes = %v, want both networks", routes)
	}
}

// A network that cannot be routed is the admin's mistake, and they are told
// what is wrong with it rather than "internal error".
func TestSetDeviceRoutesReportsWhatIsWrong(t *testing.T) {
	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "site", PublicKey: "key", Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.SetDeviceRoutes(userContext("admin", true), connect.NewRequest(&proto.SetDeviceRoutesReq{
		Name:   "site",
		Owner:  wrapperspb.String("alice"),
		Routes: []string{"0.0.0.0/0"},
	}))
	if err == nil {
		t.Fatal("a default route was accepted")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %s, want %s", code, connect.CodeInvalidArgument)
	}
}
