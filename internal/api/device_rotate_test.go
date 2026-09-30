package api

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

func deviceKey(t *testing.T, seed byte) string {
	t.Helper()
	var raw [32]byte
	raw[0] = seed
	key, err := wgtypes.NewKey(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return key.String()
}

// The owner replaces the key of their own device and keeps the device.
func TestRotateDeviceKey(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	old := deviceKey(t, 1)
	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: old, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	fresh := deviceKey(t, 2)
	res, err := service.RotateDeviceKey(userContext("alice", false), connect.NewRequest(&proto.RotateDeviceKeyReq{
		Name:      "laptop",
		PublicKey: fresh,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetPublicKey() != fresh {
		t.Errorf("the device reports %q, want the new key", res.Msg.GetPublicKey())
	}
	if res.Msg.GetAddress() != "10.44.0.2/32" {
		t.Errorf("address = %q, want the one it had", res.Msg.GetAddress())
	}

	stored, err := s.Get("alice", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if stored.PublicKey != fresh {
		t.Errorf("stored key = %q, want the new one", stored.PublicKey)
	}

	entries := auditEntries(hook, audit.DeviceRotate)
	if len(entries) != 1 {
		t.Fatalf("%d audit records, want one", len(entries))
	}
	if entries[0].Data["device"] != "laptop" || entries[0].Data["owner"] != "alice" {
		t.Errorf("audit record = %+v, want alice's laptop", entries[0].Data)
	}
	// the record says what changed, not the key material itself
	for field, value := range entries[0].Data {
		if s, ok := value.(string); ok && (s == fresh || s == old) {
			t.Errorf("the audit record carries key material in %q", field)
		}
	}
}

// Rotating names no owner, so nobody can aim it at somebody else's device -
// not even an admin, who would end up holding the private key.
func TestRotateDeviceKeyOnlyTouchesYourOwn(t *testing.T) {
	old := deviceKey(t, 1)
	service, s := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: old, Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	for _, who := range []struct {
		name  string
		admin bool
	}{{name: "another user"}, {name: "an admin", admin: true}} {
		t.Run(who.name, func(t *testing.T) {
			_, err := service.RotateDeviceKey(userContext("bob", who.admin), connect.NewRequest(&proto.RotateDeviceKeyReq{
				Name:      "laptop",
				PublicKey: deviceKey(t, 2),
			}))
			if err == nil {
				t.Fatal("somebody rotated a device that is not theirs")
			}

			stored, err := s.Get("alice", "laptop")
			if err != nil {
				t.Fatal(err)
			}
			if stored.PublicKey != old {
				t.Errorf("the device's key changed to %q", stored.PublicKey)
			}
		})
	}
}

// A key that is not one has to come back as a refusal the UI can show, not as
// an internal error.
func TestRotateDeviceKeyRefusesABrokenKey(t *testing.T) {
	service, _ := deviceServiceWith(t, &storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: deviceKey(t, 1), Address: "10.44.0.2/32", CreatedAt: time.Now(),
	})

	_, err := service.RotateDeviceKey(userContext("alice", false), connect.NewRequest(&proto.RotateDeviceKeyReq{
		Name:      "laptop",
		PublicKey: "not-a-key",
	}))
	if err == nil {
		t.Fatal("a device was given a key that is not one")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("code = %s, want %s", code, connect.CodeInvalidArgument)
	}
}

// A request without a session has nobody to act as.
func TestRotateDeviceKeyNeedsASignedInUser(t *testing.T) {
	service, _ := deviceServiceWith(t)

	_, err := service.RotateDeviceKey(t.Context(), connect.NewRequest(&proto.RotateDeviceKeyReq{
		Name:      "laptop",
		PublicKey: deviceKey(t, 2),
	}))
	if err == nil {
		t.Fatal("a request without a user rotated a key")
	}
	// the API answers a request without a session the same way it answers one
	// that may not do this, which is what errNotAuthenticated does everywhere
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("code = %s, want %s", code, connect.CodePermissionDenied)
	}
}
