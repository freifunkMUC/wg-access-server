package devices

import (
	"strings"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func addDevice(t *testing.T, manager *DeviceManager, owner, name string, key int) error {
	t.Helper()
	_, err := manager.AddDevice(testIdentity(owner), name, testPublicKey(key), "", false, "", "")
	return err
}

func TestDeviceQuotaIsEnforced(t *testing.T) {
	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "", WithMaxDevicesPerUser(2))

	for i, name := range []string{"laptop", "phone"} {
		if err := addDevice(t, manager, "alice", name, i+1); err != nil {
			t.Fatalf("device %q was refused below the limit: %v", name, err)
		}
	}

	err := addDevice(t, manager, "alice", "tablet", 3)
	if err == nil {
		t.Fatal("the device beyond the limit was accepted")
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Errorf("error %q does not explain the limit", err)
	}

	// deleting one makes room again
	if err := manager.DeleteDevice("alice", "phone"); err != nil {
		t.Fatal(err)
	}
	if err := addDevice(t, manager, "alice", "tablet", 3); err != nil {
		t.Errorf("no device could be added after deleting one: %v", err)
	}
}

// The limit is per user, not for the server as a whole.
func TestDeviceQuotaIsPerUser(t *testing.T) {
	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "", WithMaxDevicesPerUser(1))

	if err := addDevice(t, manager, "alice", "laptop", 1); err != nil {
		t.Fatal(err)
	}
	if err := addDevice(t, manager, "bob", "laptop", 2); err != nil {
		t.Errorf("bob was refused because of alice's device: %v", err)
	}
}

func TestWithoutQuotaTheNumberIsUnlimited(t *testing.T) {
	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")

	for i := 0; i < 5; i++ {
		if err := addDevice(t, manager, "alice", string(rune('a'+i)), i+1); err != nil {
			t.Fatalf("device %d was refused without a configured limit: %v", i, err)
		}
	}
}
