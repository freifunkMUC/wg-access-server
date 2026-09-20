package devices

import (
	"strings"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func managerWithDevice(t *testing.T, owner, name string) (*DeviceManager, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")
	if _, err := manager.AddDevice(testIdentity(owner), name, testPublicKey(1), "", false, "", ""); err != nil {
		t.Fatal(err)
	}
	return manager, s
}

// A rename must not disturb the tunnel: the key and the address stay, so the
// configuration file the user already has keeps working.
func TestRenameKeepsKeyAndAddress(t *testing.T) {
	manager, s := managerWithDevice(t, "alice", "laptop")
	before, err := s.Get("alice", "laptop")
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := manager.RenameDevice("alice", "laptop", "work laptop")
	if err != nil {
		t.Fatal(err)
	}

	if renamed.Name != "work laptop" {
		t.Errorf("name = %q, want %q", renamed.Name, "work laptop")
	}
	if renamed.PublicKey != before.PublicKey {
		t.Error("the public key changed")
	}
	if renamed.Address != before.Address {
		t.Errorf("address = %q, want %q", renamed.Address, before.Address)
	}

	if _, err := s.Get("alice", "laptop"); err == nil {
		t.Error("the device is still stored under its old name")
	}
	if _, err := s.Get("alice", "work laptop"); err != nil {
		t.Errorf("the device is not stored under its new name: %v", err)
	}
}

func TestRenameRejectsATakenName(t *testing.T) {
	manager, _ := managerWithDevice(t, "alice", "laptop")
	if _, err := manager.AddDevice(testIdentity("alice"), "phone", testPublicKey(2), "", false, "", ""); err != nil {
		t.Fatal(err)
	}

	_, err := manager.RenameDevice("alice", "laptop", "phone")
	if err == nil {
		t.Fatal("renaming onto an existing name succeeded")
	}
	if !strings.Contains(err.Error(), "already taken") {
		t.Errorf("error %q does not say the name is taken", err)
	}
}

// The same name in another user's account is none of our business.
func TestRenameAllowsANameTakenByAnotherUser(t *testing.T) {
	manager, _ := managerWithDevice(t, "alice", "laptop")
	if _, err := manager.AddDevice(testIdentity("bob"), "work laptop", testPublicKey(2), "", false, "", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.RenameDevice("alice", "laptop", "work laptop"); err != nil {
		t.Errorf("rename was refused because another user has that name: %v", err)
	}
}

func TestRenameValidatesTheNewName(t *testing.T) {
	manager, _ := managerWithDevice(t, "alice", "laptop")

	for _, name := range []string{"", "   ", strings.Repeat("a", maxDeviceNameLength+1), "with\nnewline"} {
		if _, err := manager.RenameDevice("alice", "laptop", name); err == nil {
			t.Errorf("rename to %q was accepted", name)
		}
	}
}

func TestRenameOfAMissingDeviceFails(t *testing.T) {
	manager, _ := managerWithDevice(t, "alice", "laptop")

	if _, err := manager.RenameDevice("alice", "does-not-exist", "whatever"); err == nil {
		t.Error("renaming a device that does not exist succeeded")
	}
}

// Renaming to the same name is a no-op, not an "already taken" error.
func TestRenameToTheSameNameIsAccepted(t *testing.T) {
	manager, _ := managerWithDevice(t, "alice", "laptop")

	device, err := manager.RenameDevice("alice", "laptop", "laptop")
	if err != nil {
		t.Fatalf("renaming to the same name failed: %v", err)
	}
	if device.Name != "laptop" {
		t.Errorf("name = %q, want laptop", device.Name)
	}
}
