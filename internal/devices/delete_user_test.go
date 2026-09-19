package devices

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// failingStorage refuses to delete one named device and behaves like the
// in-memory storage otherwise.
type failingStorage struct {
	*storage.InMemoryStorage
	failFor string
}

func (f *failingStorage) Delete(device *storage.Device) error {
	if device.Name == f.failFor {
		return errors.New("storage is on fire")
	}
	return f.InMemoryStorage.Delete(device)
}

func deviceNames(t *testing.T, s storage.Storage, owner string) []string {
	t.Helper()
	devices, err := s.List(owner)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(devices))
	for _, device := range devices {
		names = append(names, device.Name)
	}
	return names
}

// Deleting a user used to stop at the first device that failed, leaving the
// rest of a revoked user's devices connected.
func TestDeleteDevicesForUserKeepsGoingAfterAFailure(t *testing.T) {
	inner := storage.NewMemoryStorage()
	s := &failingStorage{InMemoryStorage: inner, failFor: "phone"}
	for _, name := range []string{"laptop", "phone", "tablet"} {
		if err := inner.Save(&storage.Device{
			Owner: "alice", Name: name, PublicKey: name, Address: "10.44.0.2/32", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "")

	err := manager.DeleteDevicesForUser("alice")
	if err == nil {
		t.Fatal("expected an error naming the device that is left behind")
	}
	if !strings.Contains(err.Error(), "phone") {
		t.Errorf("error %q does not name the device that could not be deleted", err)
	}

	left := deviceNames(t, inner, "alice")
	if len(left) != 1 || left[0] != "phone" {
		t.Errorf("devices left in storage: %q, want only [phone]", left)
	}
}

func TestDeleteDevicesForUserDeletesAll(t *testing.T) {
	s := storage.NewMemoryStorage()
	for _, name := range []string{"laptop", "phone"} {
		if err := s.Save(&storage.Device{
			Owner: "alice", Name: name, PublicKey: name, Address: "10.44.0.2/32", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(&storage.Device{
		Owner: "bob", Name: "desktop", PublicKey: "desktop", Address: "10.44.0.5/32", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "")

	if err := manager.DeleteDevicesForUser("alice"); err != nil {
		t.Fatal(err)
	}
	if left := deviceNames(t, s, "alice"); len(left) != 0 {
		t.Errorf("devices left for alice: %q", left)
	}
	if left := deviceNames(t, s, "bob"); len(left) != 1 {
		t.Errorf("devices of another user were touched: %q", left)
	}
}
