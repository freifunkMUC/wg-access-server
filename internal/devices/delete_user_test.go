package devices

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// failingStorage refuses to delete a user's devices and behaves like the
// in-memory storage otherwise.
type failingStorage struct {
	*storage.InMemoryStorage
}

func (f *failingStorage) DeleteForOwner(owner string) ([]*storage.Device, error) {
	return nil, errors.New("storage is on fire")
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

// Revoking a user's access is all or nothing: if the deletion fails, the user
// must not be left with some of their devices still working.
func TestDeleteDevicesForUserReportsAFailure(t *testing.T) {
	inner := storage.NewMemoryStorage()
	s := &failingStorage{InMemoryStorage: inner}
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
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error %q does not name the user", err)
	}

	if left := deviceNames(t, inner, "alice"); len(left) != 3 {
		t.Errorf("devices left in storage: %q, want all three", left)
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
