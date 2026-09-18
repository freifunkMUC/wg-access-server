package devices

import (
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// A device row whose address cannot be parsed used to panic every caller of
// usedAddresses, so one broken row stopped every user from adding a device.
func TestAddDeviceWithBrokenRowInStorage(t *testing.T) {
	for _, address := range []string{"", "not-an-address", "10.44.0.2/32, garbage"} {
		t.Run(address, func(t *testing.T) {
			s := storage.NewMemoryStorage()
			if err := s.Save(&storage.Device{
				Owner: "someone-else", Name: "broken", PublicKey: testPublicKey(1),
				Address: address, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

			device, err := manager.AddDevice(testIdentity("user"), "laptop", testPublicKey(2), "", false, "", "")
			if err != nil {
				t.Fatalf("adding a device next to a broken row failed: %v", err)
			}
			if device.Address == "" {
				t.Error("the new device got no address")
			}
		})
	}
}

// An address stored without its prefix length is still in use and must not be
// handed out a second time.
func TestAddressWithoutPrefixIsReserved(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Save(&storage.Device{
		Owner: "someone-else", Name: "legacy", PublicKey: testPublicKey(1),
		Address: "10.44.0.2, fd48:4c4:7aa9::2", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

	device, err := manager.AddDevice(testIdentity("user"), "laptop", testPublicKey(2), "", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := "10.44.0.3/32, fd48:4c4:7aa9::3/128"; device.Address != want {
		t.Errorf("new device got %q, want %q: the addresses of the existing device must stay reserved", device.Address, want)
	}
}
