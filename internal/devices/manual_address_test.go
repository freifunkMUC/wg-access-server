package devices

import (
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// The device import in the web UI hands the addresses of an exported device
// back as a manual assignment, so that an exported client configuration still
// matches the device on the server.
func TestAddDeviceWithManualAddresses(t *testing.T) {
	s := storage.NewMemoryStorage()
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

	device, err := manager.AddDevice(testIdentity("user"), "laptop", testPublicKey(1), "", true, "10.44.0.42", "fd48:4c4:7aa9::42")
	if err != nil {
		t.Fatal(err)
	}
	if want := "10.44.0.42/32, fd48:4c4:7aa9::42/128"; device.Address != want {
		t.Errorf("device got address %q, want %q", device.Address, want)
	}
}

// The import falls back to an automatic address when the stored one cannot be
// used again - these are the cases where that fallback has to kick in.
func TestAddDeviceRejectsUnusableManualAddresses(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Save(&storage.Device{
		Owner: "someone-else", Name: "taken", PublicKey: testPublicKey(1),
		Address: "10.44.0.42/32", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

	tests := []struct {
		name     string
		ipv4     string
		contains string
	}{
		{name: "address already in use", ipv4: "10.44.0.42", contains: "already in use"},
		{name: "address outside of the subnet", ipv4: "192.0.2.10", contains: "not in the configured subnet"},
		{name: "server address is reserved", ipv4: "10.44.0.1", contains: "reserved"},
		{name: "not an address at all", ipv4: "10.44.0.42/32", contains: "invalid manual IPv4 address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.AddDevice(testIdentity("user"), tt.name, testPublicKey(2), "", true, tt.ipv4, "")
			if err == nil {
				t.Fatalf("adding a device with manual address %q succeeded, want an error", tt.ipv4)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("error %q does not mention %q", err, tt.contains)
			}
		})
	}
}
