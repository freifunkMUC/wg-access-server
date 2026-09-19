package devices

import (
	"strings"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func TestValidateDeviceName(t *testing.T) {
	tests := []struct {
		name    string
		device  string
		wantErr string
	}{
		{name: "ordinary name", device: "laptop"},
		{name: "name with a dot", device: "laptop.home"},
		{name: "name with a space", device: "my laptop"},
		{name: "umlauts count as one character each", device: strings.Repeat("ä", maxDeviceNameLength)},
		{name: "exactly at the limit", device: strings.Repeat("a", maxDeviceNameLength)},
		{name: "empty", device: "", wantErr: "must not be empty"},
		{name: "only spaces", device: "   ", wantErr: "must not be empty"},
		{name: "too long", device: strings.Repeat("a", maxDeviceNameLength+1), wantErr: "at most"},
		{name: "newline", device: "laptop\nphone", wantErr: "control characters"},
		{name: "tab", device: "laptop\tphone", wantErr: "control characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDeviceName(tt.device)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateDeviceName(%q) = %v, want no error", tt.device, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateDeviceName(%q) = nil, want an error about %q", tt.device, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// A name longer than the column is rejected before it reaches the database:
// MySQL outside of strict mode truncates it, and the truncated name can
// collide with an existing device.
func TestAddDeviceRejectsAnOversizedName(t *testing.T) {
	manager := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")

	_, err := manager.AddDevice(testIdentity("user"), strings.Repeat("a", maxDeviceNameLength+1), testPublicKey(1), "", false, "", "")
	if err == nil {
		t.Fatal("adding a device with an oversized name succeeded")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("error %q does not explain the length limit", err)
	}
}
