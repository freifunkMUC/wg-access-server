package storage

import (
	"testing"
	"time"
)

// The WireGuard peer is identified by the public key, so a second user
// registering someone else's key would take over their tunnel. The SQL
// backends have a unique index for this; the in-memory one has to check.
func TestMemoryStorageRejectsADuplicatePublicKey(t *testing.T) {
	s := NewMemoryStorage()
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	if err := s.Save(&Device{Owner: "alice", Name: "laptop", PublicKey: key, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	err := s.Save(&Device{Owner: "mallory", Name: "stolen", PublicKey: key, CreatedAt: time.Now()})
	if err == nil {
		t.Fatal("a second device with the same public key was stored")
	}

	if devices, _ := s.List(""); len(devices) != 1 {
		t.Errorf("storage holds %d devices, want 1", len(devices))
	}
}

// Saving the same device again - the metadata sync does this - must work.
func TestMemoryStorageAllowsUpdatingADevice(t *testing.T) {
	s := NewMemoryStorage()
	device := &Device{Owner: "alice", Name: "laptop", PublicKey: "key", CreatedAt: time.Now()}

	if err := s.Save(device); err != nil {
		t.Fatal(err)
	}
	device.ReceiveBytes = 42
	if err := s.Save(device); err != nil {
		t.Errorf("saving the same device again failed: %v", err)
	}
}
