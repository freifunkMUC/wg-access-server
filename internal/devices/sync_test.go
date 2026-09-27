package devices

import (
	"testing"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// TestSyncMatchesTheInterfaceToStorage covers what a sync is for: after it,
// the interface carries a peer for every device and for nothing else. A peer
// left behind would keep a revoked device connected.
func TestSyncMatchesTheInterfaceToStorage(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	stored := testDeviceKey(t, 1)
	gone := testDeviceKey(t, 2)
	if err := s.Save(&storage.Device{Owner: "alice", Name: "laptop", PublicKey: stored, Address: "10.44.0.2/32"}); err != nil {
		t.Fatal(err)
	}

	wg := &recordingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]bool{}}
	// a peer whose device is not in storage any more, e.g. deleted while this
	// replica was disconnected
	if err := wg.AddPeer(gone, "", nil); err != nil {
		t.Fatal(err)
	}

	manager := New(wg, s, "10.44.0.0/24", "")
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}

	if !wg.has(stored) {
		t.Error("the stored device has no peer after the sync")
	}
	if wg.has(gone) {
		t.Error("the peer of a device that is no longer stored survived the sync")
	}
}

func testDeviceKey(t *testing.T, seed byte) string {
	t.Helper()
	var key [32]byte
	key[0] = seed
	parsed, err := wgtypes.NewKey(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.String()
}
