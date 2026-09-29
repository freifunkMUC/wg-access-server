package devices

import (
	"net"
	"sync"
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

// countingInterface records how often a peer was configured. It is used from
// the test and from the resynchronization running in the background, so
// everything it holds is behind a lock.
type countingInterface struct {
	wgembed.WireGuardInterface
	mu    sync.Mutex
	peers map[string]wgtypes.Peer
	adds  int
}

// addCount is how often a peer was configured, and resetAdds starts counting
// again.
func (c *countingInterface) addCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adds
}

func (c *countingInterface) resetAdds() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.adds = 0
}

// allowedIPs returns the networks a peer is configured with, or nil when
// there is no such peer.
func (c *countingInterface) allowedIPs(publicKey string) []net.IPNet {
	c.mu.Lock()
	defer c.mu.Unlock()
	peer, ok := c.peers[publicKey]
	if !ok {
		return nil
	}
	return peer.AllowedIPs
}

func (c *countingInterface) ListPeers() ([]wgtypes.Peer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	peers := make([]wgtypes.Peer, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	return peers, nil
}

func (c *countingInterface) AddPeer(publicKey, presharedKey string, addresses []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.adds++
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	peer := wgtypes.Peer{PublicKey: key}
	if presharedKey != "" {
		psk, err := wgtypes.ParseKey(presharedKey)
		if err != nil {
			return err
		}
		peer.PresharedKey = psk
	}
	for _, address := range addresses {
		_, ipnet, err := net.ParseCIDR(address)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
	}
	c.peers[publicKey] = peer
	return nil
}

func (c *countingInterface) RemovePeer(publicKey string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.peers, publicKey)
	return nil
}

// TestSyncLeavesMatchingPeersAlone covers the cost of a sync after a storage
// reconnect: configuring a peer is a round trip to the kernel, and one per
// device is what a few thousand of them make of it. Only what does not match
// what is stored may be configured again.
func TestSyncLeavesMatchingPeersAlone(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	devices := []*storage.Device{
		{Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32, fd48:4c4:7aa9::2/128"},
		{Owner: "bob", Name: "phone", PublicKey: testDeviceKey(t, 2), Address: "10.44.0.3/32", PresharedKey: testDeviceKey(t, 9)},
	}
	for _, device := range devices {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}

	wg := &countingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]wgtypes.Peer{}}
	manager := New(wg, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64")

	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if wg.addCount() != len(devices) {
		t.Fatalf("the first sync configured %d peers, want %d", wg.addCount(), len(devices))
	}

	// nothing changed in between
	wg.resetAdds()
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if wg.addCount() != 0 {
		t.Errorf("a sync with nothing changed configured %d peers again", wg.addCount())
	}

	// a device that moved to another address has to be configured again
	devices[0].Address = "10.44.0.4/32, fd48:4c4:7aa9::2/128"
	if err := s.Save(devices[0]); err != nil {
		t.Fatal(err)
	}
	wg.resetAdds()
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if wg.addCount() != 1 {
		t.Errorf("the moved device was configured %d times, want once", wg.addCount())
	}

	// and so does one that was given a pre-shared key
	devices[1].PresharedKey = testDeviceKey(t, 10)
	if err := s.Save(devices[1]); err != nil {
		t.Fatal(err)
	}
	wg.resetAdds()
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if wg.addCount() != 1 {
		t.Errorf("the device with the new pre-shared key was configured %d times, want once", wg.addCount())
	}
}
