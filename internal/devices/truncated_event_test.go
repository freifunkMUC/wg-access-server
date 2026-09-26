package devices

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

// recordingInterface is a WireGuard interface that only remembers its peers.
type recordingInterface struct {
	wgembed.WireGuardInterface
	mu    sync.Mutex
	peers map[string]bool
}

// AddPeer rejects a key that is not one, like the real interface does. The
// database is shared with the other test packages, and a row with a broken
// key they leave behind would otherwise become a peer that ListPeers then
// fails on - failing the sync this test waits for.
func (r *recordingInterface) AddPeer(publicKey, _ string, _ []string) error {
	if _, err := wgtypes.ParseKey(publicKey); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[publicKey] = true
	return nil
}

func (r *recordingInterface) RemovePeer(publicKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, publicKey)
	return nil
}

func (r *recordingInterface) ListPeers() ([]wgtypes.Peer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var peers []wgtypes.Peer
	for key := range r.peers {
		k, err := wgtypes.ParseKey(key)
		if err != nil {
			return nil, err
		}
		peers = append(peers, wgtypes.Peer{PublicKey: k})
	}
	return peers, nil
}

func (r *recordingInterface) has(publicKey string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peers[publicKey]
}

// With Postgres every replica - including the one creating a device - adds the
// WireGuard peer only from the database notification. A device whose row is too
// large for a notification must still end up with a peer.
func TestDeviceWithOversizedRowGetsAPeer(t *testing.T) {
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}
	s := openTruncatedTestStorage(t, uri)
	wg := &recordingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]bool{}}
	manager := New(wg, s, "10.88.0.0/16", "")
	require.NoError(t, manager.StartSync(t.Context(), false, false, 0))

	owner := "truncated-event-test"
	t.Cleanup(func() {
		devices, _ := s.List(owner)
		for _, d := range devices {
			_ = s.Delete(d)
		}
	})

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	identity := &authsession.Identity{
		Subject: owner,
		// display names come from the identity provider and are not bounded
		Name: strings.Repeat("a very long display name ", 400),
	}
	device, err := manager.AddDevice(identity, "tablet", key.PublicKey().String(), "", false, "", "")
	require.NoError(t, err)

	deadline := time.Now().Add(5 * time.Second)
	for !wg.has(device.PublicKey) {
		require.True(t, time.Now().Before(deadline), "the device never got a WireGuard peer")
		time.Sleep(20 * time.Millisecond)
	}
}

func openTruncatedTestStorage(t *testing.T, uri string) storage.Storage {
	t.Helper()
	s, err := storage.NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	t.Cleanup(func() { _ = s.Close() })
	return s
}
