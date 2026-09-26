package devices

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

// fakeWgInterface is a minimal in-memory implementation of
// wgembed.WireGuardInterface for tests. The peers returned by ListPeers can
// be injected via the peers field.
type fakeWgInterface struct {
	mu    sync.Mutex
	peers []wgtypes.Peer
	// listPeerCalls counts ListPeers calls, so a test can tell whether a
	// background loop is still running.
	listPeerCalls int
}

var _ wgembed.WireGuardInterface = (*fakeWgInterface)(nil)

func (f *fakeWgInterface) LoadConfig(config *wgembed.ConfigFile) error { return nil }

func (f *fakeWgInterface) AddPeer(publicKey string, presharedKey string, addressCIDR []string) error {
	return nil
}

func (f *fakeWgInterface) ListPeers() ([]wgtypes.Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listPeerCalls++
	return append([]wgtypes.Peer{}, f.peers...), nil
}

func (f *fakeWgInterface) listCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listPeerCalls
}

func (f *fakeWgInterface) RemovePeer(publicKey string) error { return nil }
func (f *fakeWgInterface) PublicKey() (string, error)        { return "", nil }
func (f *fakeWgInterface) Close() error                      { return nil }
func (f *fakeWgInterface) Ping() error                       { return nil }

// testIdentity returns a minimal identity for AddDevice calls.
func testIdentity(subject string) *authsession.Identity {
	return &authsession.Identity{
		Provider: "test",
		Subject:  subject,
		Name:     "Test User",
		Email:    "test@example.com",
	}
}

// testPublicKey returns a syntactically valid WireGuard public key (base64 of
// 32 bytes) that is unique per index.
func testPublicKey(i int) string {
	var b [32]byte
	b[0] = byte(i)
	b[1] = byte(i >> 8)
	return base64.StdEncoding.EncodeToString(b[:])
}

// TestConcurrentAddDeviceAssignsUniqueIPs exercises the TOCTOU window between
// reading the set of used addresses and persisting the new device. Before the
// IP allocation lock was held through SaveDevice, concurrent AddDevice calls
// could both observe the same address as free and persist duplicate IPs.
func TestConcurrentAddDeviceAssignsUniqueIPs(t *testing.T) {
	const n = 24

	dm := New(&fakeWgInterface{}, storage.NewMemoryStorage(), "10.44.0.0/24", "")
	identity := testIdentity("alice")

	start := make(chan struct{})
	errs := make(chan error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines at the same time
			_, err := dm.AddDevice(identity, fmt.Sprintf("device-%d", i), testPublicKey(i), "", false, "", "")
			if err != nil {
				errs <- fmt.Errorf("AddDevice(device-%d): %w", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	devices, err := dm.ListDevices(identity.Subject)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != n {
		t.Fatalf("expected %d devices, got %d", n, len(devices))
	}

	subnet := netip.MustParsePrefix("10.44.0.0/24")
	seen := make(map[string]string, n)
	for _, dev := range devices {
		if dev.Address == "" {
			t.Errorf("device %q has no address", dev.Name)
			continue
		}
		prefix, err := netip.ParsePrefix(dev.Address)
		if err != nil {
			t.Errorf("device %q has invalid address %q: %v", dev.Name, dev.Address, err)
			continue
		}
		if !subnet.Contains(prefix.Addr()) {
			t.Errorf("device %q address %q is outside the subnet %s", dev.Name, dev.Address, subnet)
		}
		if other, dup := seen[dev.Address]; dup {
			t.Errorf("duplicate IP assignment: %q assigned to both %q and %q", dev.Address, other, dev.Name)
		}
		seen[dev.Address] = dev.Name
	}
}
