package devices

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// benchKey is a public key in the form the server expects: 32 bytes, base64.
func benchKey(i int) string {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], uint64(i)+1)
	return base64.StdEncoding.EncodeToString(key[:])
}

// benchManager fills a device manager with count devices, as a deployment
// that has been running for a while would have. It uses in-memory storage,
// which leaves out the database round trips; WG_BENCH_STORAGE points it at a
// real backend instead, e.g.
//
//	WG_BENCH_STORAGE=postgresql://user:password@localhost:5432/db?sslmode=disable
func benchManager(b *testing.B, count int) *DeviceManager {
	b.Helper()
	uri := os.Getenv("WG_BENCH_STORAGE")
	if uri == "" {
		uri = "memory://"
	}
	s, err := storage.NewStorage(uri)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Open(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })

	// whatever an earlier run left behind
	existing, err := s.List("")
	if err != nil {
		b.Fatal(err)
	}
	for _, device := range existing {
		if err := s.Delete(device); err != nil {
			b.Fatal(err)
		}
	}
	// a /16, so that thousands of devices fit
	manager := New(wgembed.NewNoOpInterface(), s, "10.44.0.0/16", "fd48:4c4:7aa9::/64")
	for i := range count {
		device := &storage.Device{
			Owner:     fmt.Sprintf("user-%d", i),
			Name:      fmt.Sprintf("device-%d", i),
			PublicKey: benchKey(i),
			Address:   fmt.Sprintf("10.44.%d.%d/32, fd48:4c4:7aa9::%x/128", (i+2)/256, (i+2)%256, i+2),
		}
		if err := s.Save(device); err != nil {
			b.Fatal(err)
		}
	}
	return manager
}

// BenchmarkAddDevice measures what a user waits for when adding a device, on
// top of a growing number of devices already in storage. The address is
// picked under the allocation lock, so this is also how long every other
// creation waits.
func BenchmarkAddDevice(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			manager := benchManager(b, count)
			identity := &authsession.Identity{Provider: "simple", Subject: "newcomer", Name: "newcomer"}
			b.ResetTimer()
			for i := range b.N {
				if _, err := manager.AddDevice(identity, fmt.Sprintf("new-%d", i), benchKey(count+i), "", false, "", ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkListAllDevices is what the admin page and every metrics scrape do.
func BenchmarkListAllDevices(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			manager := benchManager(b, count)
			b.ResetTimer()
			for range b.N {
				if _, err := manager.ListAllDevices(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// syncInterface answers like a WireGuard interface that already carries a
// peer for every device, which is the state a sync after a storage reconnect
// finds.
type syncInterface struct {
	wgembed.WireGuardInterface
	peers []wgtypes.Peer
}

func (i *syncInterface) ListPeers() ([]wgtypes.Peer, error) { return i.peers, nil }
func (i *syncInterface) AddPeer(string, string, []string) error {
	return nil
}
func (i *syncInterface) RemovePeer(string) error { return nil }

// BenchmarkSync is the work behind bringing the interface in line with
// storage: at start-up, and again whenever the storage backend reconnects.
func BenchmarkSync(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			manager := benchManager(b, count)
			devs, err := manager.ListAllDevices()
			if err != nil {
				b.Fatal(err)
			}
			peers := make([]wgtypes.Peer, 0, len(devs))
			for _, device := range devs {
				key, err := wgtypes.ParseKey(device.PublicKey)
				if err != nil {
					b.Fatal(err)
				}
				peers = append(peers, wgtypes.Peer{PublicKey: key})
			}
			manager.wg = &syncInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: peers}

			b.ResetTimer()
			for range b.N {
				if err := manager.sync(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNextClientAddress measures the address picking on its own: the
// walk through the subnet, on top of the addresses storage hands over.
func BenchmarkNextClientAddress(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			manager := benchManager(b, count)
			b.ResetTimer()
			for range b.N {
				if _, err := manager.nextClientAddressLocked(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
