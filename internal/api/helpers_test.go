package api

import (
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// noopWireGuardInterface satisfies wgembed.WireGuardInterface without
// touching real network/kernel state.
type noopWireGuardInterface struct{}

func (noopWireGuardInterface) LoadConfig(*wgembed.ConfigFile) error   { return nil }
func (noopWireGuardInterface) AddPeer(string, string, []string) error { return nil }
func (noopWireGuardInterface) ListPeers() ([]wgtypes.Peer, error)     { return nil, nil }
func (noopWireGuardInterface) RemovePeer(string) error                { return nil }
func (noopWireGuardInterface) PublicKey() (string, error)             { return "", nil }
func (noopWireGuardInterface) Close() error                           { return nil }
func (noopWireGuardInterface) Ping() error                            { return nil }

// failingStorage wraps in-memory storage and fails every List call, to
// exercise the error paths of the services.
type failingStorage struct {
	storage.Storage
}

func (failingStorage) List(string) ([]*storage.Device, error) {
	return nil, errors.New("storage unavailable")
}
