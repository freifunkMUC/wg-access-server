package storage

import (
	"fmt"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Storage interface {
	Watcher
	Pingable
	Save(device *Device) error
	// RecordMetadata applies what one metadata sync observed. Traffic is
	// added to the stored totals, so several server replicas and restarts
	// accumulate instead of overwriting each other. Endpoint and last
	// handshake are replaced only where an update carries a Connection.
	//
	// Unlike Save it never inserts: updates for a device deleted in the
	// meantime are dropped, so a revoked device cannot be resurrected by a
	// concurrent metadata sync. It also never emits an add event.
	RecordMetadata(updates []MetadataUpdate) error
	// WithAllocationLock runs fn while holding a lock that serializes device
	// creation, so the addresses and names fn finds free are still free when
	// fn saves the device. For Postgres and MySQL the lock lives in the
	// database and holds across every server replica sharing it; the other
	// backends are single-instance and lock within the process.
	WithAllocationLock(fn func() error) error
	// Rename changes the name of a device and returns it with the new name.
	// Neither the public key nor the address changes, so the WireGuard peer
	// is untouched and the tunnel keeps running. It emits an update event,
	// which is how the authoritative DNS zone learns the new name.
	Rename(device *Device, newName string) (*Device, error)
	List(owner string) ([]*Device, error)
	Get(owner string, name string) (*Device, error)
	GetByPublicKey(publicKey string) (*Device, error)
	Delete(device *Device) error
	// DeleteForOwner removes every device of one user and returns what it
	// removed. It is all or nothing: a failure halfway through leaves the
	// user with all of their devices rather than some of them, which matters
	// because this is how a user's access is revoked. The delete events
	// follow once the change is durable.
	DeleteForOwner(owner string) ([]*Device, error)
	Close() error
	Open() error
}

type Watcher interface {
	OnAdd(cb Callback)
	// OnUpdate reports a device whose stored data changed without the device
	// itself coming or going - a rename. The WireGuard peer is unaffected by
	// those, but anything that keeps a copy of the names (the authoritative
	// DNS zone) has to hear about them.
	//
	// Metadata writes deliberately do not show up here: they happen every 30
	// seconds per active device and per replica, and nothing needs to react
	// to them.
	OnUpdate(cb Callback)
	OnDelete(cb Callback)
	OnReconnect(func())
	EmitAdd(device *Device)
	EmitUpdate(device *Device)
	EmitDelete(device *Device)
}

type Pingable interface {
	Ping() error
}

type Callback func(device *Device)

// MetadataUpdate is what one server replica observed about a peer since its
// previous metadata sync.
type MetadataUpdate struct {
	PublicKey string
	// ReceiveBytes and TransmitBytes are the traffic seen since the previous
	// sync, not WireGuard's absolute counters. Every replica only sees the
	// traffic of its own interface, so only deltas can be combined.
	ReceiveBytes  int64
	TransmitBytes int64
	// Connection is set only by the replica currently serving the peer; nil
	// leaves the stored endpoint and last handshake untouched.
	Connection *PeerConnection
}

// PeerConnection is the connection state reported by the replica a peer is
// currently talking to.
type PeerConnection struct {
	Endpoint          string
	LastHandshakeTime time.Time
}

type Device struct {
	// Owner and Name are the primary key, which already makes the pair
	// unique. The unique_index:key they used to carry on top of that was
	// redundant - and it broke the schema on MySQL, where "key" is a
	// reserved word: the CREATE INDEX failed with a syntax error and took
	// the unique index on public_key with it (see SQLStorage.Open).
	Owner         string `json:"owner" gorm:"type:varchar(100);primaryKey"`
	OwnerName     string `json:"owner_name"`
	OwnerEmail    string `json:"owner_email"`
	OwnerProvider string `json:"owner_provider"`
	Name          string `json:"name" gorm:"type:varchar(100);primaryKey"`
	// The WireGuard peer is identified by its public key, so two devices
	// must never share one: adding the second replaces the allowed
	// addresses and the pre-shared key of the peer the first one uses, and
	// deleting it removes that peer altogether. The unique index is what
	// enforces that.
	PublicKey    string    `json:"public_key" gorm:"uniqueIndex:uix_devices_public_key"`
	PresharedKey string    `json:"preshared_key" gorm:"type:varchar(100)"`
	Address      string    `json:"address"`
	CreatedAt    time.Time `json:"created_at" gorm:"column:created_at"`

	/**
	 * Metadata fields below.
	 * All metadata tracking can be disabled
	 * from the config file.
	 */

	// Traffic is the total across all server replicas and restarts; endpoint
	// and last handshake come from the replica that served the peer last.
	LastHandshakeTime *time.Time `json:"last_handshake_time"`
	ReceiveBytes      int64      `json:"received_bytes"`
	TransmitBytes     int64      `json:"transmit_bytes"`
	Endpoint          string     `json:"endpoint"`
}

func NewStorage(uri string) (Storage, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing storage uri")
	}

	switch u.Scheme {
	case "memory":
		logrus.Warn("Storing data in memory - devices will not persist between restarts")
		return NewMemoryStorage(), nil
	case "postgresql":
		fallthrough
	case "postgres":
		fallthrough
	case "mysql":
		fallthrough
	case "sqlite3":
		logrus.Infof("Storing data in SQL backend at %s", u)
		return NewSqlStorage(u), nil
	}

	return nil, fmt.Errorf("unknown storage backend %s", u)
}
