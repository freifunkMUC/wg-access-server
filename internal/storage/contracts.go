package storage

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Storage interface {
	Watcher
	Pingable
	TokenStorage
	UserStorage
	SessionStorage
	PasskeyStorage
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
	// SetAccess stores whether a device is blocked and when its access
	// expires, and returns the device as it is now. Like Rename it leaves the
	// public key and the address alone, and emits an update event - which is
	// how every replica learns that it has to add or remove the peer.
	SetAccess(device *Device, disabled bool, expiresAt *time.Time) (*Device, error)
	// SetRoutes stores the networks that live behind a device and returns it
	// as it is now. Like SetAccess it emits an update event, which is how
	// every replica learns to route them to the device's peer.
	SetRoutes(device *Device, routes string) (*Device, error)
	// SetKeys stores new key material for a device: its name, address and
	// routes stay, so everything built around it keeps pointing at the same
	// device while the key that reaches the tunnel is a different one. A
	// public key another device already uses is refused - two devices
	// sharing one would share a peer. Like SetAccess it emits an update
	// event, which is how every replica replaces the peer.
	SetKeys(device *Device, publicKey string, presharedKey string) (*Device, error)
	List(owner string) ([]*Device, error)
	// Addresses returns the address field of every device. Picking an address
	// for a new device only needs to know which ones are taken, and reading
	// whole rows for that is what made every creation wait for the entire
	// table - while holding the allocation lock.
	Addresses() ([]string, error)
	Get(owner string, name string) (*Device, error)
	GetByPublicKey(publicKey string) (*Device, error)
	Delete(device *Device) error
	// DeleteForOwner removes every device of one user and returns what it
	// removed. It is all or nothing: a failure halfway through leaves the
	// user with all of their devices rather than some of them, which matters
	// because this is how a user's access is revoked. The delete events
	// follow once the change is durable.
	DeleteForOwner(owner string) ([]*Device, error)
	// BlockForOwner blocks every device of one user that is not blocked
	// already, and returns the devices it changed. Like DeleteForOwner it is
	// all or nothing - this is how an admin takes somebody's access away, and
	// half of it would be no revocation at all - and the update events follow
	// the commit.
	BlockForOwner(owner string) ([]*Device, error)
	Close() error
	Open() error
}

// UserStorage remembers the people who signed in. A device names its owner,
// but everything else about them - their display name, and what their identity
// provider said about which groups they are in - exists only while they have a
// session. The firewall rules and the device list are built when nobody is
// signed in, so what the provider said at the last login is kept here.
type UserStorage interface {
	// SaveUser records somebody who signed in, replacing what was recorded
	// before. It is the only way a user is created.
	SaveUser(user *User) error
	// GetUser returns what is known about somebody, or an error when they
	// have never signed in.
	GetUser(subject string) (*User, error)
	// Users returns everybody who has signed in.
	Users() ([]*User, error)
	// DeleteUser forgets somebody. Their devices and tokens are not touched -
	// whoever deletes a user deletes those first.
	DeleteUser(subject string) error
	// SetUserPassword stores a password somebody set for themselves, as a
	// bcrypt hash, together with the configured entry that was in effect when
	// they set it. An empty hash removes it and hands them back to the
	// configuration. The user has to exist.
	SetUserPassword(subject string, hash string, from string) error
	// SetUserTOTP stores the two-factor state of one user, all of it at once:
	// the secret, whether it has been confirmed, and the recovery codes that
	// are still unused. They only ever change together. The user has to
	// exist.
	SetUserTOTP(subject string, state TOTPState) error
}

// TOTPState is the two-factor state of one user as it is stored. The zero
// value is somebody who has no second factor, which is how everybody starts.
type TOTPState struct {
	// Secret is the shared secret, base32. It is set when enrolment starts
	// and only counts once EnabledAt is set: an enrolment somebody walked
	// away from must not ask them for codes.
	Secret string
	// EnabledAt is when they confirmed the enrolment with a code from their
	// app. Nil means no second factor is asked for.
	EnabledAt *time.Time
	// Recovery holds the unused recovery codes, hashed, comma separated.
	Recovery string
	// LastStep is the time step a code was last accepted at. A code is good
	// for its step and the ones either side, so without remembering this the
	// same code signs in again for as long as its window lasts.
	LastStep int64
}

// User is somebody who has signed in at least once.
type User struct {
	// Subject is what the identity provider calls them, and what a device
	// names as its owner.
	Subject  string `json:"subject" gorm:"type:varchar(100);primaryKey"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	// Policies are the names of the access policies their identity provider
	// put them in at the last login, comma-separated. Empty means the devices
	// of this user may reach what vpn.allowedIPs says.
	Policies string `json:"policies"`
	// LastLogin is when they last signed in, which is also how old everything
	// else here is.
	LastLogin time.Time `json:"last_login"`

	// PasswordHash is a password this user set for themselves, bcrypt
	// hashed. Only the built-in providers have one; everybody else's password
	// belongs to their identity provider. Empty means they never set one and
	// the configured entry is what counts.
	//
	// It is never returned to anybody: the API maps users without it.
	PasswordHash string `json:"-"`
	// WebauthnChallenge is what a passkey registration or sign-in needs
	// between its two halves, and WebauthnChallengeUntil is when it stops
	// counting. They are cleared as soon as the second half arrives.
	WebauthnChallenge      string     `json:"-"`
	WebauthnChallengeUntil *time.Time `json:"-"`

	// TotpSecret, TotpEnabledAt and TotpRecovery are the second factor; see
	// TOTPState, which is how they are read and written together. Like the
	// password they never leave the server.
	TotpSecret    string     `json:"-"`
	TotpEnabledAt *time.Time `json:"-"`
	TotpRecovery  string     `json:"-"`
	TotpLastStep  int64      `json:"-"`

	// PasswordFrom is the configured entry that was in effect when the
	// password was set. When the configuration names a different one now, an
	// admin has changed it, and theirs wins: the stored password is ignored.
	// Without this an admin could not take a password back.
	PasswordFrom string `json:"-"`
}

// TOTP returns the two-factor state of this user.
func (u *User) TOTP() TOTPState {
	return TOTPState{
		Secret: u.TotpSecret, EnabledAt: u.TotpEnabledAt,
		Recovery: u.TotpRecovery, LastStep: u.TotpLastStep,
	}
}

// TwoFactorEnabled says whether this user is asked for a code when they sign
// in: a secret alone is an enrolment nobody finished.
func (u *User) TwoFactorEnabled() bool {
	return u.TotpSecret != "" && u.TotpEnabledAt != nil
}

// PolicyList returns the policies one by one, empty for a user without any.
func (u *User) PolicyList() []string {
	return splitList(u.Policies)
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
	 * Access fields below. They say whether the device may connect at all;
	 * see AccessAllowed. Only an admin changes them.
	 */

	// Disabled blocks the device without deleting it: its WireGuard peer is
	// removed, so it cannot connect, but its address stays reserved and the
	// client configuration the user has keeps working once it is enabled again.
	Disabled bool `json:"disabled"`
	// ExpiresAt is when the device loses access, for handing out temporary
	// access. Nil means it never expires.
	ExpiresAt *time.Time `json:"expires_at"`

	// Routes are the networks that live behind this device, as a
	// comma-separated list of prefixes - what makes a device a site-to-site
	// link or a subnet router. They are part of the device's allowed IPs, so
	// the server accepts that traffic from it and sends traffic for those
	// networks to it. Only an admin may set them: a device that could claim a
	// network would be claiming everybody's traffic to it.
	Routes string `json:"routes"`

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

// AllowedIPs are the networks the WireGuard peer of this device may use: its
// own addresses, and whatever is routed through it.
func (d *Device) AllowedIPs() []string {
	allowed := splitList(d.Address)
	return append(allowed, splitList(d.Routes)...)
}

// RouteList returns the device's routes one by one, empty for a device that
// routes nothing.
func (d *Device) RouteList() []string {
	return splitList(d.Routes)
}

// splitList splits the comma-separated form both addresses and routes are
// stored in. An empty string is no entries rather than one empty entry.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			entries = append(entries, part)
		}
	}
	return entries
}

// Expired reports whether the device's access has run out at the given time.
func (d *Device) Expired(at time.Time) bool {
	return d.ExpiresAt != nil && !d.ExpiresAt.After(at)
}

// AccessAllowed reports whether the device may connect at the given time, and
// with that whether it has a WireGuard peer. A device that is blocked keeps
// everything else - its address stays reserved, its name stays taken.
func (d *Device) AccessAllowed(at time.Time) bool {
	return !d.Disabled && !d.Expired(at)
}

func NewStorage(uri string) (Storage, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("error parsing storage uri: %w", err)
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
