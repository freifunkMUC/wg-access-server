package devices

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

type DeviceManager struct {
	wg      wgembed.WireGuardInterface
	storage storage.Storage
	cidr    string
	cidrv6  string
	// maxDevicesPerUser caps how many devices one user may have. Zero or
	// less means no limit.
	maxDevicesPerUser int

	// firewallSync is told what the firewall has to be built from whenever
	// that changes, and firewall is what it was told last. The rules are
	// built from the configuration at startup and know nothing of the routes
	// an admin adds later, nor of who is in which access policy.
	firewallSync func(FirewallState) error
	firewallMu   sync.Mutex
	firewall     FirewallState

	// resync asks for everything to be brought in line with storage. It has
	// one slot: one runs at a time and one more is remembered.
	resync chan struct{}
}

// Option configures a DeviceManager.
type Option func(*DeviceManager)

// WithMaxDevicesPerUser limits how many devices a single user may create.
// Zero or less leaves the number unlimited.
func WithMaxDevicesPerUser(max int) Option {
	return func(d *DeviceManager) {
		d.maxDevicesPerUser = max
	}
}

// WithFirewallSync registers what to do when what the firewall has to be built
// from changes: the networks routed through devices, and which devices belong
// to which access policy. It is called with the whole state, not only what
// changed, and only when it differs from the last call.
func WithFirewallSync(sync func(FirewallState) error) Option {
	return func(d *DeviceManager) {
		d.firewallSync = sync
	}
}

type User struct {
	Name        string
	DisplayName string
	// LastLogin is when they last signed in, if the server has seen them
	// since it started remembering that.
	LastLogin *time.Time
	// Policies are the access policies they were in at that login.
	Policies []string
	// TwoFactor is whether they are asked for a code when they sign in. An
	// admin sees it so that they know who to reset when a phone is gone.
	TwoFactor bool
}

// https://lists.zx2c4.com/pipermail/wireguard/2020-December/006222.html
var wgKeyRegex = regexp.MustCompile("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")

// ValidationError carries a message meant for the user: it says what they got
// wrong, not how the server works. Everything else that goes wrong stays in
// the log, so a client never sees storage or schema details.
type ValidationError struct {
	msg string
}

func (e *ValidationError) Error() string {
	return e.msg
}

func invalid(format string, args ...interface{}) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// maxDeviceNameLength matches the size of the name column. A longer name is
// rejected here rather than at the database: MySQL outside of strict mode
// truncates it instead of failing, and a truncated name can collide with a
// device that already exists.
const maxDeviceNameLength = 100

// validateDeviceName rejects names that the rest of the system cannot carry.
// It deliberately allows everything else, including dots and spaces, because
// devices with such names already exist.
func validateDeviceName(name string) error {
	if strings.TrimSpace(name) == "" {
		return invalid("Device name must not be empty.")
	}
	// The column counts characters, not bytes, so an umlaut must not count twice.
	if utf8.RuneCountInString(name) > maxDeviceNameLength {
		// errors.Errorf, not fmt.Errorf, to match the sentence style of the
		// other validation messages: they are shown to the user in the web UI.
		return invalid("Device name must be at most %d characters long.", maxDeviceNameLength)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return invalid("Device name must not contain control characters.")
		}
	}
	return nil
}

func New(wg wgembed.WireGuardInterface, s storage.Storage, cidr, cidrv6 string, opts ...Option) *DeviceManager {
	d := &DeviceManager{wg: wg, storage: s, cidr: cidr, cidrv6: cidrv6, resync: make(chan struct{}, 1)}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// StartSync keeps the WireGuard peers in sync with storage and starts the
// background loops. They run until ctx is cancelled, so a shutdown does not
// leave a metadata sync or a deletion pass running against a closed database.
func (d *DeviceManager) StartSync(ctx context.Context, enableMetadataCollection, enableInactiveDeviceDeletion bool, inactiveDeviceGracePeriod time.Duration) error {
	// Start listening to the device add/remove events
	d.storage.OnAdd(func(device *storage.Device) {
		logrus.Infof("Storage event: add device '%s' (public key: '%s') for user: %s %s", device.Name, device.PublicKey, device.OwnerName, device.Owner)
		if err := d.applyPeer(device); err != nil {
			logrus.Error(fmt.Errorf("failed to add WireGuard peer: %w", err))
		}
		d.Resync()
	})

	// An update is a rename or a change of the device's access. The first
	// leaves the peer alone, the second is the whole point: a device that was
	// blocked loses its peer, one that was allowed again gets it back. Every
	// replica sees the event, so a change reaches all of them.
	d.storage.OnUpdate(func(device *storage.Device) {
		logrus.Infof("Storage event: update device '%s' (public key: '%s') for user: %s %s", device.Name, device.PublicKey, device.OwnerName, device.Owner)
		if err := d.applyPeer(device); err != nil {
			logrus.Error(fmt.Errorf("failed to update WireGuard peer: %w", err))
		}
		d.Resync()
	})

	d.storage.OnDelete(func(device *storage.Device) {
		logrus.Infof("Storage event: remove device '%s' (public key: '%s') for user: %s %s", device.Name, device.PublicKey, device.OwnerName, device.Owner)
		if err := d.wg.RemovePeer(device.PublicKey); err != nil {
			logrus.Error(fmt.Errorf("failed to remove WireGuard peer: %w", err))
		}
		d.Resync()
	})

	// The storage backend asks for a resynchronization when it cannot say what
	// changed: after a reconnect that may have missed events, and - on
	// Postgres - for every change, because those notifications carry no row
	// (see storage.PgWatcher).
	//
	// They are coalesced: one runs at a time and one more is remembered, so
	// importing a hundred devices reads them all a few times instead of a
	// hundred times, and a slow sync does not hold up the events behind it.
	d.storage.OnReconnect(d.Resync)
	go resyncLoop(ctx, d, d.resync)

	// Do an initial sync of existing devices
	if err := d.sync(); err != nil {
		return fmt.Errorf("initial device sync from storage failed: %w", err)
	}

	// start the metrics loop
	if enableMetadataCollection {
		logrus.Info("Start collecting device metadata")
		go metadataLoop(ctx, d)
	}

	// start the loop that enforces the expiry dates
	go accessLoop(ctx, d)

	// start inactive devices loop
	if enableInactiveDeviceDeletion {
		if !enableMetadataCollection {
			logrus.Infof("Ignoring the automatic device deletion because the metadata collection is disabled and it is based on device metadata.")
		} else {
			logrus.Infof("Start looking for inactive devices. Inactive device grace period is set to %s", inactiveDeviceGracePeriod.String())
			go inactiveLoop(ctx, d, inactiveDeviceGracePeriod)
		}
	}

	return nil
}

func (d *DeviceManager) usedAddresses() (map[netip.Addr]bool, map[netip.Addr]bool, error) {
	stored, err := d.storage.Addresses()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list device addresses: %w", err)
	}

	usedIPv4s := make(map[netip.Addr]bool, len(stored)+3)
	usedIPv6s := make(map[netip.Addr]bool, len(stored)+3)

	// Check what IP addresses are already occupied
	for _, stored := range stored {
		addresses, unusable := network.ParseAddresses(stored)
		if len(unusable) > 0 {
			// Don't fail: one broken row would otherwise stop every user from
			// adding a device. It cannot be reserved either, so say so.
			logrus.Warnf("a device has an address that cannot be parsed ('%s') - it is not reserved for that device",
				strings.Join(unusable, ", "))
		}
		for _, addr := range addresses {
			if addr.Is4() {
				usedIPv4s[addr] = true
			} else {
				usedIPv6s[addr] = true
			}
		}
	}

	return usedIPv4s, usedIPv6s, nil
}

func (d *DeviceManager) AddDevice(identity *authsession.Identity, name string, publicKey string, presharedKey string, manualIPAssignment bool, manualIPv4Address string, manualIPv6Address string) (*storage.Device, error) {
	if err := validateDeviceName(name); err != nil {
		return nil, err
	}

	if !wgKeyRegex.MatchString(publicKey) {
		return nil, invalid("Public key has invalid format.")
	}

	// preshared key is optional
	if len(presharedKey) != 0 && !wgKeyRegex.MatchString(presharedKey) {
		return nil, invalid("Pre-shared key has invalid format.")
	}

	// Checking which names and addresses are taken and saving the new device has
	// to happen as one step. Otherwise two concurrent requests both see an
	// address as free and hand it out twice, and a client could hijack another
	// client's tunnel traffic (GHSA-j62x-qc44-h6pj). The storage makes this lock
	// hold across every server replica sharing the database, not just this process.
	var device *storage.Device
	err := d.storage.WithAllocationLock(func() error {
		var err error
		device, err = d.addDeviceLocked(identity, name, publicKey, presharedKey, manualIPAssignment, manualIPv4Address, manualIPv6Address)
		return err
	})
	if err != nil {
		return nil, err
	}
	return device, nil
}

// addDeviceLocked does the part of AddDevice that must not overlap with any
// other device creation. Callers must hold the storage's allocation lock.
func (d *DeviceManager) addDeviceLocked(identity *authsession.Identity, name string, publicKey string, presharedKey string, manualIPAssignment bool, manualIPv4Address string, manualIPv6Address string) (*storage.Device, error) {
	nameTaken := false
	devices, err := d.ListDevices(identity.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	for _, x := range devices {
		if x.Name == name {
			nameTaken = true
			break
		}
	}

	if nameTaken {
		return nil, invalid("Device name already taken.")
	}

	// Checked under the allocation lock together with the name, so two
	// requests at the same time cannot both slip past the limit.
	if d.maxDevicesPerUser > 0 && len(devices) >= d.maxDevicesPerUser {
		return nil, invalid("You already have %d devices, which is the maximum allowed. Delete one to add another.", d.maxDevicesPerUser)
	}

	clientAddr := ""
	if manualIPAssignment {
		if manualIPv4Address == "" && manualIPv6Address == "" {
			return nil, invalid("Manual IP assignment enabled but no IP address provided.")
		}

		usedIPv4s, usedIPv6s, err := d.usedAddresses()
		if err != nil {
			return nil, fmt.Errorf("failed to get used addresses: %w", err)
		}

		var ipv4Addr, ipv6Addr string

		if manualIPv4Address != "" {
			if d.cidr == "" {
				return nil, invalid("Manual IPv4 assignment not possible, IPv4 subnet is not configured.")
			}

			ipv4, err := netip.ParseAddr(manualIPv4Address)
			if err != nil {
				return nil, invalid("Manual IPv4 address is not a valid address.")
			}
			if !ipv4.Is4() {
				return nil, invalid("Manual IPv4 address is not a valid IPv4 address.")
			}

			vpnsubnetv4 := netip.MustParsePrefix(d.cidr)
			if !vpnsubnetv4.Contains(ipv4) {
				return nil, invalid("Manual IPv4 address %s is not in the configured subnet %s.", manualIPv4Address, d.cidr)
			}

			// also check for server and network address
			startIPv4 := vpnsubnetv4.Masked().Addr()
			if ipv4 == startIPv4 || ipv4 == startIPv4.Next() {
				return nil, invalid("Manual IPv4 address %s is reserved.", manualIPv4Address)
			}

			if usedIPv4s[ipv4] {
				return nil, invalid("Manual IPv4 address %s is already in use.", manualIPv4Address)
			}

			ipv4Addr = netip.PrefixFrom(ipv4, 32).String()
		}

		if manualIPv6Address != "" {
			if d.cidrv6 == "" {
				return nil, invalid("Manual IPv6 assignment not possible, IPv6 subnet is not configured.")
			}

			ipv6, err := netip.ParseAddr(manualIPv6Address)
			if err != nil {
				return nil, invalid("Manual IPv6 address is not a valid address.")
			}
			if !ipv6.Is6() {
				return nil, invalid("Manual IPv6 address is not a valid IPv6 address.")
			}

			vpnsubnetv6 := netip.MustParsePrefix(d.cidrv6)
			if !vpnsubnetv6.Contains(ipv6) {
				return nil, invalid("Manual IPv6 address %s is not in the configured subnet %s.", manualIPv6Address, d.cidrv6)
			}

			// also check for server and network address
			startIPv6 := vpnsubnetv6.Masked().Addr()
			if ipv6 == startIPv6 || ipv6 == startIPv6.Next() {
				return nil, invalid("Manual IPv6 address %s is reserved.", manualIPv6Address)
			}

			if usedIPv6s[ipv6] {
				return nil, invalid("Manual IPv6 address %s is already in use.", manualIPv6Address)
			}

			ipv6Addr = netip.PrefixFrom(ipv6, 128).String()
		}

		if ipv4Addr != "" && ipv6Addr != "" {
			clientAddr = fmt.Sprintf("%s, %s", ipv4Addr, ipv6Addr)
		} else if ipv4Addr != "" {
			clientAddr = ipv4Addr
		} else {
			clientAddr = ipv6Addr
		}

	} else {
		clientAddr, err = d.nextClientAddressLocked()
		if err != nil {
			return nil, fmt.Errorf("failed to generate an ip address for device: %w", err)
		}
	}

	device := &storage.Device{
		Owner:         identity.Subject,
		OwnerName:     identity.Name,
		OwnerEmail:    identity.Email,
		OwnerProvider: identity.Provider,
		Name:          name,
		PublicKey:     publicKey,
		PresharedKey:  presharedKey,
		Address:       clientAddr,
		CreatedAt:     time.Now(),
	}

	if err := d.SaveDevice(device); err != nil {
		return nil, fmt.Errorf("failed to save the new device: %w", err)
	}

	return device, nil
}

func (d *DeviceManager) SaveDevice(device *storage.Device) error {
	return d.storage.Save(device)
}

// RecordMetadata stores what a metadata sync observed. See
// storage.Storage.RecordMetadata for how updates are combined.
func (d *DeviceManager) RecordMetadata(updates []storage.MetadataUpdate) error {
	return d.storage.RecordMetadata(updates)
}

func (d *DeviceManager) sync() error {
	devices, err := d.ListAllDevices()
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	peers, err := d.wg.ListPeers()
	if err != nil {
		return fmt.Errorf("failed to list peers: %w", err)
	}

	// Remove any peers for devices that are no longer in storage, or that may
	// not connect. The keys go into a set first: searching the devices for
	// every peer would compare each device against each peer, which a server
	// with a few thousand of them feels at every start and every storage
	// reconnect.
	now := time.Now()
	allowed := make(map[string]bool, len(devices))
	for _, device := range devices {
		if device.AccessAllowed(now) {
			allowed[device.PublicKey] = true
		}
	}
	for _, peer := range peers {
		if !allowed[peer.PublicKey.String()] {
			if err := d.wg.RemovePeer(peer.PublicKey.String()); err != nil {
				logrus.Error(fmt.Errorf("failed to remove peer during sync: %s: %w", peer.PublicKey.String(), err))
			}
		}
	}

	// Add peers for the devices the interface does not already carry as they
	// are stored. Configuring one is a round trip to the kernel, and a sync
	// after a storage reconnect finds almost everything in place already.
	configured := make(map[string]wgtypes.Peer, len(peers))
	for _, peer := range peers {
		configured[peer.PublicKey.String()] = peer
	}
	for _, device := range devices {
		if !allowed[device.PublicKey] {
			continue
		}
		if peer, ok := configured[device.PublicKey]; ok && peerMatches(peer, device) {
			continue
		}
		if err := d.wg.AddPeer(device.PublicKey, device.PresharedKey, device.AllowedIPs()); err != nil {
			logrus.Warn(fmt.Errorf("failed to add device during sync: %s: %w", device.Name, err))
		}
	}

	d.syncFirewallState(devices)

	return nil
}

// applyPeer brings the WireGuard peer of one device in line with what is
// stored: a device that may connect has a peer, a blocked or expired one has
// none. Removing a peer that is not there is not an error, so this can run for
// any device without looking first.
func (d *DeviceManager) applyPeer(device *storage.Device) error {
	if !device.AccessAllowed(time.Now()) {
		if err := d.wg.RemovePeer(device.PublicKey); err != nil {
			return fmt.Errorf("failed to remove the peer of a device that may not connect: %w", err)
		}
		return nil
	}
	return d.wg.AddPeer(device.PublicKey, device.PresharedKey, device.AllowedIPs())
}

// peerMatches reports whether the interface carries the device as it is
// stored: the same allowed IPs - its addresses and what is routed through it -
// and the same pre-shared key. Anything else - a renamed key, an address that
// moved, a route that was added, a device that is not there at all - means the
// peer has to be configured again.
func peerMatches(peer wgtypes.Peer, device *storage.Device) bool {
	if peer.PresharedKey.String() != presharedKeyOf(device) {
		return false
	}

	stored := device.AllowedIPs()
	if len(peer.AllowedIPs) != len(stored) {
		return false
	}
	// the interface reports the network of each address, so compare in that
	// form rather than as it was written
	allowed := make(map[string]bool, len(peer.AllowedIPs))
	for _, ipnet := range peer.AllowedIPs {
		allowed[ipnet.String()] = true
	}
	for _, address := range stored {
		_, ipnet, err := net.ParseCIDR(address)
		if err != nil || ipnet == nil || !allowed[ipnet.String()] {
			return false
		}
	}
	return true
}

// presharedKeyOf is the device's pre-shared key in the form the interface
// reports it: a device without one matches the key of all zeroes.
func presharedKeyOf(device *storage.Device) string {
	if device.PresharedKey == "" {
		return (wgtypes.Key{}).String()
	}
	key, err := wgtypes.ParseKey(device.PresharedKey)
	if err != nil {
		// unusable as stored, so the peer cannot match it either
		return ""
	}
	return key.String()
}

// ListAllDevices returns every device on the server, for an admin.
func (d *DeviceManager) ListAllDevices() ([]*storage.Device, error) {
	devices, err := d.storage.List("")
	if err != nil {
		return nil, err
	}
	return d.withOwnerNames(devices), nil
}

// withOwnerNames fills in the owner name and email a device is missing. A
// device records both as they were when it was added, so one added while the
// identity provider sent no name keeps calling its owner by their subject for
// good. The users table has the newer answer, and an admin reading a list of
// devices wants to see people, not opaque identifiers.
func (d *DeviceManager) withOwnerNames(devices []*storage.Device) []*storage.Device {
	incomplete := false
	for _, device := range devices {
		if device.OwnerName == "" || device.OwnerEmail == "" {
			incomplete = true
			break
		}
	}
	if !incomplete {
		return devices
	}

	users, err := d.storage.Users()
	if err != nil {
		// not worth failing the listing over: the devices are still correct,
		// they just name some of their owners by subject
		logrus.Warn(fmt.Errorf("failed to look up the names of device owners: %w", err))
		return devices
	}
	known := make(map[string]*storage.User, len(users))
	for _, user := range users {
		known[user.Subject] = user
	}

	filled := make([]*storage.Device, 0, len(devices))
	for _, device := range devices {
		user, ok := known[device.Owner]
		if !ok || (device.OwnerName != "" && device.OwnerEmail != "") {
			filled = append(filled, device)
			continue
		}
		// a copy: the stored device is not ours to change, and a storage
		// backend may well have handed out the one it keeps
		completed := *device
		if completed.OwnerName == "" {
			completed.OwnerName = user.Name
		}
		if completed.OwnerEmail == "" {
			completed.OwnerEmail = user.Email
		}
		filled = append(filled, &completed)
	}
	return filled
}

func (d *DeviceManager) ListDevices(user string) ([]*storage.Device, error) {
	return d.storage.List(user)
}

// RenameDevice gives a device a new name. The public key and the address stay
// as they are, so the client keeps working and its configuration file stays
// valid - only the label in the web UI changes.
func (d *DeviceManager) RenameDevice(user string, name string, newName string) (*storage.Device, error) {
	if err := validateDeviceName(newName); err != nil {
		return nil, err
	}

	if name == newName {
		return d.storage.Get(user, name)
	}

	// The same lock as device creation, so a rename cannot take a name that a
	// concurrent request is about to use, and vice versa.
	var renamed *storage.Device
	err := d.storage.WithAllocationLock(func() error {
		device, err := d.storage.Get(user, name)
		if err != nil {
			return fmt.Errorf("failed to retrieve device: %w", err)
		}

		devices, err := d.ListDevices(user)
		if err != nil {
			return fmt.Errorf("failed to list devices: %w", err)
		}
		for _, existing := range devices {
			if existing.Name == newName {
				return invalid("Device name already taken.")
			}
		}

		renamed, err = d.storage.Rename(device, newName)
		return err
	})
	if err != nil {
		return nil, err
	}

	return renamed, nil
}

// RotateDeviceKey gives a device new key material and returns it as it is now.
// Everything else stays: the name, the address, the networks behind it and its
// access, so a key can be replaced without anything around the device being
// changed - the client configuration is the only thing that has to be set up
// anew, and whoever holds the old private key is out.
//
// The old peer goes right away rather than at the next sync: until it does,
// the key that is being replaced still reaches the VPN, and replacing a key
// somebody else may have is the reason to do this at all.
func (d *DeviceManager) RotateDeviceKey(user string, name string, publicKey string, presharedKey string) (*storage.Device, error) {
	if !wgKeyRegex.MatchString(publicKey) {
		return nil, invalid("Public key has invalid format.")
	}

	// preshared key is optional, as it is when a device is added
	if len(presharedKey) != 0 && !wgKeyRegex.MatchString(presharedKey) {
		return nil, invalid("Pre-shared key has invalid format.")
	}

	device, err := d.storage.Get(user, name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve device: %w", err)
	}

	if device.PublicKey == publicKey {
		return nil, invalid("This is the key the device already uses.")
	}

	// The unique index would refuse it as well, but with a message about a
	// constraint rather than about the device somebody else is using.
	if existing, err := d.storage.GetByPublicKey(publicKey); err == nil && existing != nil {
		return nil, invalid("Another device already uses this key.")
	}

	previous := device.PublicKey
	changed, err := d.storage.SetKeys(device, publicKey, presharedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to change the keys of the device: %w", err)
	}

	// The peer of the old key is not in storage any more, so the sync that
	// follows the update event removes it on every replica. Doing it here as
	// well is what makes the old key stop working now rather than then.
	if err := d.wg.RemovePeer(previous); err != nil {
		logrus.Warn(fmt.Errorf("failed to remove the peer of the replaced key: %w", err))
	}
	if err := d.applyPeer(changed); err != nil {
		logrus.Warn(fmt.Errorf("failed to add the peer of the new key: %w", err))
	}

	return changed, nil
}

// AccessChange is what SetDeviceAccess should change about a device. A field
// that is not set is left as it is, so one of the two can be changed without
// sending the other back - two admins working at the same time then cannot
// undo each other's change.
type AccessChange struct {
	// Disabled blocks the device, or lifts a block.
	Disabled *bool
	// ExpiresAt is when the device's access ends. It must be in the future:
	// ending access now is what Disabled is for.
	ExpiresAt *time.Time
	// ClearExpiresAt removes the expiry, so the device's access no longer
	// ends. It takes precedence over ExpiresAt.
	ClearExpiresAt bool
}

// SetDeviceAccess blocks a device from connecting or gives it an expiry date,
// and returns the device as it is now. The name, the key and the address stay
// as they are: the client configuration the user has stays valid, and once the
// device may connect again it works without them setting it up anew.
//
// Whether the caller may change this is decided by the API - a user must not
// be able to lift a block or extend an expiry an admin set on their device.
func (d *DeviceManager) SetDeviceAccess(user string, name string, change AccessChange) (*storage.Device, error) {
	device, err := d.storage.Get(user, name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve device: %w", err)
	}

	disabled := device.Disabled
	if change.Disabled != nil {
		disabled = *change.Disabled
	}

	expiresAt := device.ExpiresAt
	switch {
	case change.ClearExpiresAt:
		expiresAt = nil
	case change.ExpiresAt != nil:
		if !change.ExpiresAt.After(time.Now()) {
			return nil, invalid("The expiry date must be in the future. Disable the device to end its access now.")
		}
		expiresAt = change.ExpiresAt
	}

	changed, err := d.storage.SetAccess(device, disabled, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to change the access of the device: %w", err)
	}

	return changed, nil
}

func (d *DeviceManager) DeleteDevice(user string, name string) error {
	device, err := d.storage.Get(user, name)
	if err != nil {
		return fmt.Errorf("failed to retrieve device: %w", err)
	}

	if err := d.storage.Delete(device); err != nil {
		return err
	}

	return nil
}

func (d *DeviceManager) GetByPublicKey(publicKey string) (*storage.Device, error) {
	return d.storage.GetByPublicKey(publicKey)
}

// nextClientAddressLocked returns the next free client address.
// Callers must hold the storage's allocation lock.
//
// It asks storage which addresses are taken and then walks the subnet from
// its start until it finds one that is not, so the gaps that deleted devices
// leave are filled again. Both parts are linear in the number of devices:
// about two milliseconds at five thousand, two thirds of it spent parsing the
// stored addresses rather than walking, which BenchmarkNextClientAddress
// measures. Nothing is remembered between calls on purpose - the replicas
// share the allocation lock but not their memory, and an address that a
// device gave up elsewhere has to come back into use.
func (d *DeviceManager) nextClientAddressLocked() (string, error) {
	usedIPv4s, usedIPv6s, err := d.usedAddresses()
	if err != nil {
		return "", fmt.Errorf("failed to get used addresses: %w", err)
	}

	var ipv4 string
	var ipv6 string

	if d.cidr != "" {
		vpnsubnetv4 := netip.MustParsePrefix(d.cidr)
		startIPv4 := vpnsubnetv4.Masked().Addr()

		// Add the network address and the VPN server address to the list of occupied addresses
		usedIPv4s[startIPv4] = true        // x.x.x.0
		usedIPv4s[startIPv4.Next()] = true // x.x.x.1

		for ip := startIPv4.Next().Next(); vpnsubnetv4.Contains(ip); ip = ip.Next() {
			if !usedIPv4s[ip] {
				ipv4 = netip.PrefixFrom(ip, 32).String()
				break
			}
		}
	}

	if d.cidrv6 != "" {
		vpnsubnetv6 := netip.MustParsePrefix(d.cidrv6)
		startIPv6 := vpnsubnetv6.Masked().Addr()

		// Add the network address and the VPN server address to the list of occupied addresses
		usedIPv6s[startIPv6] = true        // ::0
		usedIPv6s[startIPv6.Next()] = true // ::1

		for ip := startIPv6.Next().Next(); vpnsubnetv6.Contains(ip); ip = ip.Next() {
			if !usedIPv6s[ip] {
				ipv6 = netip.PrefixFrom(ip, 128).String()
				break
			}
		}
	}

	if ipv4 != "" {
		if ipv6 != "" {
			return fmt.Sprintf("%s, %s", ipv4, ipv6), nil
		} else if d.cidrv6 != "" {
			return "", fmt.Errorf("there are no free IP addresses in the vpn subnet: '%s'", d.cidrv6)
		} else {
			return ipv4, nil
		}
	} else if ipv6 != "" {
		if d.cidr != "" {
			return "", fmt.Errorf("there are no free IP addresses in the vpn subnet: '%s'", d.cidr)
		} else {
			return ipv6, nil
		}
	} else {
		return "", fmt.Errorf("there are no free IP addresses in the vpn subnets: '%s', '%s'", d.cidr, d.cidrv6)
	}
}

// ListUsers returns everybody this server knows: whoever signed in since it
// started remembering that, and whoever owns a device. The two overlap almost
// always - the exceptions are somebody who signed in and has not added a
// device yet, and a device of somebody who has not signed in since the server
// learned to remember it.
func (d *DeviceManager) ListUsers() ([]*User, error) {
	stored, err := d.storage.Users()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve users: %w", err)
	}

	users := []*User{}
	byName := map[string]*User{}
	for _, user := range stored {
		lastLogin := user.LastLogin
		listed := &User{
			Name: user.Subject, DisplayName: user.Name,
			LastLogin: &lastLogin, Policies: user.PolicyList(),
			TwoFactor: user.TwoFactorEnabled(),
		}
		users = append(users, listed)
		byName[user.Subject] = listed
	}

	devices, err := d.storage.List("")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve devices: %w", err)
	}
	for _, dev := range devices {
		if listed, ok := byName[dev.Owner]; ok {
			// a device knows the display name too, and it is the newer one
			// only when the user has not signed in since
			if listed.DisplayName == "" {
				listed.DisplayName = dev.OwnerName
			}
			continue
		}
		listed := &User{Name: dev.Owner, DisplayName: dev.OwnerName}
		users = append(users, listed)
		byName[dev.Owner] = listed
	}

	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })

	return users, nil
}

// ForgetUser removes what the server remembers about somebody. Their devices
// and tokens are not touched: whoever deletes a user deletes those first.
func (d *DeviceManager) ForgetUser(subject string) error {
	if err := d.storage.DeleteUser(subject); err != nil {
		return fmt.Errorf("failed to forget the user '%s': %w", subject, err)
	}
	return nil
}

// DeleteDevicesForUser removes every device of a user, all of them or none.
// Leaving half of a revoked user's devices in place would be the worse
// outcome, so the storage does this in one transaction and reports the
// removed devices once it has committed.
func (d *DeviceManager) DeleteDevicesForUser(user string) error {
	deleted, err := d.storage.DeleteForOwner(user)
	if err != nil {
		return fmt.Errorf("failed to delete the devices of user '%s': %w", user, err)
	}

	logrus.Infof("Deleted %d devices of user '%s'", len(deleted), user)
	return nil
}

// BlockDevicesForUser stops every device of a user from connecting, without
// deleting any of them, and returns how many were still able to connect. The
// keys and addresses stay: this is how an admin takes access away from
// somebody who may get it back, and their client configurations keep working
// the moment the block is lifted.
func (d *DeviceManager) BlockDevicesForUser(user string) (int, error) {
	blocked, err := d.storage.BlockForOwner(user)
	if err != nil {
		return 0, fmt.Errorf("failed to block the devices of user '%s': %w", user, err)
	}

	logrus.Infof("Blocked %d devices of user '%s'", len(blocked), user)
	return len(blocked), nil
}

func (d *DeviceManager) Ping() error {
	if err := d.storage.Ping(); err != nil {
		return fmt.Errorf("failed to ping storage: %w", err)
	}

	if err := d.wg.Ping(); err != nil {
		return fmt.Errorf("failed to ping WireGuard: %w", err)
	}

	return nil
}

func IsConnected(lastHandshake time.Time) bool {
	return lastHandshake.After(time.Now().Add(-3 * time.Minute))
}
