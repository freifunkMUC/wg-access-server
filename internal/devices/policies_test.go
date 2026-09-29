package devices

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func policyManager(t *testing.T) (*DeviceManager, storage.Storage, func() []FirewallState) {
	t.Helper()

	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// the resynchronization runs in the background, so what it reports and
	// what the test reads need a lock between them
	var mu sync.Mutex
	var states []FirewallState
	wg := &countingInterface{WireGuardInterface: wgembed.NewNoOpInterface(), peers: map[string]wgtypes.Peer{}}
	manager := New(wg, s, "10.44.0.0/24", "fd48:4c4:7aa9::/64", WithFirewallSync(func(state FirewallState) error {
		mu.Lock()
		defer mu.Unlock()
		states = append(states, state)
		return nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := manager.StartSync(ctx, false, false, 0); err != nil {
		t.Fatal(err)
	}

	return manager, s, func() []FirewallState {
		mu.Lock()
		defer mu.Unlock()
		return append([]FirewallState(nil), states...)
	}
}

func lastState(t *testing.T, states func() []FirewallState) FirewallState {
	t.Helper()
	all := states()
	if len(all) == 0 {
		t.Fatal("the firewall was never told anything")
	}
	return all[len(all)-1]
}

// The devices of the people in a policy are what its rules apply to, so the
// firewall has to be told which addresses those are.
func TestFirewallStateCollectsThePolicyMembers(t *testing.T) {
	manager, s, states := policyManager(t)

	if err := s.SaveUser(&storage.User{Subject: "alice", Policies: "staff, contractors"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUser(&storage.User{Subject: "bob", Policies: "staff"}); err != nil {
		t.Fatal(err)
	}
	// carol is in no policy: her devices keep what everybody else may reach
	if err := s.SaveUser(&storage.User{Subject: "carol"}); err != nil {
		t.Fatal(err)
	}

	for _, device := range []*storage.Device{
		{Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32, fd48:4c4:7aa9::2/128"},
		{Owner: "bob", Name: "phone", PublicKey: testDeviceKey(t, 2), Address: "10.44.0.3/32"},
		{Owner: "carol", Name: "tablet", PublicKey: testDeviceKey(t, 3), Address: "10.44.0.4/32"},
	} {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}

	state := lastState(t, states)
	if got := strings.Join(state.Policies["staff"], " "); got != "10.44.0.2/32 10.44.0.3/32 fd48:4c4:7aa9::2/128" {
		t.Errorf("staff = %q, want the devices of alice and bob", got)
	}
	if got := strings.Join(state.Policies["contractors"], " "); got != "10.44.0.2/32 fd48:4c4:7aa9::2/128" {
		t.Errorf("contractors = %q, want alice's device", got)
	}
	if _, ok := state.Policies["nobody"]; ok {
		t.Error("a policy nobody is in should not be in the state at all")
	}
}

// A device that may not connect has no peer, so nothing can come from its
// address. Listing it in a policy would say otherwise.
func TestFirewallStateLeavesOutDevicesThatMayNotConnect(t *testing.T) {
	manager, s, states := policyManager(t)

	if err := s.SaveUser(&storage.User{Subject: "alice", Policies: "staff"}); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Hour)
	for _, device := range []*storage.Device{
		{Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32"},
		{Owner: "alice", Name: "blocked", PublicKey: testDeviceKey(t, 2), Address: "10.44.0.3/32", Disabled: true},
		{Owner: "alice", Name: "expired", PublicKey: testDeviceKey(t, 3), Address: "10.44.0.4/32", ExpiresAt: &expired},
	} {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(lastState(t, states).Policies["staff"], " "); got != "10.44.0.2/32" {
		t.Errorf("staff = %q, want only the device that may connect", got)
	}
}

// Somebody signing in is when their policies can change, and the rules have to
// follow. Recomputing what has not changed must not rebuild them, though.
func TestFirewallIsToldOnlyAboutRealChanges(t *testing.T) {
	manager, s, states := policyManager(t)

	if err := s.SaveUser(&storage.User{Subject: "alice", Policies: "staff"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&storage.Device{
		Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32",
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	before := len(states())
	if before == 0 {
		t.Fatal("the firewall was not told about the first device")
	}

	// the same state again
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if len(states()) != before {
		t.Errorf("the firewall was rebuilt for a state it already had: %+v", states())
	}

	// ... and a sign-in that changes the policies does reach it
	if err := s.SaveUser(&storage.User{Subject: "alice", Policies: "staff, contractors"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.sync(); err != nil {
		t.Fatal(err)
	}
	if len(states()) != before+1 {
		t.Fatalf("the firewall was told %d times, want one more after the policies changed", len(states()))
	}
	if _, ok := lastState(t, states).Policies["contractors"]; !ok {
		t.Error("the new policy did not reach the firewall")
	}
}
