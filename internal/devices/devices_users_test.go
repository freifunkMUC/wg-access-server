package devices

import (
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// The list is what the admin page shows: everybody this server knows. Somebody
// who signed in but has not added a device yet belongs there as much as the
// owner of a device who has not signed in since the server learned to remember
// that.
func TestListUsersCombinesWhatIsKnown(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	login := time.Now().Truncate(time.Second)
	if err := s.SaveUser(&storage.User{
		Subject: "alice", Name: "Alice Example", Policies: "staff", LastLogin: login,
	}); err != nil {
		t.Fatal(err)
	}
	// signed in, no device yet
	if err := s.SaveUser(&storage.User{Subject: "carol", Name: "Carol Example", LastLogin: login}); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*storage.Device{
		{Owner: "alice", Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32"},
		// a device of somebody the server has not seen sign in
		{Owner: "bob", OwnerName: "Bob Example", Name: "phone", PublicKey: testDeviceKey(t, 2), Address: "10.44.0.3/32"},
	} {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}

	manager := New(wgembed.NewNoOpInterface(), s, "10.44.0.0/24", "")
	users, err := manager.ListUsers()
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 3 {
		t.Fatalf("listed %d users, want alice, bob and carol: %+v", len(users), users)
	}
	// sorted, so the order is the same from one call to the next
	for i, want := range []string{"alice", "bob", "carol"} {
		if users[i].Name != want {
			t.Errorf("user %d = %q, want %q", i, users[i].Name, want)
		}
	}
	if users[0].LastLogin == nil || !users[0].LastLogin.Equal(login) {
		t.Errorf("alice's last login = %v, want %v", users[0].LastLogin, login)
	}
	if policies := users[0].Policies; len(policies) != 1 || policies[0] != "staff" {
		t.Errorf("alice's policies = %v, want staff", policies)
	}
	if len(users[1].Policies) != 0 {
		t.Errorf("bob has policies although he was never seen signing in: %v", users[1].Policies)
	}
	if users[1].LastLogin != nil {
		t.Errorf("bob has a last login although he was never seen signing in: %v", users[1].LastLogin)
	}
	if users[1].DisplayName != "Bob Example" {
		t.Errorf("bob's display name = %q, want the one from his device", users[1].DisplayName)
	}
}

// Deleting a user has to remove what is remembered about them, or their
// identity stays behind after their devices are gone.
func TestForgetUser(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.SaveUser(&storage.User{Subject: "alice", Name: "Alice Example", LastLogin: time.Now()}); err != nil {
		t.Fatal(err)
	}

	manager := New(wgembed.NewNoOpInterface(), s, "10.44.0.0/24", "")
	if err := manager.ForgetUser("alice"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetUser("alice"); err == nil {
		t.Error("the user is still remembered after being deleted")
	}
	users, err := manager.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Errorf("the list still has %d users: %+v", len(users), users)
	}
}

// A device keeps the owner name it was given when it was added. Somebody who
// first signed in through a provider that sent no name got devices that call
// them by their subject - a hash nobody recognises - and those devices never
// learn the name their owner has since arrived with.
func TestListAllDevicesNamesOwnersFromTheUsersTable(t *testing.T) {
	s := storage.NewMemoryStorage()
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const subject = "7b1c0a4e9d2f43a8b65e0c1d8f2a37b4"
	if err := s.SaveUser(&storage.User{
		Subject: subject, Name: "Alice Example", Email: "alice@example.com", LastLogin: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*storage.Device{
		// added before the provider ever sent a name
		{Owner: subject, Name: "laptop", PublicKey: testDeviceKey(t, 1), Address: "10.44.0.2/32"},
		// added after, and its own name is the one that counts
		{
			Owner: subject, OwnerName: "Alice at the time", OwnerEmail: "alice@example.com",
			Name: "phone", PublicKey: testDeviceKey(t, 2), Address: "10.44.0.3/32",
		},
		// nobody the server has ever seen sign in: nothing to fill in with
		{Owner: "bob", Name: "tablet", PublicKey: testDeviceKey(t, 3), Address: "10.44.0.4/32"},
	} {
		if err := s.Save(device); err != nil {
			t.Fatal(err)
		}
	}

	manager := New(wgembed.NewNoOpInterface(), s, "10.44.0.0/24", "")
	devices, err := manager.ListAllDevices()
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]*storage.Device{}
	for _, device := range devices {
		byName[device.Name] = device
	}
	if got := byName["laptop"]; got == nil || got.OwnerName != "Alice Example" || got.OwnerEmail != "alice@example.com" {
		t.Errorf("laptop owner = %+v, want the name and email the users table knows", got)
	}
	if got := byName["phone"]; got == nil || got.OwnerName != "Alice at the time" {
		t.Errorf("phone owner name = %+v, want the name the device was added with", got)
	}
	if got := byName["tablet"]; got == nil || got.OwnerName != "" {
		t.Errorf("tablet owner name = %+v, want it left alone", got)
	}

	// the stored device is not changed, only what the listing reports
	stored, err := s.List(subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range stored {
		if device.Name == "laptop" && device.OwnerName != "" {
			t.Errorf("stored laptop owner name = %q, want it untouched", device.OwnerName)
		}
	}
}
