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
	if err := s.SaveUser(&storage.User{Subject: "alice", Name: "Alice Example", LastLogin: login}); err != nil {
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
