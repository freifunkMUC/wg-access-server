package migrate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func openForTest(t *testing.T, uri string) storage.Storage {
	t.Helper()
	backend, err := storage.NewStorage(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// TestCopyAll migrates a filled backend into an empty one, the way an
// operator moves from SQLite to a database.
func TestCopyAll(t *testing.T) {
	src := openForTest(t, "memory://")
	dest := openForTest(t, "sqlite3://"+filepath.Join(t.TempDir(), "dest.db"))

	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	devices := []*storage.Device{
		{Owner: "alice", Name: "laptop", PublicKey: "alice-laptop", Address: "10.44.0.2/32"},
		{Owner: "bob", Name: "phone", PublicKey: "bob-phone", Address: "10.44.0.3/32", ReceiveBytes: 42},
	}
	for _, device := range devices {
		if err := src.Save(device); err != nil {
			t.Fatal(err)
		}
	}
	token := &storage.APIToken{
		ID:        "token-id",
		Owner:     "alice",
		Name:      "backup script",
		Hash:      "d0d0",
		Identity:  `{"provider":"simple","subject":"alice"}`,
		ExpiresAt: &expires,
	}
	if err := src.SaveToken(token); err != nil {
		t.Fatal(err)
	}

	if err := copyAll(src, dest); err != nil {
		t.Fatal(err)
	}

	copied, err := dest.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(copied) != len(devices) {
		t.Fatalf("copied %d devices, want %d", len(copied), len(devices))
	}
	phone, err := dest.Get("bob", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if phone.PublicKey != "bob-phone" || phone.Address != "10.44.0.3/32" || phone.ReceiveBytes != 42 {
		t.Errorf("the device arrived incomplete: %+v", phone)
	}

	// The tokens are what a migration used to leave behind, which only
	// showed once every script using one was refused.
	copiedToken, err := dest.GetToken("token-id")
	if err != nil {
		t.Fatalf("the api token did not arrive: %v", err)
	}
	if copiedToken.Owner != "alice" || copiedToken.Name != "backup script" || copiedToken.Hash != "d0d0" {
		t.Errorf("the api token arrived incomplete: %+v", copiedToken)
	}
	if copiedToken.Identity != token.Identity {
		t.Errorf("the identity of the api token changed: %q", copiedToken.Identity)
	}
	if copiedToken.ExpiresAt == nil || !copiedToken.ExpiresAt.Equal(expires) {
		t.Errorf("the expiry of the api token changed: %v", copiedToken.ExpiresAt)
	}
}

// TestCopyAllEmpty makes sure an empty source is not an error: an operator
// who migrates before anyone added a device gets an empty destination, not a
// failure.
func TestCopyAllEmpty(t *testing.T) {
	src := openForTest(t, "memory://")
	dest := openForTest(t, "memory://")

	if err := copyAll(src, dest); err != nil {
		t.Fatal(err)
	}
	devices, err := dest.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Errorf("the destination holds %d devices", len(devices))
	}
}
