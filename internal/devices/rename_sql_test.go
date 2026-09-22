package devices

import (
	"path/filepath"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// The other rename tests run against the in-memory storage, which cannot show
// whether the UPDATE and the unique index behave. This one uses a real
// database file.
func TestRenameAgainstSQLite(t *testing.T) {
	uri := "sqlite3://" + filepath.Join(t.TempDir(), "db.sqlite3")
	s, err := storage.NewStorage(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "")
	created, err := manager.AddDevice(testIdentity("alice"), "laptop", testPublicKey(1), "", false, "", "")
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := manager.RenameDevice("alice", "laptop", "work laptop")
	if err != nil {
		t.Fatalf("rename failed: %v", err)
	}
	t.Logf("renamed: name=%q address=%q key=%q", renamed.Name, renamed.Address, renamed.PublicKey)

	if _, err := s.Get("alice", "laptop"); err == nil {
		t.Error("the row is still there under the old name")
	}
	stored, err := s.Get("alice", "work laptop")
	if err != nil {
		t.Fatalf("device not found under the new name: %v", err)
	}
	if stored.Address != created.Address || stored.PublicKey != created.PublicKey {
		t.Errorf("address or key changed: %+v", stored)
	}
	if stored.CreatedAt.IsZero() {
		t.Error("created_at was wiped by the rename")
	}

	all, _ := s.List("")
	if len(all) != 1 {
		t.Errorf("storage holds %d rows after the rename, want 1", len(all))
	}

	// renaming onto a name that is taken is refused, and leaves both rows as
	// they were
	if _, err := manager.AddDevice(testIdentity("alice"), "phone", testPublicKey(2), "", false, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RenameDevice("alice", "phone", "work laptop"); err == nil {
		t.Error("renaming onto an existing name succeeded")
	}
	if all, _ := s.List("alice"); len(all) != 2 {
		t.Errorf("storage holds %d rows after the refused rename, want 2", len(all))
	}
}
