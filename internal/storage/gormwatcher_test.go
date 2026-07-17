package storage

import (
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// newGormWatcherTestDB opens an in-memory sqlite database and wires a
// GormWatcher to it the same way SQLStorage.Open does.
func newGormWatcherTestDB(t *testing.T) (*gorm.DB, *GormWatcher) {
	t.Helper()

	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// every pooled connection would get its own private :memory: database,
	// so restrict the pool to a single connection
	db.DB().SetMaxOpenConns(1)

	if err := db.AutoMigrate(&Device{}).Error; err != nil {
		t.Fatalf("failed to migrate schema: %v", err)
	}

	return db, NewGormWatcher(db, db.NewScope(&Device{}).TableName())
}

func deviceCount(t *testing.T, db *gorm.DB) int {
	t.Helper()
	count := 0
	if err := db.Model(&Device{}).Count(&count).Error; err != nil {
		t.Fatalf("failed to count devices: %v", err)
	}
	return count
}

func TestGormWatcherEmitsAddOnSuccessfulCreate(t *testing.T) {
	db, watcher := newGormWatcherTestDB(t)

	var added []*Device
	watcher.OnAdd(func(d *Device) {
		added = append(added, d)
	})

	device := &Device{Owner: "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}
	if err := db.Create(&device).Error; err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if len(added) != 1 {
		t.Fatalf("expected OnAdd to fire exactly once, got %d", len(added))
	}
	if added[0].Owner != "alice" || added[0].Name != "phone" {
		t.Fatalf("OnAdd fired for wrong device: %s/%s", added[0].Owner, added[0].Name)
	}
}

func TestGormWatcherDoesNotEmitAddOnFailedCreate(t *testing.T) {
	db, watcher := newGormWatcherTestDB(t)

	// seed a device before registering the callback so only the failing
	// insert below could possibly fire it
	existing := &Device{Owner: "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seeding device failed: %v", err)
	}

	addCalls := 0
	watcher.OnAdd(func(d *Device) {
		addCalls++
	})

	// same (owner, name) primary key -> unique constraint violation,
	// the insert fails and the transaction is rolled back
	duplicate := &Device{Owner: "alice", Name: "phone", PublicKey: "pub2", Address: "10.44.0.3/32"}
	if err := db.Create(&duplicate).Error; err == nil {
		t.Fatal("expected duplicate Create to fail, but it succeeded")
	}

	if addCalls != 0 {
		t.Fatalf("OnAdd fired %d time(s) for a failed create, want 0", addCalls)
	}
	if got := deviceCount(t, db); got != 1 {
		t.Fatalf("expected 1 device in the database, got %d", got)
	}
}

func TestGormWatcherDeleteEvents(t *testing.T) {
	db, watcher := newGormWatcherTestDB(t)

	device := &Device{Owner: "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}
	if err := db.Create(&device).Error; err != nil {
		t.Fatalf("seeding device failed: %v", err)
	}

	var deleted []*Device
	watcher.OnDelete(func(d *Device) {
		deleted = append(deleted, d)
	})

	// a failing delete (SQL error on a non-existent column, statement is
	// rolled back) must not emit OnDelete
	if err := db.Where("no_such_column = ?", 1).Delete(&device).Error; err == nil {
		t.Fatal("expected Delete with invalid condition to fail, but it succeeded")
	}
	if len(deleted) != 0 {
		t.Fatalf("OnDelete fired %d time(s) for a failed delete, want 0", len(deleted))
	}
	if got := deviceCount(t, db); got != 1 {
		t.Fatalf("expected device to survive the failed delete, got %d devices", got)
	}

	// a successful delete fires OnDelete exactly once
	if err := db.Delete(&device).Error; err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected OnDelete to fire exactly once, got %d", len(deleted))
	}
	if deleted[0].Owner != "alice" || deleted[0].Name != "phone" {
		t.Fatalf("OnDelete fired for wrong device: %s/%s", deleted[0].Owner, deleted[0].Name)
	}
	if got := deviceCount(t, db); got != 0 {
		t.Fatalf("expected 0 devices after delete, got %d", got)
	}
}
