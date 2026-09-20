package devices

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// The automatic deletion is a change nobody asked for, so it must still leave
// a record - attributed to the server itself.
func TestInactiveDeletionIsAudited(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	s := storage.NewMemoryStorage()
	longAgo := time.Now().Add(-48 * time.Hour)
	if err := s.Save(&storage.Device{
		Owner: "alice", Name: "forgotten", PublicKey: "key", Address: "10.44.0.2/32",
		CreatedAt: longAgo, LastHandshakeTime: &longAgo,
	}); err != nil {
		t.Fatal(err)
	}
	manager := New(&fakeWgInterface{}, s, "10.44.0.0/24", "")

	checkAndRemove(context.Background(), manager, time.Hour)

	if left, _ := s.List("alice"); len(left) != 0 {
		t.Fatal("the inactive device was not deleted")
	}

	var record *logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Data["audit"] == audit.DeviceDelete {
			record = entry
		}
	}
	if record == nil {
		t.Fatal("no audit record for the automatic deletion")
	}
	for field, want := range map[string]interface{}{
		"actor":  audit.SystemActor,
		"owner":  "alice",
		"device": "forgotten",
		"reason": "inactive",
	} {
		if record.Data[field] != want {
			t.Errorf("audit field %q = %v, want %v", field, record.Data[field], want)
		}
	}
}
