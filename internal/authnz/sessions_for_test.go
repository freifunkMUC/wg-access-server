package authnz

import (
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

// testSessions is where the identities of the tests' sessions live, as they
// live in the storage in the server.
func testSessions() *websessions.Manager {
	return websessions.New(storage.NewMemoryStorage(), time.Hour)
}
