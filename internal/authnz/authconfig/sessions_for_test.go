package authconfig

import (
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

// testSessions is where the identities of the tests' sessions live. The cookie
// carries an id, as it does in the server.
func testSessions() *websessions.Manager {
	return websessions.New(storage.NewMemoryStorage(), time.Hour)
}
