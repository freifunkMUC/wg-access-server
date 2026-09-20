package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The WireGuard peer is identified by the public key, so two devices must
// never share one: the second would take over the first one's tunnel. Every
// backend has to enforce that - MySQL did not, because the schema migration
// failed silently.
func TestPublicKeyIsUniquePerBackend(t *testing.T) {
	backends := map[string]string{
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "unique.db"),
		"postgres": os.Getenv("WG_TEST_POSTGRES_URI"),
		"mysql":    os.Getenv("WG_TEST_MYSQL_URI"),
	}
	for name, uri := range backends {
		if uri == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			key := "dupkey-test-" + name
			first := &Device{Owner: "dupkey-alice", Name: "laptop", PublicKey: key, Address: "10.44.0.2/32", CreatedAt: time.Now()}
			second := &Device{Owner: "dupkey-mallory", Name: "stolen", PublicKey: key, Address: "10.44.0.3/32", CreatedAt: time.Now()}
			t.Cleanup(func() {
				_ = s.Delete(first)
				_ = s.Delete(second)
			})

			if err := s.Save(first); err != nil {
				t.Fatal(err)
			}
			if err := s.Save(second); err == nil {
				t.Errorf("%s stored a second device with the same public key", name)
			}

			stored, err := s.GetByPublicKey(key)
			if err != nil {
				t.Fatalf("the first device is gone: %v", err)
			}
			if stored.Owner != first.Owner {
				t.Errorf("the public key now belongs to %q, want %q", stored.Owner, first.Owner)
			}
		})
	}
}
