package storage

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("memory://")
	require.NoError(err)

	require.IsType(&InMemoryStorage{}, s)
}

func TestMemoryStorageListMatchesOwnerExactly(t *testing.T) {
	require := require.New(t)

	s := NewMemoryStorage()
	require.NoError(s.Save(&Device{Owner: "alice", Name: "phone"}))
	require.NoError(s.Save(&Device{Owner: "alicebob", Name: "laptop"}))

	devices, err := s.List("alice")
	require.NoError(err)
	require.Len(devices, 1)
	require.Equal("alice", devices[0].Owner)

	all, err := s.List("")
	require.NoError(err)
	require.Len(all, 2)
}

// metadataBackends returns every storage backend the metadata contract is
// checked against. Postgres and MySQL need a real server, so they only run when
// WG_TEST_POSTGRES_URI / WG_TEST_MYSQL_URI point at one, e.g.
// postgresql://user:pass@localhost:5432/db?sslmode=disable.
func metadataBackends(t *testing.T) map[string]string {
	backends := map[string]string{
		"memory":  "memory://",
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "test.db"),
	}
	if uri := os.Getenv("WG_TEST_POSTGRES_URI"); uri != "" {
		backends["postgres"] = uri
	}
	if uri := os.Getenv("WG_TEST_MYSQL_URI"); uri != "" {
		backends["mysql"] = uri
	}
	return backends
}

// metadataTestOwner prefixes every owner these tests create. The shared test
// databases also hold devices of other packages' tests running at the same time.
const metadataTestOwner = "metadata-test-"

func openMetadataBackend(t *testing.T, uri string) Storage {
	t.Helper()
	s, err := NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	t.Cleanup(func() {
		// Postgres and MySQL are shared with other test packages, which
		// `go test ./...` runs in parallel, so only remove this file's devices.
		if devices, err := s.List(""); err == nil {
			for _, device := range devices {
				if strings.HasPrefix(device.Owner, metadataTestOwner) {
					_ = s.Delete(device)
				}
			}
		}
		_ = s.Close()
	})
	return s
}

func TestRecordMetadataDoesNotResurrectDeletedDevice(t *testing.T) {
	for name, uri := range metadataBackends(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			s := openMetadataBackend(t, uri)

			device := &Device{Owner: metadataTestOwner + "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}
			require.NoError(s.Save(device))

			// metadata updates on an existing device are persisted
			require.NoError(s.RecordMetadata([]MetadataUpdate{{
				PublicKey:    "pub1",
				ReceiveBytes: 42,
				Connection:   &PeerConnection{Endpoint: "192.0.2.1", LastHandshakeTime: time.Now()},
			}}))

			got, err := s.Get(metadataTestOwner+"alice", "phone")
			require.NoError(err)
			require.Equal(int64(42), got.ReceiveBytes)
			require.Equal("192.0.2.1", got.Endpoint)

			// a device deleted while a metadata sync is in flight
			// must not be re-created by the metadata update
			require.NoError(s.Delete(device))
			require.NoError(s.RecordMetadata([]MetadataUpdate{{PublicKey: "pub1", ReceiveBytes: 1}}))

			_, err = s.Get(metadataTestOwner+"alice", "phone")
			require.Error(err)

			devices, err := s.List(metadataTestOwner + "alice")
			require.NoError(err)
			require.Empty(devices)
		})
	}
}

// Issue #208: several replicas each report the traffic of their own
// WireGuard interface. Those reports have to add up, not replace each other.
func TestRecordMetadataAccumulatesAcrossReplicas(t *testing.T) {
	for name, uri := range metadataBackends(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			s := openMetadataBackend(t, uri)

			require.NoError(s.Save(&Device{Owner: metadataTestOwner + "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}))

			handshake := time.Now().Truncate(time.Second)
			// replica A served the client for a while
			require.NoError(s.RecordMetadata([]MetadataUpdate{{
				PublicKey: "pub1", ReceiveBytes: 1000, TransmitBytes: 100,
				Connection: &PeerConnection{Endpoint: "192.0.2.1", LastHandshakeTime: handshake},
			}}))
			// replica B took over and reports its own traffic and connection
			require.NoError(s.RecordMetadata([]MetadataUpdate{{
				PublicKey: "pub1", ReceiveBytes: 500, TransmitBytes: 50,
				Connection: &PeerConnection{Endpoint: "198.51.100.7", LastHandshakeTime: handshake.Add(time.Minute)},
			}}))
			// replica A still flushes traffic it saw before the client left,
			// but no longer reports a connection
			require.NoError(s.RecordMetadata([]MetadataUpdate{{
				PublicKey: "pub1", ReceiveBytes: 25, TransmitBytes: 5,
			}}))

			got, err := s.Get(metadataTestOwner+"alice", "phone")
			require.NoError(err)
			require.Equal(int64(1525), got.ReceiveBytes, "receive totals must add up")
			require.Equal(int64(155), got.TransmitBytes, "transmit totals must add up")
			require.Equal("198.51.100.7", got.Endpoint, "a traffic-only update must not touch the endpoint")
			require.NotNil(got.LastHandshakeTime)
			require.True(got.LastHandshakeTime.Equal(handshake.Add(time.Minute)),
				"last handshake = %v, want %v", got.LastHandshakeTime, handshake.Add(time.Minute))
		})
	}
}

func TestRecordMetadataAppliesABatch(t *testing.T) {
	for name, uri := range metadataBackends(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			s := openMetadataBackend(t, uri)

			const count = 50
			var updates []MetadataUpdate
			for i := 0; i < count; i++ {
				key := fmt.Sprintf("pub%d", i)
				require.NoError(s.Save(&Device{Owner: metadataTestOwner + "bob", Name: fmt.Sprintf("dev%d", i), PublicKey: key, Address: fmt.Sprintf("10.44.1.%d/32", i+1)}))
				updates = append(updates, MetadataUpdate{PublicKey: key, ReceiveBytes: int64(i + 1)})
			}
			// an update for an unknown key must not abort the rest of the batch
			updates = append(updates, MetadataUpdate{PublicKey: "unknown", ReceiveBytes: 7})

			require.NoError(s.RecordMetadata(updates))

			devices, err := s.List(metadataTestOwner + "bob")
			require.NoError(err)
			require.Len(devices, count)
			var sum int64
			for _, device := range devices {
				sum += device.ReceiveBytes
			}
			require.Equal(int64(count*(count+1)/2), sum)
		})
	}
}

func TestPostgresqlStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("postgresql://localhost:5432/dbname?sslmode=disable")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestMysqlStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("mysql://localhost:1234/dbname?sslmode=disable")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestSqliteStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("sqlite3:///some/path/sqlite.db")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestSqliteStorageRelativePath(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("sqlite3://sqlite.db")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestUnknownStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("foo://")
	require.Nil(s)
	require.Error(err)
	require.Equal(err.Error(), "unknown storage backend foo:")
}

// Columns added to an existing table by AutoMigrate hold NULL for old rows,
// and NULL + n stays NULL in SQL. Traffic must still start counting there.
func TestRecordMetadataCountsFromNull(t *testing.T) {
	for name, uri := range metadataBackends(t) {
		if name == "memory" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			s := openMetadataBackend(t, uri)

			require.NoError(s.Save(&Device{Owner: metadataTestOwner + "carol", Name: "old", PublicKey: "pub-null", Address: "10.44.2.2/32"}))
			db := s.(*SQLStorage).db
			require.NoError(db.Exec("UPDATE devices SET receive_bytes = NULL, transmit_bytes = NULL WHERE public_key = ?", "pub-null").Error)

			require.NoError(s.RecordMetadata([]MetadataUpdate{{PublicKey: "pub-null", ReceiveBytes: 9, TransmitBytes: 3}}))

			got, err := s.Get(metadataTestOwner+"carol", "old")
			require.NoError(err)
			require.Equal(int64(9), got.ReceiveBytes)
			require.Equal(int64(3), got.TransmitBytes)
		})
	}
}

func TestMysqlConnectionStringRequiresParseTime(t *testing.T) {
	tests := map[string]string{
		"mysql://user:pass@db:3306/wg":                          "user:pass@tcp(db:3306)/wg?parseTime=true",
		"mysql://user:pass@db:3306/wg?tls=false":                "user:pass@tcp(db:3306)/wg?parseTime=true&tls=false",
		"mysql://user:pass@db:3306/wg?parseTime=true":           "user:pass@tcp(db:3306)/wg?parseTime=true",
		"mysql://user:pass@db:3306/wg?parseTime=false&tls=true": "user:pass@tcp(db:3306)/wg?parseTime=true&tls=true",
	}
	for uri, want := range tests {
		u, err := url.Parse(uri)
		require.NoError(t, err)
		require.Equal(t, want, mysqlconn(u), uri)
	}
}
