package storage

import (
	"path/filepath"
	"testing"

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

func TestUpdateMetadataDoesNotResurrectDeletedDevice(t *testing.T) {
	uris := map[string]string{
		"memory":  "memory://",
		"sqlite3": "sqlite3://" + filepath.Join(t.TempDir(), "test.db"),
	}

	for name, uri := range uris {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			s, err := NewStorage(uri)
			require.NoError(err)
			require.NoError(s.Open())
			defer s.Close()

			device := &Device{Owner: "alice", Name: "phone", PublicKey: "pub1", Address: "10.44.0.2/32"}
			require.NoError(s.Save(device))

			// metadata updates on an existing device are persisted
			device.ReceiveBytes = 42
			device.Endpoint = "192.0.2.1"
			require.NoError(s.UpdateMetadata(device))

			got, err := s.Get("alice", "phone")
			require.NoError(err)
			require.Equal(int64(42), got.ReceiveBytes)
			require.Equal("192.0.2.1", got.Endpoint)

			// a device deleted while a metadata sync is in flight
			// must not be re-created by the metadata update
			require.NoError(s.Delete(device))
			require.NoError(s.UpdateMetadata(device))

			_, err = s.Get("alice", "phone")
			require.Error(err)

			devices, err := s.List("")
			require.NoError(err)
			require.Empty(devices)
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
