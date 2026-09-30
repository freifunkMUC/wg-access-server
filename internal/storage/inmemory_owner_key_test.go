package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A device name must not be able to address a device of another owner.
func TestInMemoryStorageDeviceNameCannotEscapeOwner(t *testing.T) {
	require := require.New(t)

	s := NewMemoryStorage()
	require.NoError(s.Save(&Device{Owner: "bob", Name: "laptop", PublicKey: "bob-key"}))

	for _, name := range []string{"../bob/laptop", "../bob/./laptop", "x/../../bob/laptop"} {
		_, err := s.Get("mallory", name)
		require.Error(err, name)
	}

	require.NoError(s.Save(&Device{Owner: "mallory", Name: "../bob/laptop", PublicKey: "mallory-key"}))
	device, err := s.Get("bob", "laptop")
	require.NoError(err)
	require.Equal("bob-key", device.PublicKey)

	require.NoError(s.Delete(&Device{Owner: "mallory", Name: "../bob/laptop"}))
	_, err = s.Get("bob", "laptop")
	require.NoError(err)

	bobDevices, err := s.List("bob")
	require.NoError(err)
	require.Len(bobDevices, 1)
}

// Owners and names containing the separator must not collide either.
func TestInMemoryStorageKeysDoNotCollide(t *testing.T) {
	require := require.New(t)

	s := NewMemoryStorage()
	require.NoError(s.Save(&Device{Owner: "a/b", Name: "c", PublicKey: "first"}))
	require.NoError(s.Save(&Device{Owner: "a", Name: "b/c", PublicKey: "second"}))

	first, err := s.Get("a/b", "c")
	require.NoError(err)
	require.Equal("first", first.PublicKey)
	second, err := s.Get("a", "b/c")
	require.NoError(err)
	require.Equal("second", second.PublicKey)
}
