package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryStorage_AddByteCounts(t *testing.T) {
	s := NewMemoryStorage()
	require.NoError(t, s.Open())
	defer s.Close()

	// Create a device
	device := &Device{
		Owner:         "user1",
		Name:          "device1",
		PublicKey:     "test-public-key",
		Address:       "10.0.0.1/32",
		CreatedAt:     time.Now(),
		ReceiveBytes:  1000,
		TransmitBytes: 2000,
	}
	require.NoError(t, s.Save(device))

	// Add byte counts
	err := s.AddByteCounts("test-public-key", 500, 750)
	require.NoError(t, err)

	// Verify the counts were added
	updated, err := s.GetByPublicKey("test-public-key")
	require.NoError(t, err)
	assert.Equal(t, int64(1500), updated.ReceiveBytes, "ReceiveBytes should be 1000 + 500")
	assert.Equal(t, int64(2750), updated.TransmitBytes, "TransmitBytes should be 2000 + 750")

	// Add more byte counts
	err = s.AddByteCounts("test-public-key", 250, 100)
	require.NoError(t, err)

	// Verify the counts were accumulated
	updated, err = s.GetByPublicKey("test-public-key")
	require.NoError(t, err)
	assert.Equal(t, int64(1750), updated.ReceiveBytes, "ReceiveBytes should be 1500 + 250")
	assert.Equal(t, int64(2850), updated.TransmitBytes, "TransmitBytes should be 2750 + 100")
}

func TestInMemoryStorage_AddByteCounts_NonExistentDevice(t *testing.T) {
	s := NewMemoryStorage()
	require.NoError(t, s.Open())
	defer s.Close()

	// Try to add byte counts for a non-existent device
	err := s.AddByteCounts("non-existent-key", 100, 200)
	require.Error(t, err, "Should return error for non-existent device")
}

func TestInMemoryStorage_AddByteCounts_ZeroDelta(t *testing.T) {
	s := NewMemoryStorage()
	require.NoError(t, s.Open())
	defer s.Close()

	// Create a device
	device := &Device{
		Owner:         "user1",
		Name:          "device1",
		PublicKey:     "test-public-key",
		Address:       "10.0.0.1/32",
		CreatedAt:     time.Now(),
		ReceiveBytes:  1000,
		TransmitBytes: 2000,
	}
	require.NoError(t, s.Save(device))

	// Add zero byte counts (should still work)
	err := s.AddByteCounts("test-public-key", 0, 0)
	require.NoError(t, err)

	// Verify the counts remain unchanged
	updated, err := s.GetByPublicKey("test-public-key")
	require.NoError(t, err)
	assert.Equal(t, int64(1000), updated.ReceiveBytes)
	assert.Equal(t, int64(2000), updated.TransmitBytes)
}

func TestInMemoryStorage_AddByteCounts_NegativeDelta(t *testing.T) {
	s := NewMemoryStorage()
	require.NoError(t, s.Open())
	defer s.Close()

	// Create a device
	device := &Device{
		Owner:         "user1",
		Name:          "device1",
		PublicKey:     "test-public-key",
		Address:       "10.0.0.1/32",
		CreatedAt:     time.Now(),
		ReceiveBytes:  1000,
		TransmitBytes: 2000,
	}
	require.NoError(t, s.Save(device))

	// Add negative byte counts (simulating a counter reset scenario)
	err := s.AddByteCounts("test-public-key", -100, -200)
	require.NoError(t, err)

	// Verify the counts were decreased (this is by design to handle counter resets)
	updated, err := s.GetByPublicKey("test-public-key")
	require.NoError(t, err)
	assert.Equal(t, int64(900), updated.ReceiveBytes)
	assert.Equal(t, int64(1800), updated.TransmitBytes)
}
