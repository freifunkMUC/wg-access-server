package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAddresses covers what device creation relies on: every stored address,
// from every backend, in the form it was written.
func TestAddresses(t *testing.T) {
	for name, uri := range metadataBackends(t) {
		t.Run(name, func(t *testing.T) {
			s := openMetadataBackend(t, uri)

			empty, err := s.Addresses()
			require.NoError(t, err)
			before := len(empty)

			devices := []*Device{
				{Owner: metadataTestOwner + "alice", Name: "laptop", PublicKey: "addresses-alice", Address: "10.44.0.2/32, fd48:4c4:7aa9::2/128"},
				{Owner: metadataTestOwner + "bob", Name: "phone", PublicKey: "addresses-bob", Address: "10.44.0.3/32"},
				// a device whose address never got written, which the
				// allocation has to survive
				{Owner: metadataTestOwner + "carol", Name: "ghost", PublicKey: "addresses-carol", Address: ""},
			}
			for _, device := range devices {
				require.NoError(t, s.Save(device))
			}

			addresses, err := s.Addresses()
			require.NoError(t, err)
			require.Len(t, addresses, before+len(devices))
			require.Contains(t, addresses, "10.44.0.2/32, fd48:4c4:7aa9::2/128")
			require.Contains(t, addresses, "10.44.0.3/32")
			require.Contains(t, addresses, "")

			require.NoError(t, s.Delete(devices[1]))
			addresses, err = s.Addresses()
			require.NoError(t, err)
			require.NotContains(t, addresses, "10.44.0.3/32")
		})
	}
}
