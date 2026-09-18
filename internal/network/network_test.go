package network

import (
	"net/netip"
	"testing"
)

func TestParseAddresses(t *testing.T) {
	tests := []struct {
		name         string
		addresses    string
		want         []netip.Addr
		wantUnusable []string
	}{
		{
			name:      "dual stack prefixes",
			addresses: "10.44.0.2/32, fd48:4c4:7aa9::2/128",
			want:      []netip.Addr{netip.MustParseAddr("10.44.0.2"), netip.MustParseAddr("fd48:4c4:7aa9::2")},
		},
		{
			name:      "IPv4 only",
			addresses: "10.44.0.2/32",
			want:      []netip.Addr{netip.MustParseAddr("10.44.0.2")},
		},
		{
			// A row written by hand or by an older version can hold a bare
			// address. It must still count as taken, otherwise the address
			// gets handed out to a second device.
			name:      "bare address without a prefix",
			addresses: "10.44.0.2",
			want:      []netip.Addr{netip.MustParseAddr("10.44.0.2")},
		},
		{
			name:         "unusable entry next to a good one",
			addresses:    "not-an-address, 10.44.0.2/32",
			want:         []netip.Addr{netip.MustParseAddr("10.44.0.2")},
			wantUnusable: []string{"not-an-address"},
		},
		{
			name:         "empty address",
			addresses:    "",
			wantUnusable: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unusable := ParseAddresses(tt.addresses)

			if len(got) != len(tt.want) {
				t.Fatalf("ParseAddresses(%q) = %v, want %v", tt.addresses, got, tt.want)
			}
			for i, addr := range got {
				if addr != tt.want[i] {
					t.Errorf("address %d = %v, want %v", i, addr, tt.want[i])
				}
			}

			if len(unusable) != len(tt.wantUnusable) {
				t.Fatalf("unusable entries = %q, want %q", unusable, tt.wantUnusable)
			}
			for i, entry := range unusable {
				if entry != tt.wantUnusable[i] {
					t.Errorf("unusable entry %d = %q, want %q", i, entry, tt.wantUnusable[i])
				}
			}
		})
	}
}
