package dnsproxy

import (
	"testing"
)

func TestUpstreamAddr(t *testing.T) {
	tests := []struct {
		upstream string
		want     string
	}{
		{upstream: "192.0.2.1", want: "192.0.2.1:53"},
		{upstream: "192.0.2.1:5353", want: "192.0.2.1:5353"},
		{upstream: "2001:db8::1", want: "[2001:db8::1]:53"},
		{upstream: "[2001:db8::1]:5353", want: "[2001:db8::1]:5353"},
		{upstream: "dns.example.com", want: "dns.example.com:53"},
	}

	for _, tt := range tests {
		t.Run(tt.upstream, func(t *testing.T) {
			if got := upstreamAddr(tt.upstream); got != tt.want {
				t.Errorf("upstreamAddr(%q) = %q, want %q", tt.upstream, got, tt.want)
			}
		})
	}
}
