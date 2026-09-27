package dnsproxy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// BenchmarkCachedLookup is the common case for the clients of a VPN: a name
// somebody asked for recently, answered without leaving the server.
func BenchmarkCachedLookup(b *testing.B) {
	cache, err := newResponseCache(DefaultCacheSize)
	if err != nil {
		b.Fatal(err)
	}
	proxy := &DNSProxy{cache: cache}

	// a cache filled the way the clients of a busy server would fill it
	queries := make([]*dns.Msg, 100)
	for i := range queries {
		name := fmt.Sprintf("host-%d.example.com.", i)
		key, response := responseWithTTL(name, 300)
		proxy.cacheResponse(key, response)
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		queries[i] = query
	}

	b.ResetTimer()
	for i := range b.N {
		response, err := proxy.Lookup(queries[i%len(queries)])
		if err != nil || len(response.Answer) != 1 {
			b.Fatalf("no answer from the cache: %v", err)
		}
	}
}

// BenchmarkAuthLookup answers for a device name, out of a zone holding as
// many devices as the server has.
func BenchmarkAuthLookup(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			auth := &DNSAuth{Domain: dns.Fqdn("vpn.example.com"), zoneLock: new(sync.RWMutex)}
			zone := make(Zone, count)
			zone[ZoneKey{}] = []netip.Addr{netip.MustParseAddr("10.44.0.1")}
			for i := range count {
				zone[ZoneKey{Owner: fmt.Sprintf("user-%d", i%50), Name: fmt.Sprintf("device-%d", i)}] = []netip.Addr{
					netip.AddrFrom4([4]byte{10, 44, byte(i / 256), byte(i % 256)}),
				}
			}
			auth.PushZone(zone)

			query := new(dns.Msg)
			query.SetQuestion(dns.Fqdn(fmt.Sprintf("device-%d.user-%d.vpn.example.com", count/2, (count/2)%50)), dns.TypeA)

			b.ResetTimer()
			for range b.N {
				response, err := auth.Lookup(query)
				if err != nil || len(response.Answer) != 1 {
					b.Fatalf("the device was not found: %v", err)
				}
			}
		})
	}
}

// BenchmarkPushZone is the work behind every device change: the whole zone is
// rebuilt and replaced.
func BenchmarkPushZone(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d-devices", count), func(b *testing.B) {
			auth := &DNSAuth{Domain: dns.Fqdn("vpn.example.com"), zoneLock: new(sync.RWMutex)}
			zone := make(Zone, count)
			for i := range count {
				zone[ZoneKey{Owner: fmt.Sprintf("User-%d", i%50), Name: fmt.Sprintf("Device-%d", i)}] = []netip.Addr{
					netip.AddrFrom4([4]byte{10, 44, byte(i / 256), byte(i % 256)}),
				}
			}
			b.ResetTimer()
			for range b.N {
				auth.PushZone(zone)
			}
		})
	}
}
