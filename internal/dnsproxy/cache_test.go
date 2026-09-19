package dnsproxy

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func responseWithTTL(name string, ttl uint32) (string, *dns.Msg) {
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IPv4(192, 0, 2, 1),
	})
	return makekey(query), response
}

// The cache holds whatever the VPN clients ask for, so it must not grow
// without end: a client querying random names would otherwise be able to use
// up the server's memory.
func TestCacheDropsTheLeastRecentlyUsedEntry(t *testing.T) {
	small, err := newResponseCache(2)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &DNSProxy{cache: small}

	firstKey, first := responseWithTTL("first.example.com.", 300)
	secondKey, second := responseWithTTL("second.example.com.", 300)
	thirdKey, third := responseWithTTL("third.example.com.", 300)

	proxy.cacheResponse(firstKey, first)
	proxy.cacheResponse(secondKey, second)
	// touch the first entry so the second one is the least recently used
	proxy.cache.Get(firstKey)
	proxy.cacheResponse(thirdKey, third)

	if proxy.cache.Len() != 2 {
		t.Errorf("cache holds %d entries, want at most 2", proxy.cache.Len())
	}
	if _, found := proxy.cache.Get(secondKey); found {
		t.Error("the least recently used entry is still cached")
	}
	for _, key := range []string{firstKey, thirdKey} {
		if _, found := proxy.cache.Get(key); !found {
			t.Errorf("entry %q was dropped although it was used more recently", key)
		}
	}
}

// Nothing sweeps the cache in the background, so an entry that has expired
// must be recognised when it is looked up.
func TestLookupDoesNotServeAnExpiredEntry(t *testing.T) {
	proxy := newTestProxy(t) // no upstreams, so a cache miss cannot be answered
	key, response := responseWithTTL("expired.example.com.", 300)
	proxy.cache.Add(key, cachedResponse{response: response, expiresAt: time.Now().Add(-time.Second)})

	query := new(dns.Msg)
	query.SetQuestion("expired.example.com.", dns.TypeA)
	if _, err := proxy.Lookup(query); err == nil {
		t.Fatal("the expired entry was served from the cache")
	}

	if _, found := proxy.cache.Get(key); found {
		t.Error("the expired entry is still in the cache")
	}
}

func TestLookupServesAnEntryThatIsStillValid(t *testing.T) {
	proxy := newTestProxy(t)
	key, response := responseWithTTL("valid.example.com.", 300)
	proxy.cache.Add(key, cachedResponse{response: response, expiresAt: time.Now().Add(time.Minute)})

	query := new(dns.Msg)
	query.SetQuestion("valid.example.com.", dns.TypeA)
	got, err := proxy.Lookup(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answer))
	}
	if fmt.Sprint(got.Answer[0]) != fmt.Sprint(response.Answer[0]) {
		t.Errorf("got answer %v, want %v", got.Answer[0], response.Answer[0])
	}
	if _, found := proxy.cache.Get(key); !found {
		t.Error("a valid entry must stay in the cache")
	}
}

func TestNewHonoursTheConfiguredCacheSize(t *testing.T) {
	server, err := New(DNSServerOpts{Upstream: []string{"192.0.2.1"}, CacheSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	proxy := server.proxy

	if proxy.cache == nil {
		t.Fatal("caching is off although a cache size was configured")
	}
	for _, name := range []string{"a.example.com.", "b.example.com.", "c.example.com."} {
		key, response := responseWithTTL(name, 300)
		proxy.cacheResponse(key, response)
	}
	if proxy.cache.Len() != 2 {
		t.Errorf("cache holds %d entries, want the configured 2", proxy.cache.Len())
	}
}

// Size 0 turns caching off - every query then goes to the upstream, which is
// what an operator running their own resolver in front of us may want.
func TestNewWithoutCaching(t *testing.T) {
	server, err := New(DNSServerOpts{Upstream: []string{"192.0.2.1"}, CacheSize: 0})
	if err != nil {
		t.Fatal(err)
	}
	proxy := server.proxy

	if proxy.cache != nil {
		t.Fatal("expected no cache")
	}

	// neither storing nor looking up may touch the missing cache
	key, response := responseWithTTL("a.example.com.", 300)
	proxy.cacheResponse(key, response)

	query := new(dns.Msg)
	query.SetQuestion("a.example.com.", dns.TypeA)
	proxy.upstream = nil
	if _, err := proxy.Lookup(query); err == nil {
		t.Error("a lookup without upstreams and without a cache must fail")
	}
}
