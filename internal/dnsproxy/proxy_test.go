package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

var ffmucUpstreams, _ = net.LookupHost("dns.ffmuc.net")

func TestDNSProxy_ServeDNS(t *testing.T) {
	const listen = "[::1]:8053"

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second}
			return d.DialContext(ctx, network, listen)
		},
	}

	server, err := New(DNSServerOpts{
		Domain:     "",
		ListenAddr: []string{listen},
		Upstream:   ffmucUpstreams,
	})
	server.ListenAndServe()
	defer func() { _ = server.Close() }()

	if err != nil {
		t.Fatal(err)
	}

	t.Run("Reply over 1300 bytes", func(t *testing.T) {
		_, err := resolver.LookupTXT(context.Background(), "cloudflare.com.")
		if err != nil {
			t.Error(err)
			return
		}
	})
	t.Run("Reply over 1500 bytes", func(t *testing.T) {
		records, err := resolver.LookupTXT(context.Background(), "txtfill1500.test.dnscheck.tools.")
		if err != nil {
			t.Error(err)
			return
		}
		var containsBigRecord bool
		for _, r := range records {
			if len(r) >= 1500 {
				containsBigRecord = true
			}
		}
		if !containsBigRecord {
			t.Error("missing big TXT record, packet probably truncated")
		}
	})
}

func TestDNSProxy_Lookup(t *testing.T) {
	proxy := &DNSProxy{
		udpClient: &dns.Client{Net: "udp"},
		tcpClient: &dns.Client{Net: "tcp"},
		cache:     cache.New(5*time.Minute, 10*time.Minute),
		upstream:  ffmucUpstreams,
	}

	t.Run("Cache hit", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		proxy.cache.Set(makekey(msg), msg, cache.DefaultExpiration)

		resp, err := proxy.Lookup(msg)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}
	})
}

func TestDNSProxy_CacheResponse(t *testing.T) {
	newA := func(ttl uint32) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IPv4(127, 0, 0, 1),
		}
	}
	newProxy := func() *DNSProxy {
		return &DNSProxy{cache: cache.New(10*time.Minute, 10*time.Minute)}
	}
	newResponse := func(name string, ttls ...uint32) (string, *dns.Msg) {
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		response := new(dns.Msg)
		response.SetReply(query)
		for _, ttl := range ttls {
			response.Answer = append(response.Answer, newA(ttl))
		}
		return makekey(query), response
	}

	t.Run("TTL 0 responses are not cached", func(t *testing.T) {
		proxy := newProxy()
		key, response := newResponse("ttl-zero.example.com.", 0)

		proxy.cacheResponse(key, response)

		if _, found := proxy.cache.Get(key); found {
			t.Fatal("response with TTL 0 must not be cached")
		}
	})

	t.Run("mixed TTLs with a 0 are not cached", func(t *testing.T) {
		proxy := newProxy()
		key, response := newResponse("mixed-zero.example.com.", 300, 0)

		proxy.cacheResponse(key, response)

		if _, found := proxy.cache.Get(key); found {
			t.Fatal("response containing a TTL 0 record must not be cached")
		}
	})

	t.Run("minimum TTL across answers is used", func(t *testing.T) {
		proxy := newProxy()
		key, response := newResponse("mixed-ttl.example.com.", 300, 30)

		proxy.cacheResponse(key, response)

		_, expiration, found := proxy.cache.GetWithExpiration(key)
		if !found {
			t.Fatal("expected response to be cached")
		}
		remaining := time.Until(expiration)
		if remaining > 30*time.Second {
			t.Fatalf("cache TTL %v exceeds minimum record TTL of 30s", remaining)
		}
		if remaining <= 0 {
			t.Fatalf("cache TTL %v should be positive", remaining)
		}
	})

	t.Run("responses without answers are not cached", func(t *testing.T) {
		proxy := newProxy()
		key, response := newResponse("no-answer.example.com.")

		proxy.cacheResponse(key, response)

		if _, found := proxy.cache.Get(key); found {
			t.Fatal("response without answers must not be cached")
		}
	})
}

func TestMinTTL(t *testing.T) {
	newA := func(ttl uint32) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IPv4(127, 0, 0, 1),
		}
	}

	t.Run("empty message", func(t *testing.T) {
		if got := minTTL(new(dns.Msg)); got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
	})

	t.Run("minimum across sections", func(t *testing.T) {
		m := new(dns.Msg)
		m.Answer = []dns.RR{newA(300), newA(60)}
		m.Extra = []dns.RR{newA(10)}
		if got := minTTL(m); got != 10*time.Second {
			t.Fatalf("expected 10s, got %v", got)
		}
	})

	t.Run("OPT records are ignored", func(t *testing.T) {
		m := new(dns.Msg)
		m.Answer = []dns.RR{newA(60)}
		m.SetEdns0(1232, false) // OPT header TTL is 0 but must not count
		if got := minTTL(m); got != 60*time.Second {
			t.Fatalf("expected 60s, got %v", got)
		}
	})

	t.Run("zero TTL answer", func(t *testing.T) {
		m := new(dns.Msg)
		m.Answer = []dns.RR{newA(0), newA(300)}
		if got := minTTL(m); got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
	})
}
