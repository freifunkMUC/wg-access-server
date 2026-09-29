package dnsproxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/miekg/dns"
)

// testCache returns a response cache for tests.
func testCache(t *testing.T) *lru.Cache[string, cachedResponse] {
	t.Helper()
	c, err := newResponseCache(DefaultCacheSize)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// txtChunks is one TXT record of about size bytes, in the 255 byte pieces a
// TXT record is made of. A resolver joins them again.
func txtChunks(size int) []string {
	const piece = 255
	var chunks []string
	for written := 0; written < size; written += piece {
		chunks = append(chunks, strings.Repeat("x", piece))
	}
	return chunks
}

// newTXTUpstream is a resolver for the test: it answers the TXT queries it has
// a record for, over UDP and over TCP, and cuts a UDP answer down to what the
// client said it could take - which is what makes an answer arrive truncated,
// and the proxy ask again over TCP.
func newTXTUpstream(t *testing.T, records map[string][]string) string {
	t.Helper()

	// the same port on both transports, as a resolver has it
	var conn net.PacketConn
	var listener net.Listener
	for attempt := 0; attempt < 5; attempt++ {
		var err error
		conn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener, err = net.Listen("tcp", conn.LocalAddr().String())
		if err == nil {
			break
		}
		_ = conn.Close()
		conn, listener = nil, nil
	}
	if conn == nil || listener == nil {
		t.Fatal("could not listen on the same port over UDP and TCP")
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		response.Authoritative = true

		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeTXT {
			if chunks, ok := records[r.Question[0].Name]; ok {
				response.Answer = append(response.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: chunks,
				})
			}
		}

		// what a resolver does: fit the answer to the transport, and say so
		// when it does not fit
		size := dns.MaxMsgSize
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size = dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
		}
		response.Truncate(size)

		_ = w.WriteMsg(response)
	})

	for _, server := range []*dns.Server{
		{PacketConn: conn, Handler: handler},
		{Listener: listener, Handler: handler},
	} {
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go func() { _ = server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = server.Shutdown() })
	}

	return conn.LocalAddr().String()
}

// A query goes to the proxy, the proxy asks the resolver, and the answer finds
// its way back even when it does not fit into a UDP packet - over TCP, twice:
// between the proxy and the resolver, and between the client and the proxy.
func TestDNSProxy_ServeDNS(t *testing.T) {
	const listen = "[::1]:8053"

	upstream := newTXTUpstream(t, map[string][]string{
		"medium.example.": txtChunks(1300),
		"large.example.":  txtChunks(1800),
	})

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
		Upstream:   []string{upstream},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.ListenAndServe()
	defer func() { _ = server.Close() }()

	t.Run("Reply over 1300 bytes", func(t *testing.T) {
		records, err := resolver.LookupTXT(context.Background(), "medium.example.")
		if err != nil {
			t.Error(err)
			return
		}
		if len(records) != 1 || len(records[0]) < 1300 {
			t.Errorf("got %d records of %d bytes, want one of at least 1300", len(records), recordLength(records))
		}
	})

	t.Run("Reply over 1500 bytes", func(t *testing.T) {
		records, err := resolver.LookupTXT(context.Background(), "large.example.")
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
			t.Errorf("missing big TXT record (%d bytes), packet probably truncated", recordLength(records))
		}
	})
}

func recordLength(records []string) int {
	length := 0
	for _, record := range records {
		length += len(record)
	}
	return length
}

func TestDNSProxy_Lookup(t *testing.T) {
	proxy := &DNSProxy{
		udpClient: &dns.Client{Net: "udp"},
		tcpClient: &dns.Client{Net: "tcp"},
		cache:     testCache(t),
		// never reached: the answer this test asks for is in the cache
		upstream: []string{"127.0.0.1:1"},
	}

	t.Run("Cache hit", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		proxy.cache.Add(makekey(msg), cachedResponse{response: msg, expiresAt: time.Now().Add(time.Minute)})

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
		return &DNSProxy{cache: testCache(t)}
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

		entry, found := proxy.cache.Get(key)
		if !found {
			t.Fatal("expected response to be cached")
		}
		remaining := time.Until(entry.expiresAt)
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

func TestPurgeECS(t *testing.T) {
	newECS := func() *dns.EDNS0_SUBNET {
		return &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			Address:       net.IPv4(192, 0, 2, 0),
		}
	}
	newCookie := func() *dns.EDNS0_COOKIE {
		return &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "24a5ac1223344556"}
	}
	countECS := func(m *dns.Msg) int {
		opt := m.IsEdns0()
		if opt == nil {
			return 0
		}
		n := 0
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				n++
			}
		}
		return n
	}
	newMsg := func(options ...dns.EDNS0) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		m.SetEdns0(1232, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, options...)
		return m
	}

	t.Run("no EDNS0 at all", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		purgeECS(m) // must not panic
	})

	t.Run("no ECS option", func(t *testing.T) {
		m := newMsg(newCookie())
		purgeECS(m)
		if got := len(m.IsEdns0().Option); got != 1 {
			t.Fatalf("expected 1 remaining option, got %d", got)
		}
	})

	t.Run("single ECS option", func(t *testing.T) {
		m := newMsg(newECS())
		purgeECS(m)
		if got := countECS(m); got != 0 {
			t.Fatalf("expected 0 ECS options, got %d", got)
		}
	})

	t.Run("multiple ECS options are all removed", func(t *testing.T) {
		m := newMsg(newECS(), newECS(), newCookie(), newECS())
		purgeECS(m)
		if got := countECS(m); got != 0 {
			t.Fatalf("expected 0 ECS options, got %d", got)
		}
		if got := len(m.IsEdns0().Option); got != 1 {
			t.Fatalf("expected 1 remaining non-ECS option, got %d", got)
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

// responseRecorder captures the message a handler writes back to the client.
type responseRecorder struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (r *responseRecorder) WriteMsg(m *dns.Msg) error { r.msg = m; return nil }

func (r *responseRecorder) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv6loopback, Port: 40000}
}

// The client must see the response code the upstream sent. Answering an
// upstream NXDOMAIN with NOERROR makes a name that does not exist look like a
// name without records, which breaks search domain resolution on the clients.
func TestDNSProxy_ServeDNSKeepsUpstreamRcode(t *testing.T) {
	tests := []struct {
		name  string
		rcode int
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError},
		{name: "REFUSED", rcode: dns.RcodeRefused},
		{name: "NOERROR", rcode: dns.RcodeSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &DNSProxy{cache: testCache(t)}

			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			// Serve the answer from the cache so the test needs no upstream.
			upstream := new(dns.Msg)
			upstream.SetRcode(query, tt.rcode)
			proxy.cache.Add(makekey(query), cachedResponse{response: upstream, expiresAt: time.Now().Add(time.Minute)})

			recorder := &responseRecorder{}
			proxy.ServeDNS(recorder, query)

			if recorder.msg == nil {
				t.Fatal("no response written")
			}
			if recorder.msg.Rcode != tt.rcode {
				t.Errorf("client got %s, upstream sent %s",
					dns.RcodeToString[recorder.msg.Rcode], dns.RcodeToString[tt.rcode])
			}
			if recorder.msg.Id != query.Id || !recorder.msg.Response {
				t.Error("response header does not match the query")
			}
		})
	}
}
