package dnsproxy

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// fakeUpstream is a DNS server on a random port that counts the queries it
// receives. A silent one never answers, which is what a dead resolver looks
// like to the proxy: every query runs into the client timeout.
type fakeUpstream struct {
	addr   string
	server *dns.Server

	mu      sync.Mutex
	queries int
}

func newFakeUpstream(t *testing.T, answer bool) *fakeUpstream {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	upstream := &fakeUpstream{addr: conn.LocalAddr().String()}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstream.mu.Lock()
		upstream.queries++
		upstream.mu.Unlock()

		if !answer {
			return
		}
		response := new(dns.Msg)
		response.SetReply(r)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		})
		_ = w.WriteMsg(response)
	})

	upstream.server = &dns.Server{PacketConn: conn, Handler: handler}
	started := make(chan struct{})
	upstream.server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = upstream.server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = upstream.server.Shutdown() })

	return upstream
}

func (f *fakeUpstream) queryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries
}

func newTestProxy(upstreams ...string) *DNSProxy {
	return &DNSProxy{
		udpClient: &dns.Client{Timeout: 100 * time.Millisecond},
		tcpClient: &dns.Client{Net: "tcp", Timeout: 100 * time.Millisecond},
		cache:     cache.New(time.Minute, time.Minute),
		upstream:  upstreams,
	}
}

func lookup(t *testing.T, proxy *DNSProxy, name string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	response, err := proxy.Lookup(query)
	if err != nil {
		t.Fatalf("lookup of %s failed: %v", name, err)
	}
	return response
}

// A dead first upstream must not cost every single query its timeout: after
// the first failure it is skipped until its cooldown has passed.
func TestLookupSkipsAFailingUpstream(t *testing.T) {
	dead := newFakeUpstream(t, false)
	alive := newFakeUpstream(t, true)
	proxy := newTestProxy(dead.addr, alive.addr)

	lookup(t, proxy, "first.example.com.")
	if dead.queryCount() != 1 {
		t.Fatalf("the dead upstream saw %d queries, want 1", dead.queryCount())
	}

	for _, name := range []string{"second.example.com.", "third.example.com."} {
		lookup(t, proxy, name)
	}

	if got := dead.queryCount(); got != 1 {
		t.Errorf("the dead upstream saw %d queries, want 1: it must be skipped during its cooldown", got)
	}
	if got := alive.queryCount(); got != 3 {
		t.Errorf("the working upstream answered %d queries, want 3", got)
	}
}

// Once the cooldown has passed the upstream is tried again, otherwise a
// resolver that comes back would stay unused until the next restart.
func TestLookupRetriesAfterTheCooldown(t *testing.T) {
	previous := upstreamCooldown
	upstreamCooldown = time.Millisecond
	t.Cleanup(func() { upstreamCooldown = previous })

	dead := newFakeUpstream(t, false)
	alive := newFakeUpstream(t, true)
	proxy := newTestProxy(dead.addr, alive.addr)

	lookup(t, proxy, "first.example.com.")
	time.Sleep(5 * time.Millisecond)
	lookup(t, proxy, "second.example.com.")

	if got := dead.queryCount(); got != 2 {
		t.Errorf("the recovered upstream saw %d queries, want 2", got)
	}
}

// With every upstream in its cooldown, answering slowly still beats not
// answering at all.
func TestOrderedUpstreamsKeepsAllUpstreams(t *testing.T) {
	proxy := newTestProxy("192.0.2.1", "192.0.2.2")
	proxy.markFailed("192.0.2.1")
	proxy.markFailed("192.0.2.2")

	if got := proxy.orderedUpstreams(); len(got) != 2 {
		t.Errorf("orderedUpstreams() = %q, want both upstreams", got)
	}
}

func TestOrderedUpstreamsPutsFailingOnesLast(t *testing.T) {
	proxy := newTestProxy("192.0.2.1", "192.0.2.2", "192.0.2.3")
	proxy.markFailed("192.0.2.1")

	got := proxy.orderedUpstreams()
	want := []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orderedUpstreams() = %q, want %q", got, want)
		}
	}
}

// A successful answer clears an earlier failure, so a resolver that flaps
// does not stay at the back of the queue forever.
func TestSuccessClearsAFailure(t *testing.T) {
	proxy := newTestProxy("192.0.2.1", "192.0.2.2")
	proxy.markFailed("192.0.2.1")
	proxy.markHealthy("192.0.2.1")

	if got := proxy.orderedUpstreams()[0]; got != "192.0.2.1" {
		t.Errorf("first upstream is %q, want 192.0.2.1", got)
	}
}

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
