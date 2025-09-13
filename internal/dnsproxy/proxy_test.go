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
