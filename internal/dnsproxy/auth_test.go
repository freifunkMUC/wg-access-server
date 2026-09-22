package dnsproxy

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSAuth_Lookup(t *testing.T) {
	serverAddr := netip.MustParseAddr("10.44.0.1")
	deviceAddr := netip.MustParseAddr("10.44.0.2")

	auth := &DNSAuth{
		Domain:   dns.Fqdn("vpn.example.com"),
		zoneLock: new(sync.RWMutex),
	}
	auth.PushZone(Zone{
		{}:                               {serverAddr},
		{Owner: "alice", Name: "laptop"}: {deviceAddr},
	})

	lookupA := func(t *testing.T, qname string) *dns.Msg {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(qname, dns.TypeA)
		resp, err := auth.Lookup(query)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	expectA := func(t *testing.T, resp *dns.Msg, addr netip.Addr) {
		t.Helper()
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("expected A record, got %T", resp.Answer[0])
		}
		if a.A.String() != addr.String() {
			t.Fatalf("expected %s, got %s", addr, a.A)
		}
	}

	t.Run("device and owner names ignore case", func(t *testing.T) {
		auth.PushZone(Zone{
			{}:                               {serverAddr},
			{Owner: "alice", Name: "laptop"}: {deviceAddr},
			{Owner: "Bob", Name: "iPhone"}:   {deviceAddr},
		})
		for _, qname := range []string{"iphone.bob.vpn.example.com.", "IPHONE.BOB.vpn.example.com.", "iPhone.Bob.vpn.example.com."} {
			expectA(t, lookupA(t, qname), deviceAddr)
		}
	})

	t.Run("lowercase device query resolves", func(t *testing.T) {
		expectA(t, lookupA(t, "laptop.alice.vpn.example.com."), deviceAddr)
	})

	t.Run("mixed-case domain suffix resolves", func(t *testing.T) {
		expectA(t, lookupA(t, "laptop.alice.VpN.eXaMpLe.CoM."), deviceAddr)
	})

	t.Run("uppercase domain suffix resolves", func(t *testing.T) {
		expectA(t, lookupA(t, "laptop.alice.VPN.EXAMPLE.COM."), deviceAddr)
	})

	t.Run("mixed-case query for the search domain itself returns server address", func(t *testing.T) {
		expectA(t, lookupA(t, "VPN.Example.Com."), serverAddr)
	})

	t.Run("unknown device with mixed-case suffix returns NXDOMAIN", func(t *testing.T) {
		resp := lookupA(t, "unknown.alice.VPN.Example.COM.")
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
		}
	})
}
