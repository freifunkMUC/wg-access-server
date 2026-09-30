package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func trust(t *testing.T, entries ...string) *TrustedProxies {
	t.Helper()
	trusted, err := ParseTrustedProxies(entries)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func requestFrom(peer string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://vpn.example.com/signin", nil)
	r.RemoteAddr = peer
	for _, value := range forwarded {
		r.Header.Add("X-Forwarded-For", value)
	}
	return r
}

func TestTheClientAddressBehindATrustedProxy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		trusted   []string
		peer      string
		forwarded []string
		want      string
	}{
		{
			name:      "the proxy names the client",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"203.0.113.7"},
			want:      "203.0.113.7",
		},
		{
			// what a client sent before the proxy appended to it can say
			// anything, so only the entries our own proxies wrote count
			name:      "a chain the client started is not believed past our own",
			trusted:   []string{"172.18.0.0/16", "10.0.0.0/8"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"198.51.100.9, 203.0.113.7, 10.0.0.1"},
			want:      "203.0.113.7",
		},
		{
			name:      "several headers read as one chain",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"198.51.100.9", "203.0.113.7"},
			want:      "203.0.113.7",
		},
		{
			name:      "a bare address is a network of its own",
			trusted:   []string{"172.18.0.4"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"203.0.113.7"},
			want:      "203.0.113.7",
		},
		{
			// the trusted network is the /64 the proxy sits in, so the
			// client one subnet over is not one of ours
			name:      "IPv6 throughout",
			trusted:   []string{"2001:db8::/64"},
			peer:      "[2001:db8::4]:60904",
			forwarded: []string{"2001:db8:1::9, 2001:db8::4"},
			want:      "2001:db8:1::9",
		},
		{
			name:      "a proxy that writes a port on the entry",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"203.0.113.7:41234"},
			want:      "203.0.113.7",
		},
		{
			// this is the whole point of the trusted list
			name:      "a client reaching the server directly is not believed",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "203.0.113.7:41234",
			forwarded: []string{"198.51.100.1"},
			want:      "",
		},
		{
			name:      "nothing configured believes nothing",
			trusted:   nil,
			peer:      "172.18.0.4:60904",
			forwarded: []string{"203.0.113.7"},
			want:      "",
		},
		{
			name:      "a trusted proxy that forwards nothing leaves the request alone",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: nil,
			want:      "",
		},
		{
			name:      "a chain of nothing but our own proxies names no client",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"172.18.0.9, 172.18.0.4"},
			want:      "",
		},
		{
			name:      "rubbish in the header is skipped",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"not-an-address, 203.0.113.7, unknown"},
			want:      "203.0.113.7",
		},
		{
			name:      "an IPv4 client arriving as a mapped v6 address",
			trusted:   []string{"172.18.0.0/16"},
			peer:      "172.18.0.4:60904",
			forwarded: []string{"::ffff:203.0.113.7"},
			want:      "203.0.113.7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := trust(t, tc.trusted...).clientAddr(requestFrom(tc.peer, tc.forwarded...))
			if got != tc.want {
				t.Errorf("clientAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

// Some proxies send only this one, and it carries no chain. It is read only
// when the request came from a proxy we trust.
func TestXRealIPIsUsedWhenThereIsNoChain(t *testing.T) {
	r := requestFrom("172.18.0.4:60904")
	r.Header.Set("X-Real-Ip", "203.0.113.7")

	if got := trust(t, "172.18.0.0/16").clientAddr(r); got != "203.0.113.7" {
		t.Errorf("clientAddr = %q, want the address the proxy reported", got)
	}

	direct := requestFrom("203.0.113.9:41234")
	direct.Header.Set("X-Real-Ip", "198.51.100.1")
	if got := trust(t, "172.18.0.0/16").clientAddr(direct); got != "" {
		t.Errorf("clientAddr = %q, want nothing from a client reaching the server directly", got)
	}
}

// The chain wins over X-Real-Ip when both are there: it is the one with
// enough information to tell our proxies from whoever came before them.
func TestTheChainIsPreferredOverXRealIP(t *testing.T) {
	r := requestFrom("172.18.0.4:60904", "203.0.113.7")
	r.Header.Set("X-Real-Ip", "198.51.100.1")

	if got := trust(t, "172.18.0.0/16").clientAddr(r); got != "203.0.113.7" {
		t.Errorf("clientAddr = %q, want the address from the chain", got)
	}
}

// The middleware is what the rest of the server sees, so what it rewrites is
// what the audit trail and the logs report.
func TestMiddlewareRewritesTheRequest(t *testing.T) {
	var seen string
	handler := ClientAddrMiddleware(trust(t, "172.18.0.0/16"))(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r.RemoteAddr }))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("172.18.0.4:60904", "203.0.113.7"))
	if seen != "203.0.113.7" {
		t.Errorf("the handler saw %q, want the client address", seen)
	}

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("203.0.113.9:41234", "198.51.100.1"))
	if seen != "203.0.113.9:41234" {
		t.Errorf("the handler saw %q, want the address it connected from", seen)
	}
}

func TestParseTrustedProxiesRefusesNonsense(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"172.18.0.0/16", "not-a-network"}); err == nil {
		t.Error("an entry that is neither a network nor an address was accepted")
	}

	// blank entries are ignored, so a trailing comma in an env var is not an
	// error
	trusted, err := ParseTrustedProxies([]string{"172.18.0.0/16", "  ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.Any() {
		t.Error("the one real entry was lost")
	}
}

// A nil set is what a server without the option has, and it must not panic.
func TestNoTrustedProxiesAtAll(t *testing.T) {
	var trusted *TrustedProxies
	if trusted.Any() {
		t.Error("a nil set trusts something")
	}
	if got := trusted.clientAddr(requestFrom("172.18.0.4:60904", "203.0.113.7")); got != "" {
		t.Errorf("clientAddr = %q, want nothing", got)
	}
}
