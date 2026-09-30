package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is the set of networks that requests legitimately reach this
// server through. It decides one thing: whether the forwarded headers of a
// request may be believed.
//
// Nothing here grants access. The address a request came from is used for the
// logs, the audit trail and the list of sessions somebody sees of their own -
// all of which are useless behind a reverse proxy, where every user shares the
// proxy's address. The login throttle deliberately does not use it and is
// keyed by username instead, so a forged header cannot skip it.
type TrustedProxies struct {
	nets []netip.Prefix
}

// ParseTrustedProxies reads the configured entries, each a CIDR or a bare
// address. An empty list trusts nothing, which is the default.
func ParseTrustedProxies(entries []string) (*TrustedProxies, error) {
	trusted := &TrustedProxies{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if prefix, err := netip.ParsePrefix(entry); err == nil {
			trusted.nets = append(trusted.nets, prefix.Masked())
			continue
		}
		// A bare address is the network that holds only itself.
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("'%s' is neither a network nor an address", entry)
		}
		trusted.nets = append(trusted.nets, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return trusted, nil
}

// Any says whether anything is trusted at all.
func (t *TrustedProxies) Any() bool {
	return t != nil && len(t.nets) > 0
}

func (t *TrustedProxies) contains(addr netip.Addr) bool {
	if !t.Any() {
		return false
	}
	// A v4 address that arrived as ::ffff:a.b.c.d has to match a v4 network.
	addr = addr.Unmap()
	for _, network := range t.nets {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientAddrMiddleware replaces the address of a request that came through a
// trusted proxy with the address the client connected from, so that everything
// downstream - the audit trail, the sign-in log, a person's own list of
// sessions - reports the client rather than the proxy.
//
// Rewriting the request rather than adding an accessor keeps the nine places
// that report an address as they are, and none of them decides anything.
func ClientAddrMiddleware(trusted *TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if client := trusted.clientAddr(r); client != "" {
				r = r.Clone(r.Context())
				r.RemoteAddr = client
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientAddr is the address to report, or empty to leave the request alone.
func (t *TrustedProxies) clientAddr(r *http.Request) string {
	if !t.Any() || r == nil {
		return ""
	}

	peer, ok := addrOf(r.RemoteAddr)
	if !ok || !t.contains(peer) {
		// Not from a proxy we trust, so its headers say nothing: a client
		// reaching the server directly must not be able to choose the
		// address it is logged under.
		return ""
	}

	// The chain reads oldest first, each proxy appending the address it was
	// spoken to by. Everything a trusted proxy added is trustworthy, so the
	// client is the last entry that is not itself one of ours; entries
	// before it were written by whoever was there first and can say
	// anything.
	chain := forwardedFor(r)
	for i := len(chain) - 1; i >= 0; i-- {
		candidate, ok := addrOf(chain[i])
		if !ok || t.contains(candidate) {
			continue
		}
		return candidate.Unmap().String()
	}

	// No usable chain. Some proxies send only this, and it comes from a
	// proxy we trust.
	if real, ok := addrOf(r.Header.Get("X-Real-Ip")); ok && !t.contains(real) {
		return real.Unmap().String()
	}

	return ""
}

func forwardedFor(r *http.Request) []string {
	var chain []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, entry := range strings.Split(header, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				chain = append(chain, entry)
			}
		}
	}
	return chain
}

// addrOf reads an address that may carry a port, brackets or an interface
// zone, in whatever shape a proxy wrote it.
func addrOf(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.WithZone(""), true
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.WithZone(""), true
		}
	}
	return netip.Addr{}, false
}
