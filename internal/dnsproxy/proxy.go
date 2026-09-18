package dnsproxy

import (
	"fmt"
	"math"
	"net"
	"runtime/debug"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// upstreamCooldown is how long an upstream that failed is passed over. Long
// enough that a dead resolver does not cost every client another timeout,
// short enough to pick it up again quickly once it is back. A var so tests
// can shorten it.
var upstreamCooldown = 30 * time.Second

// DefaultCacheSize bounds how many responses are cached unless the operator
// configures another size. The cache is filled by whatever the VPN clients
// ask for, so it needs a limit: without one a client can grow it without end
// by querying random names. Least recently used entries are dropped once it
// is full.
const DefaultCacheSize = 10000

// cachedResponse is a cached upstream response together with the time it
// stops being valid. The expiry is per entry because it comes from the TTLs
// of the records in that response.
type cachedResponse struct {
	response  *dns.Msg
	expiresAt time.Time
}

func newResponseCache(size int) (*lru.Cache[string, cachedResponse], error) {
	return lru.New[string, cachedResponse](size)
}

type DNSProxy struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	cache     *lru.Cache[string, cachedResponse]
	upstream  []string

	// failedAt remembers when an upstream last failed, so the next queries
	// skip it instead of waiting for its timeout again.
	mu       sync.Mutex
	failedAt map[string]time.Time
}

// ServeDNS is called by the mux from the listening servers.
func (d *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Errorf("dns server panic handled: %v\n%s", err, string(debug.Stack()))
			dns.HandleFailed(w, r)
		}
	}()

	logrus.Debugf("dns query: %s", prettyPrintMsg(r))

	switch r.Opcode {
	case dns.OpcodeQuery:
		// Remove EDNS0 Client Subnet information as we don't handle them in the cache
		purgeECS(r)
		outQuery := r.Copy()
		// Set EDNS BufSize for forwarding to upstream
		ensureEDNS0BufSize(outQuery)
		m, err := d.Lookup(outQuery)
		if err != nil {
			logrus.Errorf("failed lookup record with error: %s\n%s", err.Error(), r)
			HandleFailed(w, r)
			return
		}
		// SetReply adopts the client's header (id, question, rd/cd bits) but
		// also resets the response code to NOERROR, which would turn an
		// upstream NXDOMAIN into an empty NOERROR answer and hide SERVFAIL
		// and REFUSED from the client. Put the upstream's code back.
		rcode := m.Rcode
		m.SetReply(r)
		m.Rcode = rcode
		truncateIfRequired(m, r, w.RemoteAddr().Network())
		err = w.WriteMsg(m)
		if err != nil {
			logrus.Errorf("failed write response for client with error: %s\n%s", err.Error(), r)
			return
		}
	default:
		m := &dns.Msg{}
		m.SetReply(r)
		err := w.WriteMsg(m)
		if err != nil {
			logrus.Errorf("failed write response for client with error: %s\n%s", err.Error(), r)
			return
		}
	}

}

// Lookup first checks the cache for a matching response, and if unsuccessful queries the upstream resolvers.
func (d *DNSProxy) Lookup(m *dns.Msg) (*dns.Msg, error) {
	key := makekey(m)

	// check the cache first, unless caching is turned off
	if d.cache != nil {
		if entry, found := d.cache.Get(key); found {
			if time.Now().Before(entry.expiresAt) {
				logrus.Debugf("dns cache hit %s", prettyPrintMsg(m))
				return entry.response.Copy(), nil
			}
			// The LRU has no janitor of its own, so drop what has expired
			// when we come across it.
			d.cache.Remove(key)
		}
	}

	// fallback to upstream exchange
	var response *dns.Msg
	var firstErr error
	for _, upstream := range d.orderedUpstreams() {
		resp, err := d.exchange(m, upstream)
		if err != nil {
			logrus.Warnf("DNS lookup failed for upstream %s: %v", upstream, err)
			d.markFailed(upstream)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		d.markHealthy(upstream)
		response = resp
		break
	}
	if response == nil {
		if firstErr != nil {
			return nil, fmt.Errorf("no response from upstream servers: %w", firstErr)
		}
		return nil, fmt.Errorf("no upstream servers configured")
	}

	d.cacheResponse(key, response)

	return response.Copy(), nil
}

// exchange sends the query to one upstream, retrying over TCP when the
// response comes back truncated.
func (d *DNSProxy) exchange(m *dns.Msg, upstream string) (*dns.Msg, error) {
	target := upstreamAddr(upstream)

	response, _, err := d.udpClient.Exchange(m, target)
	if err != nil {
		return nil, err
	}
	if !response.Truncated {
		return response, nil
	}

	response, _, err = d.tcpClient.Exchange(m, target)
	if err != nil {
		return nil, fmt.Errorf("retry over TCP failed: %w", err)
	}
	return response, nil
}

// upstreamAddr adds the default DNS port to an upstream that does not name
// one, so "192.0.2.1", "192.0.2.1:5353", "2001:db8::1" and "[2001:db8::1]:5353"
// all work.
func upstreamAddr(upstream string) string {
	if _, _, err := net.SplitHostPort(upstream); err == nil {
		return upstream
	}
	return net.JoinHostPort(upstream, "53")
}

// orderedUpstreams returns the upstreams to try, in order: the ones that are
// not in their cooldown first, the rest behind them. Failing upstreams are
// passed over rather than dropped - when every upstream is in its cooldown,
// answering slowly still beats answering not at all.
func (d *DNSProxy) orderedUpstreams() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	healthy := make([]string, 0, len(d.upstream))
	var cooling []string
	for _, upstream := range d.upstream {
		if failed, ok := d.failedAt[upstream]; ok && time.Since(failed) < upstreamCooldown {
			cooling = append(cooling, upstream)
			continue
		}
		healthy = append(healthy, upstream)
	}
	return append(healthy, cooling...)
}

func (d *DNSProxy) markFailed(upstream string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failedAt == nil {
		d.failedAt = map[string]time.Time{}
	}
	d.failedAt[upstream] = time.Now()
}

func (d *DNSProxy) markHealthy(upstream string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.failedAt, upstream)
}

// cacheResponse stores a response using the minimum TTL across all of its
// records so the cache never serves a record past its TTL. A minimum TTL of 0
// means the response must not be cached at all (e.g. DNS failover setups rely
// on that).
func (d *DNSProxy) cacheResponse(key string, response *dns.Msg) {
	if d.cache == nil {
		return
	}
	if len(response.Answer) == 0 {
		return
	}
	if ttl := minTTL(response); ttl > 0 {
		logrus.Debugf("caching dns response for %s for %v", prettyPrintMsg(response), ttl)
		d.cache.Add(key, cachedResponse{response: response, expiresAt: time.Now().Add(ttl)})
	} else {
		logrus.Debugf("not caching dns response for %s: minimum record TTL is 0", prettyPrintMsg(response))
	}
}

// minTTL returns the minimum TTL across all records in the message (Answer,
// Ns and Extra sections), or 0 if the message contains no such records.
// OPT pseudo-records are ignored because their header TTL field encodes
// extended RCODE and flags rather than a time to live.
func minTTL(m *dns.Msg) time.Duration {
	min := uint32(math.MaxUint32)
	found := false
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if ttl := rr.Header().Ttl; ttl < min {
				min = ttl
			}
			found = true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(min) * time.Second
}

func purgeECS(m *dns.Msg) {
	if opt := m.IsEdns0(); opt != nil {
		filtered := opt.Option[:0]
		for _, option := range opt.Option {
			if option.Option() != dns.EDNS0SUBNET {
				filtered = append(filtered, option)
			}
		}
		opt.Option = filtered
	}
}

func ensureEDNS0BufSize(m *dns.Msg) {
	if opt := m.IsEdns0(); opt != nil {
		opt.SetUDPSize(1232)
	} else {
		m.SetEdns0(1232, false)
	}
}

func truncateIfRequired(response *dns.Msg, original *dns.Msg, transport string) {
	size := dns.MinMsgSize
	if transport == "tcp" {
		size = dns.MaxMsgSize
	} else if opt := original.IsEdns0(); opt != nil {
		size = int(opt.UDPSize())
	}
	logrus.Debugf("truncating to %d", size)
	response.Truncate(size)
}
