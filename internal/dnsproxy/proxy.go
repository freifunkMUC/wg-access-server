package dnsproxy

import (
	"fmt"
	"math"
	"net"
	"runtime/debug"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type DNSProxy struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	cache     *cache.Cache
	upstream  []string
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

	// check the cache first
	if item, found := d.cache.Get(key); found {
		logrus.Debugf("dns cache hit %s", prettyPrintMsg(m))
		return item.(*dns.Msg).Copy(), nil
	}

	// fallback to upstream exchange
	// TODO disable upstream after certain amount of failures?
	var response *dns.Msg
	var firstErr error
	for _, upstream := range d.upstream {
		target := net.JoinHostPort(upstream, "53")
		resp, _, err := d.udpClient.Exchange(m, target)
		if err != nil && firstErr == nil {
			logrus.Warnf("DNS lookup failed for upstream %s: %v", upstream, err)
			firstErr = err
		} else if err == nil {
			// Retry truncated responses over TCP
			if resp.Truncated {
				resp, _, err = d.tcpClient.Exchange(m, target)
				if err != nil && firstErr == nil {
					logrus.Warnf("DNS lookup failed over TCP for upstream %s: %v", upstream, err)
					firstErr = err
					continue
				}
			}
			response = resp
			break
		}
	}
	if response == nil {
		return nil, fmt.Errorf("no response from upstream servers")
	}

	d.cacheResponse(key, response)

	return response.Copy(), nil
}

// cacheResponse stores a response using the minimum TTL across all of its
// records so the cache never serves a record past its TTL. A minimum TTL of 0
// means "do not cache": passing a zero duration to go-cache would make it use
// the cache's DefaultExpiration instead, pinning deliberately uncacheable
// records (e.g. DNS failover) for minutes.
func (d *DNSProxy) cacheResponse(key string, response *dns.Msg) {
	if len(response.Answer) == 0 {
		return
	}
	if ttl := minTTL(response); ttl > 0 {
		logrus.Debugf("caching dns response for %s for %v", prettyPrintMsg(response), ttl)
		d.cache.Set(key, response, ttl)
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
