// DoH upgrade layer (design §7 "DNS через inner обязательно", warp-socks
// dns.rs pattern).
//
// v1 RESOLUTION (owner decision, E8 close-out): the shipping inner-path DNS
// of v1 is UDP/53-in-tunnel (dns_tunnel.go TunnelResolver) — its anti-leak
// property is COMPLETE. This file is the ready ENCRYPTION UPGRADE: RFC 8484
// wireformat (query construction, response parsing with per-record TTL) and
// a TTL-clamped cache ([5s..300s], warp-socks numbers) behind a
// TunnelResolver-compatible ResolveA shape, so the geo gate can switch
// carriers without shape changes.
//
// The byte carrier stays injected (DoHExchangeFunc): DoH-over-H2 inside the
// CONNECT-IP tunnel needs TCP-through-base, i.e. the same userspace carrier
// as Backend B. With no carrier attached every call fails closed with
// ErrDoHNotWired (wrapping ErrBlockedCarrier) — diagnostics classify this
// as "carrier absent", never as a network failure.
package transportwarp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// DoH cache clamp (warp-socks ttl.rs numbers).
const (
	DoHMinTTL = 5 * time.Second
	DoHMaxTTL = 300 * time.Second
)

// ErrDoHNotWired reports a missing base-tunnel HTTPS carrier; wraps
// ErrBlockedCarrier (structural layer classification).
var ErrDoHNotWired = fmt.Errorf("transportwarp: doh %w", ErrBlockedCarrier)

// ErrDoHResponse reports an unusable DNS response payload.
var ErrDoHResponse = errors.New("transportwarp: doh response unusable")

// DoHExchangeFunc carries one RFC 8484 query: wire-format DNS request in,
// wire-format DNS response out. URL/content-type decisions belong to this
// layer; the carrier only moves bytes.
type DoHExchangeFunc func(ctx context.Context, query []byte) ([]byte, error)

// dnsQueryWire builds a recursive A-query DNS message for name; returns the
// message and its transaction id.
func dnsQueryWire(name string) ([]byte, [2]byte, error) {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return nil, [2]byte{}, errors.New("transportwarp: invalid qname")
	}
	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, [2]byte{}, err
	}
	msg := make([]byte, 0, 17+len(name)+4)
	msg = append(msg, txid[0], txid[1])
	msg = append(msg, 0x01, 0x00) // RD=1
	msg = append(msg, 0x00, 0x01) // QDCOUNT=1
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	start := 0
	for {
		dot := indexByte(name[start:], '.')
		label := name[start:]
		if dot >= 0 {
			label = name[start : start+dot]
		}
		if len(label) == 0 || len(label) > 63 {
			return nil, [2]byte{}, errors.New("transportwarp: invalid probe label")
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
		if dot < 0 {
			break
		}
		start += dot + 1
	}
	msg = append(msg, 0x00)       // root label
	msg = append(msg, 0x00, 0x01) // QTYPE=A
	msg = append(msg, 0x00, 0x01) // QCLASS=IN
	return msg, txid, nil
}

// parseDNSAWithTTL extracts A records plus the minimum positive TTL across
// answers (cache semantics). Reuses the compressed-name walker from
// dns_tunnel.go.
func parseDNSAWithTTL(resp []byte) ([]netip.Addr, uint32, error) {
	if len(resp) < 12 {
		return nil, 0, errors.New("short dns header")
	}
	if resp[2]&0x80 == 0 {
		return nil, 0, errors.New("not a response (QR=0)")
	}
	if rc := resp[3] & 0x0f; rc != 0 {
		return nil, 0, errors.New("dns rcode != NOERROR")
	}
	answers := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	questions := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < questions && off < len(resp); i++ {
		if err := skipDNSName(resp, &off); err != nil {
			return nil, 0, err
		}
		off += 4
	}
	var addrs []netip.Addr
	minTTL := uint32(0)
	for i := 0; i < answers && off+10 <= len(resp); i++ {
		if err := skipDNSName(resp, &off); err != nil {
			return addrs, minTTL, err
		}
		if off+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[off:])
		ttl := binary.BigEndian.Uint32(resp[off+4:])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if rtype == 1 && rdlen == 4 && off+4 <= len(resp) {
			addrs = append(addrs, netip.AddrFrom4([4]byte(resp[off:off+4])))
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
		off += rdlen
	}
	if len(addrs) == 0 {
		return nil, 0, errors.New("no A records")
	}
	return addrs, minTTL, nil
}

type dohEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// DoHResolver resolves A records over an injectable RFC 8484 carrier with a
// TTL-clamped cache. Safe for concurrent use.
type DoHResolver struct {
	mu       sync.Mutex
	exchange DoHExchangeFunc
	cache    map[string]dohEntry
	now      func() time.Time
}

func NewDoHResolver() *DoHResolver {
	return &DoHResolver{cache: map[string]dohEntry{}, now: time.Now}
}

// WithExchange attaches the base-tunnel carrier (nil restores fail-closed).
func (r *DoHResolver) WithExchange(fn DoHExchangeFunc) *DoHResolver {
	r.mu.Lock()
	r.exchange = fn
	r.mu.Unlock()
	return r
}

// WithClock overrides the clock (tests).
func (r *DoHResolver) WithClock(now func() time.Time) *DoHResolver {
	r.mu.Lock()
	r.now = now
	r.mu.Unlock()
	return r
}

// ResolveA returns cached addresses within their clamped TTL or performs
// one exchange. Negative results are never cached.
func (r *DoHResolver) ResolveA(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	r.mu.Lock()
	exchange, now := r.exchange, r.now
	if entry, ok := r.cache[name]; ok && now().Before(entry.expires) {
		addrs := append([]netip.Addr(nil), entry.addrs...)
		ttl := entry.expires.Sub(now())
		r.mu.Unlock()
		return addrs, ttl, nil
	}
	r.mu.Unlock()

	if exchange == nil {
		return nil, 0, ErrDoHNotWired
	}
	query, _, err := dnsQueryWire(name)
	if err != nil {
		return nil, 0, err
	}
	resp, err := exchange(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	addrs, minTTL, perr := parseDNSAWithTTL(resp)
	if perr != nil {
		return nil, 0, perr
	}

	ttl := time.Duration(minTTL) * time.Second
	if ttl < DoHMinTTL {
		ttl = DoHMinTTL
	}
	if ttl > DoHMaxTTL {
		ttl = DoHMaxTTL
	}

	r.mu.Lock()
	r.cache[name] = dohEntry{addrs: append([]netip.Addr(nil), addrs...), expires: now().Add(ttl)}
	r.mu.Unlock()
	return addrs, ttl, nil
}
