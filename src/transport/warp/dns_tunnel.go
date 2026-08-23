// DNS inside the tunnel (design §7: "DNS через inner обязательно",
// warp-socks DoH-inner pattern at 162.159.36.1/.46.1).
//
// v1 RESOLUTION (owner decision, E8 close-out): plain UDP/53 DNS to
// Cloudflare's dedicated resolvers 162.159.36.1 / 162.159.46.1, carried as
// IP packets through the CONNECT-IP session, IS the shipping inner-path DNS
// of v1 — the anti-leak property is complete (queries never leave the
// tunnel). TLS-wrapped DoH (RFC 8484 over HTTPS-in-tunnel) is a planned
// ENCRYPTION upgrade gated on the userspace TCP carrier (BLOCKED_CARRIER,
// see backendb.go); it is an enhancement on top, not a deficiency fix.
package transportwarp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// InnerTunnelDNS1 / InnerTunnelDNS2 are Cloudflare's dedicated resolver
// addresses reachable only from inside WARP (warp-socks dns.rs pattern).
var (
	InnerTunnelDNS1 = [4]byte{162, 159, 36, 1}
	InnerTunnelDNS2 = [4]byte{162, 159, 46, 1}
)

var ErrDNSNoAnswer = errors.New("transportwarp: tunnel dns: no valid answer in time")

// TunnelResolver resolves names through one established session by
// exchanging raw IPv4/UDP DNS packets on it. A resolver owns its session's
// packet stream for the duration of each query — serialize queries per
// session (the engine never shares a session between pumps here).
type TunnelResolver struct {
	sess    *Session
	local   [4]byte
	server  [4]byte
	timeout time.Duration // per-query deadline, default 2s
}

func NewTunnelResolver(sess *Session, localV4 [4]byte) *TunnelResolver {
	return &TunnelResolver{sess: sess, local: localV4, server: InnerTunnelDNS1, timeout: 2 * time.Second}
}

// WithServer overrides the resolver address; WithTimeout the deadline.
func (r *TunnelResolver) WithServer(s [4]byte) *TunnelResolver        { r.server = s; return r }
func (r *TunnelResolver) WithTimeout(d time.Duration) *TunnelResolver { r.timeout = d; return r }

// LookupIP sends an A query for name and returns parsed addresses plus the
// observed round-trip time.
func (r *TunnelResolver) LookupIP(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	q, err := NewDNSProbe(r.local, r.server, name)
	if err != nil {
		return nil, 0, fmt.Errorf("query build: %w", err)
	}
	sport := udpSportOf(q.Packet)
	if sport == 0 {
		return nil, 0, errors.New("transportwarp: tunnel dns: bad query sport")
	}

	reader := newBurstReader(ctx, r.sess)
	defer reader.close()

	started := time.Now()
	if err := r.sess.WritePacket(q.Packet); err != nil {
		return nil, 0, fmt.Errorf("query send: %w", err)
	}

	deadline := time.NewTimer(r.timeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-deadline.C:
			return nil, 0, ErrDNSNoAnswer
		case m, open := <-reader.ch:
			if !open || m.err != nil {
				return nil, 0, ErrDNSNoAnswer
			}
			if !isDNSReply(m.data, r.local, r.server, sport, q.TXID) {
				continue // foreign payload or stale datagram: keep draining
			}
			addrs, perr := parseDNSA(m.data[28:]) // skip IPv4+UDP headers
			if perr != nil || len(addrs) == 0 {
				return nil, 0, fmt.Errorf("%w: %v", ErrDNSNoAnswer, perr)
			}
			return addrs, time.Since(started), nil
		}
	}
}

// isDNSReply filters inbound tunnel packets to OUR transaction: IPv4/UDP
// from server:53 back to our source port, QR=1, matching txid.
func isDNSReply(pkt []byte, local, server [4]byte, sport uint16, txid [2]byte) bool {
	if len(pkt) < 20+8+12 {
		return false
	}
	if pkt[9] != 17 { // proto UDP
		return false
	}
	if string(pkt[12:16]) != string(server[:]) || string(pkt[16:20]) != string(local[:]) {
		return false
	}
	if binary.BigEndian.Uint16(pkt[20:22]) != 53 ||
		binary.BigEndian.Uint16(pkt[22:24]) != sport {
		return false
	}
	dns := pkt[28:]
	if dns[0] != txid[0] || dns[1] != txid[1] {
		return false
	}
	return dns[2]&0x80 != 0 // QR=1
}

// parseDNSA extracts A-record addresses from a DNS response (handles
// compressed names via pointer bytes without following loops beyond the
// message bounds).
func parseDNSA(resp []byte) ([]netip.Addr, error) {
	if len(resp) < 12 {
		return nil, errors.New("short dns header")
	}
	answers := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	questions := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < questions && off < len(resp); i++ {
		if err := skipDNSName(resp, &off); err != nil {
			return nil, err
		}
		off += 4 // qtype + qclass
	}
	var out []netip.Addr
	for i := 0; i < answers && off+10 <= len(resp); i++ {
		if err := skipDNSName(resp, &off); err != nil {
			return out, err
		}
		if off+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[off:])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if rtype == 1 && rdlen == 4 && off+4 <= len(resp) {
			out = append(out, netip.AddrFrom4([4]byte(resp[off:off+4])))
		}
		off += rdlen
	}
	return out, nil
}

// skipDNSName advances off past one (possibly compressed) name.
func skipDNSName(msg []byte, off *int) error {
	for {
		if *off >= len(msg) {
			return errors.New("dns name overrun")
		}
		b := msg[*off]
		switch {
		case b == 0:
			*off++
			return nil
		case b&0xC0 == 0xC0:
			if *off+2 > len(msg) {
				return errors.New("dns pointer overrun")
			}
			*off += 2
			return nil
		default:
			*off += 1 + int(b)
		}
	}
}

// udpSportOf extracts the query source port (fixed offset ip20+udp0).
func udpSportOf(pkt []byte) uint16 {
	if len(pkt) < 24 {
		return 0
	}
	return binary.BigEndian.Uint16(pkt[20:22])
}
