package nfq

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// QUIC Version-Negotiation liveness probe (Часть 3 П.5; zapret-gui
// quic_tester.py:35-85): one UDP/443 long-header packet with a force-VN
// version (0x?a?a?a?a, RFC 9000 §15) padded to 1200 bytes. ANY answer counts
// as "QUIC reachable"; version field 0 = true Version Negotiation. No crypto,
// no handshake state — the cheapest possible automatic "QUIC is alive" fact
// for L0/L3 gates and for the qbp guard's liveness map.

const (
	vnbInterval      = 5 * time.Minute
	vnbInitialDelay  = 45 * time.Second
	vnbTimeout       = 2 * time.Second
	vnbRetries       = 2
	vnbMaxTargets    = 8
	vnbMinDatagram   = 1200
	forceVNVersion   = 0x1A2A3A4A
)

type vnbVerdict struct {
	alive bool
	at    time.Time
}

// vnbRegistry stores the latest probe outcome per shard IP so other layers
// (ggcdisc hint feeding) can skip endpoints that just proved dead.
var vnbRegistry = struct {
	sync.Mutex
	m map[string]vnbVerdict
}{m: make(map[string]vnbVerdict)}

func vnbMark(addr netip.Addr, alive bool, now time.Time) {
	vnbRegistry.Lock()
	vnbRegistry.m[addr.String()] = vnbVerdict{alive: alive, at: now}
	vnbRegistry.Unlock()
}

// vnbLastVerdict returns the most recent probe outcome for addr.
func vnbLastVerdict(addr netip.Addr) (vnbVerdict, bool) {
	vnbRegistry.Lock()
	v, ok := vnbRegistry.m[addr.String()]
	vnbRegistry.Unlock()
	return v, ok
}

type vnbProbe struct {
	w    *Worker
	mu   sync.Mutex
	last map[string]bool // "ip|host" -> last alive verdict (Warn on change only)
}

func StartVNBProbe(ctx context.Context, cfgPtr *(atomic.Pointer[config.Config]), pool *Pool) {
	if !vnbEnabled || ctx == nil || cfgPtr == nil || pool == nil || len(pool.Workers) == 0 {
		return
	}
	p := &vnbProbe{w: pool.Workers[0], last: make(map[string]bool)}
	go p.loop(ctx)
	log.Infof("[vnb] QUIC VN probe started (interval=%v timeout=%v retries=%d)", vnbInterval, vnbTimeout, vnbRetries)
}

func (p *vnbProbe) loop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(vnbInitialDelay):
	}
	ticker := time.NewTicker(vnbInterval)
	defer ticker.Stop()
	for {
		p.cycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *vnbProbe) cycle(ctx context.Context) {
	body, err := ggcdiscHTTPFetch(ctx)
	if err != nil {
		log.Tracef("[vnb] shard discovery unavailable: %v", err)
		return
	}
	hosts := ggcdiscExtractShardHosts(body, vnbMaxTargets)
	if len(hosts) == 0 {
		log.Tracef("[vnb] no shard hosts to probe")
		return
	}
	now := time.Now()
	for _, host := range hosts {
		addrs, err := ggcdiscDNSResolve(ctx, host)
		if err != nil {
			continue
		}
		var addr netip.Addr
		for _, a := range addrs {
			if ggcdiscPublicIPv4(a) {
				addr = a
				break
			}
		}
		if !addr.IsValid() {
			continue
		}
		alive, vn, rtt := probeQUICVN(ctx, addr)
		vnbMark(addr, alive, now)
		if alive && p.w != nil && p.w.qbp != nil {
			p.w.qbp.noteIP(addr.String(), now)
			p.w.qbp.noteHost(host, now)
		}
		key := addr.String() + "|" + host
		p.mu.Lock()
		prev, known := p.last[key]
		if !known || prev != alive {
			p.last[key] = alive
			p.mu.Unlock()
			log.Warnf("[vnb] %s (%s) alive=%t vn=%t rtt=%s", host, addr, alive, vn, rtt.Round(time.Millisecond))
			continue
		}
		p.mu.Unlock()
		log.Tracef("[vnb] %s (%s) alive=%t vn=%t rtt=%s", host, addr, alive, vn, rtt.Round(time.Millisecond))
	}
}

// probeQUICVN sends one force-VN datagram and classifies any answer.
func probeQUICVN(ctx context.Context, addr netip.Addr) (alive bool, vn bool, rtt time.Duration) {
	packet := buildVNBPacket()
	udpAddr := &net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: 443}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return false, false, 0
	}
	defer conn.Close()
	for attempt := 0; attempt < vnbRetries; attempt++ {
		start := time.Now()
		if _, err := conn.Write(packet); err != nil {
			return false, false, 0
		}
		buf := make([]byte, vnbMinDatagram)
		if err := conn.SetReadDeadline(start.Add(vnbTimeout)); err != nil {
			return false, false, 0
		}
		n, err := conn.Read(buf)
		rtt = time.Since(start)
		if err != nil {
			continue // timeout -> retry
		}
		if n >= 1 {
			vn = n >= 5 && buf[0]&0x80 != 0 && binary.BigEndian.Uint32(buf[1:5]) == 0
			return true, vn, rtt
		}
	}
	return false, false, 0
}

// buildVNBPacket mirrors zapret-gui quic_tester.build_quic_vn_probe:
// long header 0xC0, force-VN version, 8-byte DCID + 8-byte SCID, zero pad to
// the 1200-byte QUIC minimum so middleboxes do not drop it as noise.
func buildVNBPacket() []byte {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)

	header := make([]byte, 0, 22)
	header = append(header, 0xC0)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], forceVNVersion)
	header = append(header, ver[:]...)
	header = append(header, 8)
	header = append(header, dcid...)
	header = append(header, 8)
	header = append(header, scid...)

	packet := make([]byte, vnbMinDatagram)
	copy(packet, header)
	return packet
}
