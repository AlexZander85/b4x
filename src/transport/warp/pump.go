// TUN/PBR field-facing packet pump (design §2 rows MTU/Uplink/Downlink
// watchdog; design §11.3: the APPLY of TUN/NDM/PBR belongs to the field
// session on the router — this file is the engine-side io adapter that the
// field layer mounts a real tun device into).
//
// Responsibilities (all offline-testable):
//   - uplink pump: TUNDevice → session, with MTU enforcement and the
//     synthetic ICMP TooBig(1280) answer for oversized packets (usque would
//     silently TRUNCATE oversized reads; we answer with ICMP so the sender
//     re-clamps PMTU);
//   - downlink pump: session → TUNDevice;
//   - downlink idle watchdog (Aether WG-watchdog adaptation, recorded E3
//     gap): no inbound data > DownlinkIdleTimeout while active → single
//     OnStall callback and pump termination ("stall") instead of a silent
//     black-hole.
package transportwarp

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// DefaultDownlinkIdleTimeout is the Aether WG-watchdog number adapted to
// MASQUE (research Part 4): 10s without ANY inbound data while active.
const DefaultDownlinkIdleTimeout = 10 * time.Second

// ICMPTunnelMTU is the clamped MTU advertised in synthetic ICMP TooBig
// messages (addendum §16 / design §2).
const ICMPTunnelMTU = 1280

// ErrTUNClosed reports the TUN device side terminated.
var ErrTUNClosed = errors.New("transportwarp: tun device closed")

// TUNDevice is the minimal device face the field layer implements (a real
// /dev/net/tun fd, a veth pair, or an in-memory fake in tests).
type TUNDevice interface {
	// ReadPacket blocks until one outbound IP packet is available.
	ReadPacket(ctx context.Context) ([]byte, error)
	// WritePacket injects one inbound IP packet into the device.
	WritePacket(pkt []byte) error
	// Close terminates both directions; pending reads unblock with an error.
	Close() error
}

// PumpSession is the tunnel face of one pump (satisfied by *Session).
type PumpSession interface {
	WritePacket(pkt []byte) error
	ReadPacket(ctx context.Context) ([]byte, error)
	Done() <-chan struct{}
}

// PumpConfig tunes one pump instance.
type PumpConfig struct {
	Session PumpSession
	TUN     TUNDevice

	MTU                 int           // session-side MTU; DefaultMTU when zero
	DownlinkIdleTimeout time.Duration // DefaultDownlinkIdleTimeout when zero
	OnStall             func()        // called AT MOST once on idle-watchdog expiry
	StallCheckEvery     time.Duration // watchdog poll cadence, default 1s
}

// Pump moves packets between a TUN device and one tunnel session until the
// parent context is cancelled or either side reports a terminal condition.
// It returns the structured stop reason:
//
//	"stop"          — parent context cancelled;
//	"session-lost"  — tunnel read/write failed terminally;
//	"tun-closed"    — device side terminated;
//	"stall"         — downlink idle watchdog expired (OnStall already fired).
//
// All internal goroutines are joined before returning; no leaks.
func Pump(parent context.Context, cfg PumpConfig) string {
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.DownlinkIdleTimeout <= 0 {
		cfg.DownlinkIdleTimeout = DefaultDownlinkIdleTimeout
	}
	if cfg.StallCheckEvery <= 0 {
		cfg.StallCheckEvery = time.Second
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// First terminal report wins; later ones are dropped (buffered cap 1,
	// non-blocking sends per drop-instead-of-block discipline).
	reason := make(chan string, 1)
	report := func(r string) {
		select {
		case reason <- r:
		default:
		}
	}

	lastInbound := time.Now()
	var lastMu sync.Mutex

	var stallOnce sync.Once

	var wg sync.WaitGroup
	wg.Add(3)

	// --- uplink: TUN -> session ---
	go func() {
		defer wg.Done()
		for {
			pkt, err := cfg.TUN.ReadPacket(ctx)
			if err != nil {
				report("tun-closed")
				return
			}
			if werr := cfg.Session.WritePacket(pkt); werr != nil {
				if errors.Is(werr, ErrPacketTooBig) {
					// Synthetic ICMP TooBig back to the device (design §2):
					// never truncate, never forward oversized into the
					// tunnel; checksums fully computed so the message stays
					// valid through real forwarding.
					if tooBig := BuildICMPTooBig(pkt, ICMPTunnelMTU); tooBig != nil {
						_ = cfg.TUN.WritePacket(tooBig)
					}
					continue
				}
				report("session-lost")
				return
			}
		}
	}()

	// --- downlink: session -> TUN ---
	go func() {
		defer wg.Done()
		for {
			pkt, err := cfg.Session.ReadPacket(ctx)
			if err != nil {
				report("session-lost")
				return
			}
			lastMu.Lock()
			lastInbound = time.Now()
			lastMu.Unlock()
			if werr := cfg.TUN.WritePacket(pkt); werr != nil {
				report("tun-closed")
				return
			}
		}
	}()

	// --- downlink idle watchdog ---
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(cfg.StallCheckEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			lastMu.Lock()
			idle := time.Since(lastInbound)
			lastMu.Unlock()
			if idle >= cfg.DownlinkIdleTimeout {
				stallOnce.Do(func() {
					if cfg.OnStall != nil {
						// Off-loop: the callback may kick/reconnect via the
						// supervisor; it must never block this goroutine.
						go cfg.OnStall()
					}
				})
				report("stall")
				return
			}
		}
	}()

	first := ""
	select {
	case <-parent.Done():
	case r := <-reason:
		first = r
	}

	cancel()  // unblock both readers deterministically
	wg.Wait() // join everything — no leaked goroutines

	if parent.Err() != nil {
		return "stop"
	}
	return first
}

// BuildICMPTooBig synthesizes an IPv4 ICMP destination-unreachable /
// fragmentation-needed (type 3, code 4) message advertising mtu, embedding
// the original IP header plus the first 8 payload bytes (RFC 792). Returns
// nil for non-IPv4 or truncated input.
func BuildICMPTooBig(orig []byte, mtu int) []byte {
	if len(orig) < 20 || orig[0]>>4 != 4 {
		return nil
	}
	ihl := int(orig[0]&0x0f) * 4
	if ihl < 20 || len(orig) < ihl+8 {
		return nil
	}
	embedded := ihl + 8
	msg := make([]byte, 0, 8+embedded)
	msg = append(msg, 3, 4, 0, 0) // type, code, checksum placeholder, unused
	msg = append(msg, 0x00, 0x00) // unused
	msg = append(msg, byte(mtu>>8), byte(mtu))
	msg = append(msg, orig[:embedded]...)

	sum := ^fold(checksum32(msg))
	binary.BigEndian.PutUint16(msg[2:4], sum)

	// Outer IPv4 header semantics of an ICMP error: source = the entity
	// reporting (the original destination), destination = the original
	// sender (original source).
	total := 20 + len(msg)
	ip := make([]byte, total)
	ip[0] = 0x45
	ip[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	binary.BigEndian.PutUint16(ip[4:], 0) // id
	binary.BigEndian.PutUint16(ip[6:], 0) // flags/frag off
	ip[8] = 64                            // TTL
	ip[9] = 1                             // proto ICMP
	copy(ip[12:16], orig[16:20])          // src <- original dst
	copy(ip[16:20], orig[12:16])          // dst <- original src
	binary.BigEndian.PutUint16(ip[10:], ^fold(checksum32(ip[:20])))
	copy(ip[20:], msg)
	return ip
}
