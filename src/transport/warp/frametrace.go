// Frame-level trace for the MASQUE capsule plane (bd b4x-46z phase Б):
// byte-level evidence of what leaves and enters the CONNECT stream around
// the first-client-data-segment stall. Off by default; enabled with
// B4_WARP_FRAMETRACE=<path> ("-" = stderr). When disabled the cost is one
// atomic load per event.
//
// Evidence rules (§what-counts-as-proof):
//   - tx: one line per capsule handed to the H2 request body, including the
//     wall time spent inside the pipe write (a long write = H2 backpressure,
//     a fast write with no rx = the edge ate the capsule);
//   - rx: one line per DATAGRAM capsule parsed off the response body;
//   - drop: one line whenever an inbound packet is dropped instead of
//     delivered (primary queue or tap fan-out) — the reference client NEVER
//     drops inbound, so any drop line near a stall is a prime suspect;
//   - payloads are summarized (lengths, IP/TCP metadata, hex head) — never
//     logged in full, no key material ever reaches this sink.
package transportwarp

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EnvFrameTrace enables the capsule-plane frame trace.
const EnvFrameTrace = "B4_WARP_FRAMETRACE"

var (
	traceWriter atomic.Pointer[io.Writer]
	traceMu     sync.Mutex
)

func init() { initFrameTrace() }

// initFrameTrace installs the trace sink from B4_WARP_FRAMETRACE. Separated
// from init so tests can re-arm it after t.Setenv.
func initFrameTrace() {
	path := os.Getenv(EnvFrameTrace)
	if path == "" {
		traceWriter.Store(nil) // explicit re-arm: env cleared ⇒ sink removed
		return
	}
	var w io.Writer = os.Stderr
	if path != "-" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "frametrace: open %s: %v (falling back to stderr)\n", path, err)
		} else {
			w = f
		}
	}
	traceWriter.Store(&w)
}

func traceEnabled() bool { return traceWriter.Load() != nil }

type traceLine struct {
	T       string `json:"t"`             // RFC3339Nano UTC
	Dir     string `json:"dir"`           // tx | rx | drop | ev
	Session string `json:"sess"`          // EndpointHash of the owning session
	Len     int    `json:"len"`           // payload (IP packet) length
	WriteMS int64  `json:"wr_ms"`         // tx only: time spent inside pw.Write
	CapType uint64 `json:"cap,omitempty"` // rx only: capsule type (0 = DATAGRAM)
	Proto   uint8  `json:"proto,omitempty"`
	Src     string `json:"src,omitempty"`
	Dst     string `json:"dst,omitempty"`
	SPort   uint16 `json:"sport,omitempty"`
	DPort   uint16 `json:"dport,omitempty"`
	TCPSeq  uint32 `json:"tcp_seq,omitempty"`
	TCPFlag string `json:"tcp_flag,omitempty"` // SYN|ACK|FIN|RST|PSH summary
	Err     string `json:"err,omitempty"`
	Head    string `json:"head_hex,omitempty"` // first headBytes of the payload
	Note    string `json:"note,omitempty"`
}

const headBytes = 24

func emitTrace(l traceLine) {
	w := traceWriter.Load()
	if w == nil {
		return
	}
	l.T = time.Now().UTC().Format(time.RFC3339Nano)
	buf, err := json.Marshal(l)
	if err != nil {
		return
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	_, _ = (*w).Write(append(buf, '\n'))
}

// pktMeta extracts redacted-safe routing metadata from a raw IPv4 packet.
// ok=false for anything that is not a parsable IPv4 packet (head hex still
// carries evidence for those).
func pktMeta(pkt []byte) (m traceLine, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return m, false
	}
	m.Proto = pkt[9]
	m.Src = netip.AddrFrom4([4]byte(pkt[12:16])).String()
	m.Dst = netip.AddrFrom4([4]byte(pkt[16:20])).String()
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return m, true
	}
	switch m.Proto {
	case 6, 17: // TCP / UDP
		if len(pkt) < ihl+4 {
			return m, true
		}
		m.SPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		m.DPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		if m.Proto == 6 && len(pkt) >= ihl+14 {
			seq := binary.BigEndian.Uint32(pkt[ihl+4 : ihl+8])
			m.TCPSeq = seq
			f := pkt[ihl+13]
			m.TCPFlag = tcpFlagNames(f)
		}
	}
	return m, true
}

func tcpFlagNames(f byte) string {
	names := []struct {
		bit byte
		ch  string
	}{{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x10, "ACK"}}
	out := ""
	for _, n := range names {
		if f&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.ch
		}
	}
	if out == "" {
		return fmt.Sprintf("0x%02x", f)
	}
	return out
}

// traceTx records one outbound capsule. wrMS is the duration of the request
// body write (backpressure evidence).
func (s *Session) traceTx(pkt []byte, wrMS int64, err error) {
	if !traceEnabled() {
		return
	}
	l := traceLine{Dir: "tx", Session: EndpointHash(s.cfg.Endpoint), Len: len(pkt), WriteMS: wrMS}
	if err != nil {
		l.Err = err.Error()
	}
	if m, ok := pktMeta(pkt); ok {
		l.Proto, l.Src, l.Dst, l.SPort, l.DPort, l.TCPSeq, l.TCPFlag =
			m.Proto, m.Src, m.Dst, m.SPort, m.DPort, m.TCPSeq, m.TCPFlag
	}
	if len(pkt) > 0 && l.Proto == 0 {
		l.Head = hex.EncodeToString(pkt[:min(headBytes, len(pkt))])
	}
	emitTrace(l)
}

// traceRx records one parsed inbound DATAGRAM capsule.
func (s *Session) traceRx(capType uint64, pkt []byte) {
	if !traceEnabled() {
		return
	}
	l := traceLine{Dir: "rx", Session: EndpointHash(s.cfg.Endpoint), Len: len(pkt), CapType: capType}
	if capType != 0 {
		l.Note = "foreign-capsule-skipped"
	}
	if m, ok := pktMeta(pkt); ok {
		l.Proto, l.Src, l.Dst, l.SPort, l.DPort, l.TCPSeq, l.TCPFlag =
			m.Proto, m.Src, m.Dst, m.SPort, m.DPort, m.TCPSeq, m.TCPFlag
	} else if len(pkt) > 0 {
		l.Head = hex.EncodeToString(pkt[:min(headBytes, len(pkt))])
	}
	emitTrace(l)
}

// traceDropPrimary records an inbound packet dropped because the primary
// consumer queue was full/unattended.
func (s *Session) traceDropPrimary(pkt []byte) {
	if !traceEnabled() {
		return
	}
	l := traceLine{Dir: "drop", Session: EndpointHash(s.cfg.Endpoint), Len: len(pkt), Note: "primary-queue-full"}
	if m, ok := pktMeta(pkt); ok {
		l.Proto, l.Src, l.Dst, l.SPort, l.DPort, l.TCPSeq, l.TCPFlag =
			m.Proto, m.Src, m.Dst, m.SPort, m.DPort, m.TCPSeq, m.TCPFlag
	}
	emitTrace(l)
}

// traceDropTap records an inbound packet dropped at the session tap fan-out.
func (s *Session) traceDropTap(pkt []byte) {
	if !traceEnabled() {
		return
	}
	l := traceLine{Dir: "drop", Session: EndpointHash(s.cfg.Endpoint), Len: len(pkt), Note: "tap-full"}
	if m, ok := pktMeta(pkt); ok {
		l.Proto, l.Src, l.Dst, l.SPort, l.DPort, l.TCPSeq, l.TCPFlag =
			m.Proto, m.Src, m.Dst, m.SPort, m.DPort, m.TCPSeq, m.TCPFlag
	}
	emitTrace(l)
}

// traceEv records a lifecycle/protocol event on the capsule plane.
func (s *Session) traceEv(note string) {
	if !traceEnabled() {
		return
	}
	emitTrace(traceLine{Dir: "ev", Session: EndpointHash(s.cfg.Endpoint), Note: note})
}
