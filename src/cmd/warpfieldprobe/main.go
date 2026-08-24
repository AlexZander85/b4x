// Command warpfieldprobe is the field-session probe for E-H3/E-WG data
// collection (FIELD1_AGENT_PROMPT.md phases E/F). Stdlib-only, no new module
// dependencies.
//
// Modes:
//
//	warpfieldprobe quic -host 162.159.198.1 -ports 443,500,1701,4500
//	warpfieldprobe junk -host 162.159.193.10 -ports 2408,500 -len 92 -count 3
//
// quic mode sends a version-negotiation-triggering long header (RFC 9000
// SS6.2: version 0x?a?a?a?a forces a Version Negotiation reply from any
// conforming listener without requiring TLS or crypto). A VN reply proves a
// live QUIC listener and yields an honest RTT; silence/ICMP are recorded as
// their own outcomes. Limitation recorded honestly: this is NOT a full QUIC
// handshake (that would need a QUIC stack the repo deliberately does not
// ship); it classifies reachability exactly as the E-H3 stage needs.
//
// Output: one JSON object per line (grep-friendly, no secrets).
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Outcome classes (structural, report-ready).
const (
	OutcomeVNSent    = "vn-reply"    // Version Negotiation received: QUIC listener alive
	OutcomeOtherData = "other-reply" // non-VN datagram back (recorded, hex head kept)
	OutcomeTimeout   = "timeout"     // silence within deadline
	OutcomeICMP      = "icmp-error"  // ICMP unreachable surfaced by the socket
	OutcomeSendError = "send-error"
)

type result struct {
	TS        string `json:"ts"`
	Mode      string `json:"mode"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Round     int    `json:"round"`
	Outcome   string `json:"outcome"`
	RTTMS     int64  `json:"rtt_ms,omitempty"`
	ReplyLen  int    `json:"reply_len,omitempty"`
	ReplyHead string `json:"reply_head_hex,omitempty"` // first 16 bytes, diagnostics only
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "quic":
		runQuic(os.Args[2:])
	case "junk":
		runJunk(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: warpfieldprobe quic|junk -host IP -ports 443,500 [-timeout 2s] [-rounds 3] [-len 92]")
}

func commonFlags(fs *flag.FlagSet) (host *string, ports *string, timeout *time.Duration, rounds *int) {
	host = fs.String("host", "", "destination IPv4 address (required)")
	ports = fs.String("ports", "443", "comma-separated destination ports")
	timeout = fs.Duration("timeout", 2*time.Second, "per-round read deadline")
	rounds = fs.Int("rounds", 3, "probes per port")
	return host, ports, timeout, rounds
}

func runQuic(args []string) {
	fs := flag.NewFlagSet("quic", flag.ExitOnError)
	host, portsStr, timeout, rounds := commonFlags(fs)
	fs.Parse(args)

	for _, port := range parsePorts(*portsStr) {
		for r := 1; r <= *rounds; r++ {
			emit(probeOnce("quic", *host, port, *timeout, r, craftVNTrigger))
		}
	}
}

func runJunk(args []string) {
	fs := flag.NewFlagSet("junk", flag.ExitOnError)
	host, portsStr, timeout, rounds := commonFlags(fs)
	length := fs.Int("len", 92, "junk datagram size")
	fs.Parse(args)

	for _, port := range parsePorts(*portsStr) {
		for r := 1; r <= *rounds; r++ {
			n := *length
			emit(probeOnce("junk", *host, port, *timeout, r, func() []byte { return craftJunk(n) }))
		}
	}
}

func parsePorts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// payloadBuilder returns one fresh datagram per round.
type payloadBuilder func() []byte

func probeOnce(mode, host string, port int, timeout time.Duration, round int, build payloadBuilder) result {
	res := result{TS: time.Now().UTC().Format(time.RFC3339Nano), Mode: mode, Host: host, Port: port, Round: round}

	raddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		res.Outcome = OutcomeSendError
		return res
	}
	defer conn.Close()

	payload := build()
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		res.Outcome = OutcomeSendError
		return res
	}

	buf := make([]byte, 65536)
	conn.SetReadDeadline(start.Add(timeout))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if oe, ok := err.(*net.OpError); ok && oe.Err != nil && strings.Contains(strings.ToLower(oe.Err.Error()), "refused") {
				res.Outcome = OutcomeICMP
				return res
			}
			res.Outcome = OutcomeTimeout
			return res
		}
		rtt := time.Since(start)
		if isVNReply(buf[:n]) {
			res.Outcome = OutcomeVNSent
		} else {
			res.Outcome = OutcomeOtherData
		}
		res.RTTMS = rtt.Milliseconds()
		res.ReplyLen = n
		res.ReplyHead = hex.EncodeToString(buf[:min(n, 16)])
		return res
	}
}

func emit(r result) {
	fmt.Printf("{\"ts\":%q,\"mode\":%q,\"host\":%q,\"port\":%d,\"round\":%d,\"outcome\":%q,\"rtt_ms\":%d,\"reply_len\":%d,\"reply_head_hex\":%q}\n",
		r.TS, r.Mode, r.Host, r.Port, r.Round, r.Outcome, r.RTTMS, r.ReplyLen, r.ReplyHead)
}

// craftVNTrigger builds a QUIC long header with a forced-version-negotiation
// value (RFC 9000 SS6.2 "version negotiation was requested": version
// 0x?a?a?a?a MUST elicit a Version Negotiation packet) padded to the 1200-byte
// minimum — RFC 9000 SS14.1 makes servers DISCARD sub-1200 long-header
// datagrams before any VN logic, so unpadded triggers die silently (field-
// proven on session #1: every port looked dead until this fix).
func craftVNTrigger() []byte {
	pkt := make([]byte, 0, 1200)
	first := byte(0xc0) // long header form, fixed bit set; type bits irrelevant for VN
	version := uint32(0x1a2a3a4a)
	dcid := randBytes(8)
	scid := randBytes(8)

	pkt = append(pkt, first)
	pkt = binary.BigEndian.AppendUint32(pkt, version)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	// Zero bytes are PADDING frames; extend to the required datagram size.
	pkt = pkt[:cap(pkt)]
	return pkt
}

func craftJunk(n int) []byte {
	if n < 16 {
		n = 16
	}
	return randBytes(n)
}

func isVNReply(b []byte) bool {
	// Version Negotiation: long header (bit 7 set), Version field == 0.
	if len(b) >= 5 && b[0]&0x80 != 0 && binary.BigEndian.Uint32(b[1:5]) == 0 {
		return true
	}
	return false
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i)
		}
	}
	return b
}
