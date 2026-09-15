package torscan

// Deep relay probe (design §4.3/§1.6 — the ValdikSS TCPSocketConnectChecker
// canon): the probe proves BOTH "a live Tor node" AND "the DPI lets the
// TLS application stage through", in four steps:
//
//	1. TLS handshake with a RANDOM SNI www.<4-25 base32>.org (CERT_NONE —
//	   imitating the Tor client fingerprint);
//	2. VERSIONS cell  00 00 07 00 | 06 00 03 00 04 00 05  — the answer
//	   MUST start with 00 00 07;
//	3. NETINFO (00 00 00 01 08 … + zeros) followed by N dummy CREATE
//	   cells (00 00 00 05 | 01 + 509 zero bytes);
//	4. the answer MUST be a CREATED cell: 00 00 00 05 | 04.
//
// A TCP connect alone proves nothing (a censor's RST-on-Tor-SNI would
// still pass); this probe walks the protocol until only a real,
// DPI-transparent Tor ORPort can answer.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Cell wire constants (research-tor-tooling §1).
var (
	versionsCell = []byte{
		0x00, 0x00, 0x07, 0x00, // circid=0, cmd=7 (VERSIONS)
		0x06, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, // link versions 3..6
	}
	netinfoCell = []byte{
		0x00, 0x00, 0x00, 0x01, // circid=0, cmd=1 (NETINFO)
		0x08,       // cell body: timestamp len + addr len minimal form
		0, 0, 0, 0, // timestamp placeholder
	}
	createCellHeader = []byte{
		0x00, 0x00, 0x00, 0x05, // circid=5, cmd=5 (CREATE)
		0x01, // CREATE (short form)
	}
	// createCellPadLen: the full CREATE cell is 514 bytes (5 header + 1 cmd + 509 pad? —
	// the canonical scanner form: 509 zero bytes after the command byte,
	// filling the fixed cell size).
	createCellPadLen = 509

	answerVersionsPrefix = []byte{0x00, 0x00, 0x07}
	answerCreatedHeader  = []byte{0x00, 0x00, 0x00, 0x05, 0x04}
)

// ProbeTimeout bounds one deep probe.
const ProbeTimeout = 6 * time.Second

// Dialer opens the raw TCP stream (production: through the egress dialer;
// tests: local stands).
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// RandomSNI renders www.<4-25 base32 chars>.org (the Tor-client imitation).
func RandomSNI() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	n := 4 + int(randomByte()%22) // 4..25
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = alphabet[randomByte()%32]
	}
	return "www." + string(buf) + ".org"
}

func randomByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// DeepProbe runs the full four-step probe against addr. createCount is
// the number of dummy CREATE cells (default 8 per the scanner).
func DeepProbe(ctx context.Context, dial Dialer, addr string, createCount int) error {
	if createCount <= 0 {
		createCount = 8
	}
	cctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	raw, err := dial(cctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp: %w", err)
	}
	defer raw.Close()

	// step 1: TLS with a random SNI, no verification (liveness, not WebPKI)
	tc := tls.Client(raw, &tls.Config{
		ServerName:         RandomSNI(),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(cctx); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	_ = tc.SetDeadline(time.Now().Add(ProbeTimeout))

	// step 2: VERSIONS → answer must start 00 00 07
	if _, err := tc.Write(versionsCell); err != nil {
		return fmt.Errorf("write versions: %w", err)
	}
	// VERSIONS answer: [00 00 07] [len:2] [body:len]
	vhead := make([]byte, 5)
	if _, err := ioReadFull(tc, vhead); err != nil {
		return fmt.Errorf("read versions answer: %w", err)
	}
	if string(vhead[:3]) != string(answerVersionsPrefix) {
		return fmt.Errorf("versions answer %#x, want prefix 000007", vhead[:3])
	}
	bodyLen := int(binary.BigEndian.Uint16(vhead[3:5]))
	if bodyLen > 0 {
		if err := drainCellBody(tc, uint16(bodyLen)); err != nil {
			return fmt.Errorf("versions body: %w", err)
		}
	}

	// step 3: NETINFO + N dummy CREATEs
	if _, err := tc.Write(netinfoCell); err != nil {
		return fmt.Errorf("write netinfo: %w", err)
	}
	create := append(append([]byte{}, createCellHeader...), make([]byte, createCellPadLen)...)
	for i := 0; i < createCount; i++ {
		if _, err := tc.Write(create); err != nil {
			return fmt.Errorf("write create %d: %w", i, err)
		}
	}

	// step 4: the answer must be a CREATED cell (circid=5, cmd=4)
	reply := make([]byte, len(answerCreatedHeader))
	if _, err := ioReadFull(tc, reply); err != nil {
		return fmt.Errorf("read created answer: %w", err)
	}
	if string(reply) != string(answerCreatedHeader) {
		return fmt.Errorf("answer %#x, want CREATED 0000000504", reply)
	}
	return nil
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// drainCellBody skips len bytes of a cell body.
func drainCellBody(c net.Conn, bodyLen uint16) error {
	buf := make([]byte, 512)
	for remaining := int(bodyLen); remaining > 0; {
		n := remaining
		if n > len(buf) {
			n = len(buf)
		}
		read, err := ioReadFull(c, buf[:n])
		remaining -= read
		if err != nil {
			if read >= n {
				return nil // short body: tolerated, the probe continues
			}
			return err
		}
	}
	return nil
}

// PlainDial is the standard-library dialer (test stands and direct
// egress when no policy applies).
func PlainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
