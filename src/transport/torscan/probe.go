package torscan

// Modern relay probe (Tor link protocols 4/5). The old implementation was
// copied from a legacy scanner and treated command 0x04 as CREATED; in the
// Tor protocol 0x04 is DESTROY, CREATED is deprecated command 2, and modern
// relays use CREATE2/CREATED2 for circuits. A relay liveness/DPI probe does
// not need to build a circuit at all: completing the authenticated channel
// handshake through the responder's CERTS/AUTH_CHALLENGE/NETINFO sequence is
// already a Tor-specific application-stage proof.
//
// Stages, on one bounded connection:
//   1. TLS handshake with a random SNI (CERT_NONE: endpoint liveness, not
//      WebPKI identity);
//   2. VERSIONS negotiation for link v4/v5;
//   3. parse bounded Tor variable/fixed cells until CERTS,
//      AUTH_CHALLENGE and NETINFO have all arrived;
//   4. send our well-formed NETINFO to finish the client side.
//
// No CREATE/CREATE_FAST cells are sent. That avoids obsolete handshakes and
// reduces the scanner's active footprint while still proving that a live Tor
// OR endpoint survived TLS and application framing through the DPI path.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ProbeTimeout        = 6 * time.Second
	maxHandshakeCells   = 12
	maxVariableCellBody = 64 << 10
	cellBodyLen         = 509

	cmdVersions      = 7
	cmdNetinfo       = 8
	cmdVPadding      = 128
	cmdCerts         = 129
	cmdAuthChallenge = 130
)

var versionsCell = []byte{
	0x00, 0x00, cmdVersions, 0x00, 0x04,
	0x00, 0x04, 0x00, 0x05,
}

type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

func RandomSNI() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	n := 4 + int(randomByte()%22)
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

// DeepProbe keeps the historical createCount parameter for source/API
// compatibility; modern probing deliberately ignores it because no circuit
// creation is needed for a liveness/DPI verdict.
func DeepProbe(ctx context.Context, dial Dialer, addr string, _ int) error {
	cctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	raw, err := dial(cctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp: %w", err)
	}
	defer raw.Close()

	tc := tls.Client(raw, &tls.Config{
		ServerName:         RandomSNI(),
		InsecureSkipVerify: true, // probe identity comes from Tor cells
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(cctx); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	_ = tc.SetDeadline(time.Now().Add(ProbeTimeout))

	if _, err := tc.Write(versionsCell); err != nil {
		return fmt.Errorf("write versions: %w", err)
	}
	peerVersions, err := readVersions(tc)
	if err != nil {
		return fmt.Errorf("versions: %w", err)
	}
	linkVersion := negotiateVersion(peerVersions, []uint16{4, 5})
	if linkVersion == 0 {
		return fmt.Errorf("versions: no common modern link protocol (peer=%v)", peerVersions)
	}

	var sawCerts, sawChallenge, sawNetinfo bool
	for i := 0; i < maxHandshakeCells && !sawNetinfo; i++ {
		cmd, body, err := readCell(tc, linkVersion)
		if err != nil {
			return fmt.Errorf("channel cell %d: %w", i, err)
		}
		switch cmd {
		case cmdVPadding:
			continue
		case cmdCerts:
			if err := validateCertsCell(body); err != nil {
				return fmt.Errorf("CERTS: %w", err)
			}
			sawCerts = true
		case cmdAuthChallenge:
			if len(body) < 34 { // 32-byte challenge + uint16 method count
				return fmt.Errorf("AUTH_CHALLENGE too short: %d", len(body))
			}
			n := int(binary.BigEndian.Uint16(body[32:34]))
			if 34+2*n > len(body) {
				return fmt.Errorf("AUTH_CHALLENGE methods overflow: n=%d len=%d", n, len(body))
			}
			sawChallenge = true
		case cmdNetinfo:
			if err := validateNetinfo(body); err != nil {
				return fmt.Errorf("NETINFO: %w", err)
			}
			sawNetinfo = true
		default:
			return fmt.Errorf("unexpected handshake command %d", cmd)
		}
	}
	if !sawCerts || !sawChallenge || !sawNetinfo {
		return fmt.Errorf("incomplete Tor channel handshake: certs=%t challenge=%t netinfo=%t", sawCerts, sawChallenge, sawNetinfo)
	}

	if _, err := tc.Write(buildNetinfo(linkVersion, raw.RemoteAddr())); err != nil {
		return fmt.Errorf("write NETINFO: %w", err)
	}
	return nil
}

func readVersions(r io.Reader) ([]uint16, error) {
	header := make([]byte, 5) // VERSIONS is always link v=0: 2-byte CircID
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 0 || header[1] != 0 || header[2] != cmdVersions {
		return nil, fmt.Errorf("bad VERSIONS header %#x", header)
	}
	n := int(binary.BigEndian.Uint16(header[3:5]))
	if n == 0 || n%2 != 0 || n > 256 {
		return nil, fmt.Errorf("bad VERSIONS length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:i+2]))
	}
	return out, nil
}

func negotiateVersion(peer, ours []uint16) uint16 {
	set := make(map[uint16]bool, len(ours))
	for _, v := range ours {
		set[v] = true
	}
	var best uint16
	for _, v := range peer {
		if set[v] && v > best {
			best = v
		}
	}
	return best
}

func readCell(r io.Reader, linkVersion uint16) (byte, []byte, error) {
	circLen := 2
	if linkVersion >= 4 {
		circLen = 4
	}
	header := make([]byte, circLen+1)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	for _, b := range header[:circLen] {
		if b != 0 {
			return 0, nil, errors.New("handshake cell has non-zero CircID")
		}
	}
	cmd := header[circLen]
	if cmd == cmdVersions || cmd >= 128 {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(lenBuf))
		if n > maxVariableCellBody {
			return 0, nil, fmt.Errorf("variable cell %d too large: %d", cmd, n)
		}
		body := make([]byte, n)
		_, err := io.ReadFull(r, body)
		return cmd, body, err
	}
	body := make([]byte, cellBodyLen)
	_, err := io.ReadFull(r, body)
	return cmd, body, err
}

func validateCertsCell(body []byte) error {
	if len(body) < 1 {
		return errors.New("empty body")
	}
	n := int(body[0])
	if n == 0 {
		return errors.New("no certificates")
	}
	off := 1
	seen := map[byte]bool{}
	for i := 0; i < n; i++ {
		if off+3 > len(body) {
			return errors.New("truncated certificate header")
		}
		typ := body[off]
		ln := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if ln <= 0 || off+ln > len(body) {
			return fmt.Errorf("certificate %d length %d invalid", i, ln)
		}
		if seen[typ] {
			return fmt.Errorf("duplicate certificate type %d", typ)
		}
		seen[typ] = true
		off += ln
	}
	return nil
}

func validateNetinfo(body []byte) error {
	if len(body) < 7 { // time + ATYPE + ALEN + NMYADDR at minimum
		return fmt.Errorf("body too short: %d", len(body))
	}
	off := 4
	_, next, err := consumeAddress(body, off)
	if err != nil {
		return err
	}
	off = next
	if off >= len(body) {
		return errors.New("missing NMYADDR")
	}
	n := int(body[off])
	off++
	for i := 0; i < n; i++ {
		_, next, err = consumeAddress(body, off)
		if err != nil {
			return err
		}
		off = next
	}
	return nil
}

func consumeAddress(body []byte, off int) ([]byte, int, error) {
	if off+2 > len(body) {
		return nil, off, errors.New("truncated address header")
	}
	typ, ln := body[off], int(body[off+1])
	off += 2
	if off+ln > len(body) {
		return nil, off, errors.New("truncated address value")
	}
	if (typ == 4 && ln != 4) || (typ == 6 && ln != 16) {
		return nil, off, fmt.Errorf("address type=%d has invalid length=%d", typ, ln)
	}
	return body[off : off+ln], off + ln, nil
}

func buildNetinfo(linkVersion uint16, remote net.Addr) []byte {
	circLen := 2
	if linkVersion >= 4 {
		circLen = 4
	}
	cell := make([]byte, circLen+1+cellBodyLen)
	cell[circLen] = cmdNetinfo
	body := cell[circLen+1:]
	binary.BigEndian.PutUint32(body[:4], uint32(time.Now().Unix()))
	off := 4
	ip := net.IPv4zero
	if ta, ok := remote.(*net.TCPAddr); ok && ta.IP != nil {
		ip = ta.IP
	}
	if v4 := ip.To4(); v4 != nil {
		body[off] = 4
		body[off+1] = 4
		copy(body[off+2:off+6], v4)
		off += 6
	} else if v6 := ip.To16(); v6 != nil {
		body[off] = 6
		body[off+1] = 16
		copy(body[off+2:off+18], v6)
		off += 18
	}
	body[off] = 0 // NMYADDR: clients need not advertise a relay address
	return cell
}

func PlainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
