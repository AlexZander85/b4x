package sni

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 client fingerprint (Часть 3 П.5), ported from Nova nova-tls ja4.rs
// (D:\FreeDPI\research\Nova\nova-rs\crates\nova-tls\src\ja4.rs). Pure bytes-in,
// fingerprint-out: answers "is TSPU cutting by ECH presence or by client
// signature" once fingerprints are logged next to the ech flag and flow fate.
//
// GREASE values are removed from every counted list so a deliberately
// randomising client keeps one stable identity.

// IsGREASE reports whether v is one of the sixteen 0x?a?a GREASE values
// (RFC 8701): hi == lo and low nibble == 0xa.
func IsGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && (hi&0x0f) == 0x0a
}

// JA4Hello carries the ClientHello parts JA4 is computed from.
type JA4Hello struct {
	Version    uint16   // highest offered: supported_versions, else legacy
	HasSNI     bool     // server_name extension present
	Ciphers    []uint16 // wire order, GREASE removed
	Extensions []uint16 // wire order, GREASE removed
	SigAlgs    []uint16 // wire order, GREASE removed
	ALPN       []string // protocol names, wire order
}

type ja4Reader struct {
	buf []byte
	at  int
}

func (r *ja4Reader) take(n int) ([]byte, error) {
	if len(r.buf)-r.at < n {
		return nil, fmt.Errorf("truncated at %d: want %d have %d", r.at, n, len(r.buf)-r.at)
	}
	out := r.buf[r.at : r.at+n]
	r.at += n
	return out, nil
}

func (r *ja4Reader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *ja4Reader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *ja4Reader) u24() (int, error) {
	b, err := r.take(3)
	if err != nil {
		return 0, err
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2]), nil
}

// ParseJA4ClientHello parses a full TLS record or a bare handshake message.
// Truncated input is an error, never a panic.
func ParseJA4ClientHello(input []byte) (*JA4Hello, error) {
	handshake := input
	if len(handshake) > 0 && handshake[0] == 0x16 {
		if len(handshake) < 5 {
			return nil, fmt.Errorf("record header truncated")
		}
		recLen := int(binary.BigEndian.Uint16(handshake[3:5]))
		if recLen > len(handshake)-5 {
			return nil, fmt.Errorf("record incomplete: body %d of %d", len(handshake)-5, recLen)
		}
		handshake = handshake[5:]
	}
	if len(handshake) == 0 {
		return nil, fmt.Errorf("empty handshake")
	}
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello (type %#04x)", handshake[0])
	}

	r := &ja4Reader{buf: handshake}
	if _, err := r.u8(); err != nil { // handshake type (already verified above)
		return nil, err
	}
	if _, err := r.u24(); err != nil { // handshake length
		return nil, err
	}
	body, err := r.u16() // legacy_version
	if err != nil {
		return nil, err
	}
	hello := &JA4Hello{Version: body}
	random, err := r.take(32)
	if err != nil {
		return nil, err
	}
	_ = random
	sidLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.take(int(sidLen)); err != nil {
		return nil, err
	}
	cipherLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(cipherLen); i += 2 {
		c, err := r.u16()
		if err != nil {
			return nil, err
		}
		if !IsGREASE(c) {
			hello.Ciphers = append(hello.Ciphers, c)
		}
	}
	compLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.take(int(compLen)); err != nil {
		return nil, err
	}
	extLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	extEnd := r.at + int(extLen)
	if extEnd > len(r.buf) {
		return nil, fmt.Errorf("extensions truncated")
	}
	for r.at+4 <= extEnd {
		etype, err := r.u16()
		if err != nil {
			return nil, err
		}
		elen, err := r.u16()
		if err != nil {
			return nil, err
		}
		data, err := r.take(int(elen))
		if err != nil {
			return nil, err
		}
		if IsGREASE(etype) {
			continue
		}
		hello.Extensions = append(hello.Extensions, etype)
		switch etype {
		case 0x0000: // server_name
			hello.HasSNI = true
		case 0x000d: // signature_algorithms
			hello.SigAlgs = parseU16List(data)
		case 0x0010: // ALPN
			hello.ALPN = parseALPN(data)
		case 0x002b: // supported_versions
			if best := highestNonGREASEVersion(data); best != 0 {
				hello.Version = best
			}
		}
	}
	return hello, nil
}

func parseU16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data))
	if listLen > len(data)-2 {
		listLen = len(data) - 2
	}
	out := make([]uint16, 0, listLen/2)
	for i := 2; i+2 <= 2+listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i:])
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data))
	if listLen > len(data)-2 {
		listLen = len(data) - 2
	}
	var out []string
	for i := 2; i < 2+listLen; {
		nameLen := int(data[i])
		i++
		if i+nameLen > 2+listLen {
			break
		}
		out = append(out, string(data[i:i+nameLen]))
		i += nameLen
	}
	return out
}

func highestNonGREASEVersion(data []byte) uint16 {
	// supported_versions uses a ONE-byte list length (RFC 8446 §4.2.1).
	if len(data) < 1 {
		return 0
	}
	listLen := int(data[0])
	if listLen > len(data)-1 {
		listLen = len(data) - 1
	}
	best := uint16(0)
	for i := 1; i+2 <= 1+listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i:])
		if !IsGREASE(v) && v > best {
			best = v
		}
	}
	return best
}

// JA4 returns the full "a_b_c" fingerprint string.
func (h *JA4Hello) JA4() string {
	return h.JA4A() + "_" + h.JA4B() + "_" + h.JA4C()
}

// JA4A is the readable half: version, SNI presence, counts, ALPN token.
func (h *JA4Hello) JA4A() string {
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		b := h.ALPN[0]
		alpn = string(b[0]) + string(b[len(b)-1])
	}
	ciphers := len(h.Ciphers)
	if ciphers > 99 {
		ciphers = 99
	}
	exts := len(h.Extensions)
	if exts > 99 {
		exts = 99
	}
	sni := "i"
	if h.HasSNI {
		sni = "d"
	}
	return fmt.Sprintf("t%s%s%02d%02d%s", ja4VersionLabel(h.Version), sni, ciphers, exts, alpn)
}

// JA4B hashes the SORTED cipher list: reorderable without changing identity.
func (h *JA4Hello) JA4B() string {
	c := append([]uint16(nil), h.Ciphers...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return ja4TruncatedHash(hexList(c))
}

// JA4C hashes sorted extensions (server_name and ALPN dropped — they vary per
// request) plus signature algorithms in WIRE order (order is implementation).
func (h *JA4Hello) JA4C() string {
	exts := make([]uint16, 0, len(h.Extensions))
	for _, t := range h.Extensions {
		if t == 0x0000 || t == 0x0010 {
			continue
		}
		exts = append(exts, t)
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	return ja4TruncatedHash(hexList(exts) + "_" + hexList(h.SigAlgs))
}

func hexList(vals []uint16) string {
	var b strings.Builder
	for _, v := range vals {
		b.WriteString(fmt.Sprintf("%04x", v))
	}
	return b.String()
}

func ja4TruncatedHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4VersionLabel(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}
