// Minimal QPACK (RFC 9204) codec for the fxvpn H3 CONNECT transport — a
// hand-written HTTP/3 layer over raw quic-go streams, copied from the
// proven E-H1/E-H2 warp implementation (owner decision FX2 option (a): no
// x/net/http3, same wire formats).
//
// Scope (deliberate):
//   - static table ONLY on the wire; the dynamic table is never used and
//     dynamic references decode to a typed error. This is protocol-legal:
//     we never advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY (default 0), so a
//     conformant peer MUST NOT insert or reference dynamic entries.
//   - the encoder emits literals without Huffman (allowed; deterministic);
//     the decoder accepts Huffman via golang.org/x/net/http2/hpack (the
//     RFC 7541 Appendix B table applies unchanged per RFC 9204 §4.1.2).
//
// Wire formats verified against RFC 9204: field section prefix §4.5.1
// (Required Insert Count, 8-bit prefix; Base sign+delta, 7-bit prefix),
// indexed field line §4.5.2 ("1 T" + Index(6+)), literal with name reference
// §4.5.4 ("01 N T" + NameIdx(4+) + value string), literal with literal name
// §4.5.6 ("001 N" + name string 4-bit prefix + value string).
package fxvpn

import (
	"errors"
	"fmt"

	hpack "golang.org/x/net/http2/hpack"
)

// ErrQPACKDynamic is returned when a peer references the dynamic table or
// post-base indices. We advertise zero table capacity, so a conformant peer
// never does this; seeing it means the endpoint dialect diverged from the
// minimal-H3 contract and the session must fail closed.
var ErrQPACKDynamic = errors.New("fxvpn: qpack dynamic/post-base reference in field section")

const qpackMaxStringLength = 4096 // inbound name/value cap; HEADERS frame itself is capped by h3frame.go

// qpackEntry is one RFC 9204 Appendix A row.
type qpackEntry struct{ name, value string }

// qpackStaticTable is RFC 9204 Appendix A verbatim (indices 0..73).
var qpackStaticTable = [74]qpackEntry{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
}

// Static table indexes exercised by the encoder. Verified: Appendix A;
// :method CONNECT = 15 reproduces warp-socks' single indexed byte 0xCF
// (1 T index6 -> 1100_1111), :authority literal = the 0x50 pattern
// (01 N=0 T=1 idx4=0000).
const (
	qpackIdxAuthority    = 0
	qpackIdxMethodConnct = 15
	qpackIdxStatus200    = 25
)

// ---- prefixed integers (RFC 9204 §4.1.1, format of RFC 7541 §5.1) ----

// appendQPACKInt appends a prefixed integer whose first byte shares
// highBitsValue's pattern bits (already shifted into place by the caller);
// prefixBits counts how many low bits of that first byte belong to the value.
func appendQPACKInt(dst []byte, firstByte byte, prefixBits int, v uint64) []byte {
	max := uint64(1)<<uint(prefixBits) - 1
	if v < max {
		return append(dst, firstByte|byte(v))
	}
	dst = append(dst, firstByte|byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(0x80|(v&0x7f)))
		v >>= 7
	}
	return append(dst, byte(v))
}

// ---- string literals (RFC 9204 §4.1.2: H flag + N-bit-prefix length) ----

// appendQPACKStringImpl writes a plain (non-Huffman) string whose length
// field starts at the bit slot carved out by firstByte/prefixBits. For
// prefixBits == 8 the H flag is the top bit of a fresh byte (always 0 here);
// for narrower prefixes the caller owns every bit above the H flag slot
// (deterministic literals by design, see package doc).
func appendQPACKStringImpl(dst []byte, firstByte byte, prefixBits int, s string) []byte {
	dst = appendQPACKInt(dst, firstByte, prefixBits, uint64(len(s)))
	return append(dst, s...)
}

// ---- encoder ----

type qpackWriter struct{ b []byte }

// EncodeConnectFieldSection builds the QPACK field section of the fxvpn
// plain-CONNECT request (reference main.go:2727-2735 semantics: :method
// CONNECT, :authority = target authority, Proxy-Authorization Bearer):
// :method CONNECT (indexed static), :authority (literal, static name
// reference), then each extra header as a never-indexed literal-with-literal-
// name line (§4.5.6, N=1). No :scheme/:path are ever emitted (RFC 9114 §4.4:
// CONNECT omits them).
func EncodeConnectFieldSection(authority string, extra [][2]string) []byte {
	w := &qpackWriter{}
	w.b = appendQPACKInt(w.b, 0x00, 8, 0) // Required Insert Count = 0 (§4.5.1.1)
	w.b = appendQPACKInt(w.b, 0x00, 7, 0) // Base: sign 0, delta 0
	// Indexed field line, static: :method CONNECT -> single byte 0xCF.
	w.b = append(w.b, 0xC0|qpackIdxMethodConnct)
	// Literal field line with name reference: N=0, T=1(static), idx=:authority.
	w.b = appendQPACKInt(w.b, 0x50, 4, 0) // name index in the first byte
	w.b = appendQPACKStringImpl(w.b, 0x00, 8, authority)
	for _, kv := range extra {
		w.encodeLiteralNameLine(kv[0], kv[1])
	}
	return w.b
}

// encodeLiteralNameLine emits one §4.5.6 line: 001 N H NameLen(3+) ...
// Never-indexed (N=1 → first-byte pattern 0011); plain (non-Huffman) strings.
func (w *qpackWriter) encodeLiteralNameLine(name, value string) {
	const firstBytePattern = byte(0x30) // 0 0 1 N=1 ; H and 3-bit length live below
	nameBytes := len(name)
	if nameBytes < 7 {
		// Length fits the 3-bit prefix: 0 0 1 1 H LLL.
		w.b = append(w.b, firstBytePattern|byte(nameBytes))
	} else {
		w.b = appendQPACKInt(w.b, firstBytePattern|0x07, 3, uint64(nameBytes))
	}
	w.b = append(w.b, name...)
	w.b = appendQPACKStringImpl(w.b, 0x00, 8, value) // fresh byte: H + 7-bit-prefixed length
}

// ---- decoder ----

// DecodeFieldSection parses an encoded field section into ordered name/value
// pairs. Dynamic-table and post-base references fail with ErrQPACKDynamic;
// oversized or truncated sections fail with structural errors.
func DecodeFieldSection(b []byte) ([][2]string, error) {
	c := &qpackReader{buf: b}
	ric, err := c.readInt(8)
	if err != nil {
		return nil, err
	}
	if ric != 0 {
		return nil, fmt.Errorf("%w: required insert count %d", ErrQPACKDynamic, ric)
	}
	// Base (§4.5.1.2): sign bit, then Delta Base as a 7-bit-prefixed integer.
	sign, err := c.readBits(1)
	if err != nil {
		return nil, err
	}
	if _, err := c.readInt(7); err != nil {
		return nil, err
	}
	if sign != 0 {
		// Sign=1 implies Base < Required Insert Count; without any dynamic
		// entries a conformant encoder never produces this.
		return nil, errors.New("fxvpn: qpack negative base in field section")
	}

	var out [][2]string
	for c.pos < len(c.buf)*8 {
		b0 := c.buf[c.pos/8] // representations always start byte-aligned
		switch {
		case b0&0x80 != 0: // §4.5.2 indexed field line: 1 T Index(6)
			t := (b0 >> 6) & 1
			idx := uint64(b0 & 0x3F)
			c.pos += 8 // the whole first byte belongs to this representation
			if idx == 0x3F {
				var err error
				idx, err = c.finishInt(idx)
				if err != nil {
					return nil, err
				}
			}
			if t == 0 {
				return nil, fmt.Errorf("%w: indexed dynamic %d", ErrQPACKDynamic, idx)
			}
			e, err := staticLookup(idx)
			if err != nil {
				return nil, err
			}
			out = append(out, [2]string{e.name, e.value})
		case b0&0xC0 == 0x40: // §4.5.4 literal with name reference: 01 N T Index(4)
			t := (b0 >> 4) & 1
			idx := uint64(b0 & 0x0F)
			c.pos += 8
			if idx == 0x0F {
				var err error
				idx, err = c.finishInt(idx)
				if err != nil {
					return nil, err
				}
			}
			if t == 0 {
				return nil, fmt.Errorf("%w: literal dynamic name %d", ErrQPACKDynamic, idx)
			}
			e, err := staticLookup(idx)
			if err != nil {
				return nil, err
			}
			val, err := c.readString(8)
			if err != nil {
				return nil, err
			}
			out = append(out, [2]string{e.name, val})
		case b0&0xE0 == 0x20: // §4.5.6 literal with literal name (mid-byte string)
			// First byte = 0 0 1 N | H | NameLen(3): consume the 4 pattern
			// bits; readString(4) then takes H + 3-bit-prefixed length.
			if _, err := c.readBits(4); err != nil {
				return nil, err
			}
			name, err := c.readString(4) // 4-bit-prefix string (H + 3-bit length)
			if err != nil {
				return nil, err
			}
			val, err := c.readString(8)
			if err != nil {
				return nil, err
			}
			out = append(out, [2]string{name, val})
		default: // 0000/0001 post-base forms (RFC 9204 §4.5.3/§4.5.5)
			return nil, fmt.Errorf("%w: post-base representation %#x", ErrQPACKDynamic, b0>>4)
		}
	}
	return out, nil
}

// finishInt continues an integer whose first-byte prefix was exhausted at its
// maximum value: full continuation bytes follow (RFC 7541 §5.1).
func (c *qpackReader) finishInt(acc uint64) (uint64, error) {
	var shift uint
	for {
		b, err := c.readBits(8)
		if err != nil {
			return 0, err
		}
		acc += (b & 0x7f) << shift
		if b&0x80 == 0 {
			return acc, nil
		}
		shift += 7
		if shift > 56 {
			return 0, errors.New("fxvpn: qpack integer overflow")
		}
	}
}

func staticLookup(idx uint64) (qpackEntry, error) {
	if idx >= uint64(len(qpackStaticTable)) {
		return qpackEntry{}, fmt.Errorf("fxvpn: qpack static index %d out of range", idx)
	}
	return qpackStaticTable[idx], nil
}

// qpackReader consumes bits MSB-first across the buffer.
type qpackReader struct {
	buf []byte
	pos int // absolute bit position
}

// readInt reads an HPACK-style prefixed integer starting at the cursor.
func (c *qpackReader) readInt(prefixBits int) (uint64, error) {
	max := uint64(1)<<uint(prefixBits) - 1
	v, err := c.readBits(uint(prefixBits))
	if err != nil {
		return 0, err
	}
	if v < max {
		return v, nil
	}
	var shift uint
	for {
		b, err := c.readBits(8)
		if err != nil {
			return 0, err
		}
		v += (b & 0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 56 {
			return 0, errors.New("fxvpn: qpack integer overflow")
		}
	}
	return v, nil
}

// readString reads an N-bit-prefix string literal (H flag + length prefix),
// decoding Huffman when flagged.
func (c *qpackReader) readString(prefixBits int) (string, error) {
	huff, err := c.readBits(1)
	if err != nil {
		return "", err
	}
	n, err := c.readInt(prefixBits - 1)
	if err != nil {
		return "", err
	}
	if n > qpackMaxStringLength {
		return "", fmt.Errorf("fxvpn: qpack string too long (%d)", n)
	}
	raw := make([]byte, n)
	for i := range raw {
		bit, err := c.readBits(8)
		if err != nil {
			return "", err
		}
		raw[i] = byte(bit)
	}
	if huff == 0 {
		return string(raw), nil
	}
	s, err := qpackHuffmanDecode(raw)
	if err != nil {
		return "", fmt.Errorf("fxvpn: qpack huffman decode: %w", err)
	}
	return s, nil
}

// qpackHuffmanDecode decodes the RFC 7541 Appendix B static-Huffman bit
// string (identical table for QPACK per RFC 9204 §4.1.2) via x/net's
// implementation.
func qpackHuffmanDecode(raw []byte) (string, error) {
	return hpack.HuffmanDecodeToString(raw)
}

// readBits consumes n bits MSB-first; n <= 64.
func (c *qpackReader) readBits(n uint) (uint64, error) {
	if c.pos+int(n) > len(c.buf)*8 {
		return 0, errors.New("fxvpn: qpack unexpected end of field section")
	}
	var v uint64
	for i := uint(0); i < n; i++ {
		byteIdx := c.pos / 8
		bitIdx := uint(7 - c.pos%8)
		v = v<<1 | uint64(c.buf[byteIdx]>>bitIdx&1)
		c.pos++
	}
	return v, nil
}
