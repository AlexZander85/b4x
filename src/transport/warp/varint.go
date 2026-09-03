// Package transportwarp implements the built-in WARP/MASQUE transport data
// plane (addendum v1.2, bd b4x-c6d / B4X-FIX-0004): a Cloudflare WARP MASQUE
// CONNECT-IP client over HTTP/2 TCP 443 with endpoint public-key pinning,
// data-plane trust validation, bounded lifecycle management for base and
// nested instances, and through-tunnel geo attestation for the experimental
// non-RU mode.
//
// Protocol source of truth is the pinned upstream reference usque commit
// 6aa03fc97d12848dce34eedbd187fb1077b5d1ea (MIT; see docs/reports/warp/
// WARP_1_REFERENCE_AUDIT.md): api/masque.go (TLS pinning + H2 CONNECT),
// internal/consts.go (API/SNI constants), cmd/enroll.go + models/register.go
// (enrollment schema), api/tunnel.go (pump semantics). The H2 wire format is
// capsule DATAGRAM frames per RFC 9297 as accepted by Cloudflare's endpoint:
// varint(type=0) varint(len) <ip packet>, in both directions on the CONNECT
// stream body.
//
// Design: .ag/research/warp-dataplane-design.md (v2, owner-approved).
package transportwarp

import "errors"

// Varint errors.
var (
	ErrVarintOverflow  = errors.New("engine: varint exceeds 10 bytes / 62-bit range")
	ErrVarintTruncated = errors.New("engine: varint input truncated")
)

// AppendVarint appends v using the QUIC variable-length integer encoding
// (RFC 9000 section 16) to dst and returns the extended buffer. Only the
// low 62 bits are representable on the wire; callers pass bounded values
// (frame lengths, stream ids).
func AppendVarint(dst []byte, v uint64) []byte {
	switch {
	case v <= 0x3f:
		return append(dst, byte(v))
	case v <= 0x3fff:
		return append(dst, byte(v>>8)&0x3f|0x40, byte(v))
	case v <= 0x3fffffff:
		return append(dst, byte(v>>24)&0x3f|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(v>>56)&0x3f|0xc0, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// ParseVarint parses one QUIC variable-length integer from the front of b,
// returning the value and the number of bytes consumed. It returns
// ErrVarintTruncated when more input is needed and ErrVarintOverflow when the
// encoding itself is malformed (length prefix larger than remaining bytes).
func ParseVarint(b []byte) (v uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, ErrVarintTruncated
	}
	size := 1 << (b[0] >> 6)
	if len(b) < size {
		return 0, 0, ErrVarintTruncated
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < size; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, size, nil
}

// VarintLen returns the encoded length of v in bytes.
func VarintLen(v uint64) int {
	switch {
	case v <= 0x3f:
		return 1
	case v <= 0x3fff:
		return 2
	case v <= 0x3fffffff:
		return 4
	default:
		return 8
	}
}
