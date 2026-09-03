// QUIC variable-length integers (RFC 9000 §16) for the fxvpn H3 wire layer.
// Same encoding as transport/warp (proven in EH1/EH2); error names prefixed
// for this package.
package fxvpn

import "errors"

var (
	ErrVarintOverflow  = errors.New("fxvpn: varint exceeds 10 bytes / 62-bit range")
	ErrVarintTruncated = errors.New("fxvpn: varint input truncated")
)

// AppendVarint appends v in QUIC variable-length encoding to dst.
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

// ParseVarint parses one varint from the front of b; returns value and bytes
// consumed. Truncated input => ErrVarintTruncated.
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
