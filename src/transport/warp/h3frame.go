// HTTP/3 framing for the path-B MASQUE transport (E-H3 design §2): frames on
// raw quic-go streams, control-stream lifecycle per RFC 9114 with the
// warp-socks minimal-H3 restrictions — the control stream is never closed by
// us (H3_CLOSED_CRITICAL_STREAM is terminal), unknown inbound frames are
// skipped (max 8 in a row before declaring the dialect broken), HEADERS
// payloads are capped at 64 KiB (design §2).
package transportwarp

import (
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
)

// HTTP/3 frame types (RFC 9114 §7.2). Only the subset the minimal dialect
// touches is named; everything else is skipped inbound.
const (
	h3FrameData     uint64 = 0x0
	h3FrameHeaders  uint64 = 0x1
	h3FrameSettings uint64 = 0x4
)

// HTTP/3 unidirectional stream types (RFC 9114 §6.2).
const (
	h3StreamControl      uint64 = 0x00
	h3StreamPush         uint64 = 0x01 // reserved; never created by us
	h3StreamQpackEncoder uint64 = 0x02
	h3StreamQpackDecoder uint64 = 0x03
)

const (
	// h3MaxFramePayload bounds any single buffered frame payload. HEADERS are
	// capped at 64 KiB by design §2; SETTINGS/DATA on control paths are far
	// smaller, and tunnel DATA travels via QUIC datagrams, not H3 DATA frames,
	// so one conservative cap keeps allocation bounded everywhere.
	h3MaxFramePayload = 64 << 10

	// h3MaxUnknownFrames is the inbound skip budget for consecutive unknown
	// frame types before the peer is considered non-conformant (design §2).
	h3MaxUnknownFrames = 8
)

var (
	errH3TruncatedFrame = errors.New("transportwarp: h3 truncated frame")
	errH3FrameTooLarge  = errors.New("transportwarp: h3 frame exceeds size cap")
	errH3TooManyUnknown = errors.New("transportwarp: h3 too many consecutive unknown frames")
)

// appendH3Frame appends one complete frame (type + length + payload).
func appendH3Frame(dst []byte, typ uint64, payload []byte) []byte {
	dst = AppendVarint(dst, typ)
	dst = AppendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// appendH3Headers appends a HEADERS frame carrying the field section.
func appendH3Headers(dst []byte, section []byte) []byte {
	return appendH3Frame(dst, h3FrameHeaders, section)
}

// readQUICVarintFrom reads one QUIC varint starting at b[off:]; returns the
// value and total bytes consumed. Errors when fewer than the indicated bytes
// are present (caller re-reads from the stream).
func readQUICVarintFrom(b []byte, off int) (uint64, int, error) {
	if off >= len(b) {
		return 0, 0, errH3TruncatedFrame
	}
	v, n, err := ParseVarint(b[off:])
	if err != nil || n > len(b)-off {
		if err == nil {
			err = errH3TruncatedFrame
		}
		return 0, n, err
	}
	return v, n, nil
}

// h3Framer reads whole frames off a QUIC stream.
type h3Framer struct{ r io.Reader }

func newH3Framer(r io.Reader) *h3Framer { return &h3Framer{r: r} }

// readVarintStream reads one QUIC varint byte-wise (handles partial reads).
func (f *h3Framer) readVarintStream() (uint64, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(f.r, hdr[:1]); err != nil {
		return 0, err
	}
	size := 1 << (hdr[0] >> 6)
	if _, err := io.ReadFull(f.r, hdr[1:size]); err != nil {
		return 0, err
	}
	v, _, err := ParseVarint(hdr[:size])
	return v, err
}

// ReadFrame blocks until one full frame is available.
func (f *h3Framer) ReadFrame() (typ uint64, payload []byte, err error) {
	typ, err = f.readVarintStream()
	if err != nil {
		return 0, nil, err
	}
	length, err := f.readVarintStream()
	if err != nil {
		return 0, nil, err
	}
	if length > h3MaxFramePayload {
		return 0, nil, fmt.Errorf("%w: type %#x len %d", errH3FrameTooLarge, typ, length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(f.r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// ReadKnownFrame reads the next known frame, skipping unknown/GREASE types up
// to the consecutive-unknown budget (RFC 9114 §9 requires ignoring them).
func (f *h3Framer) ReadKnownFrame(known map[uint64]bool) (typ uint64, payload []byte, err error) {
	for i := 0; ; i++ {
		typ, payload, err = f.ReadFrame()
		if err != nil {
			return 0, nil, err
		}
		if known[typ] {
			return typ, payload, nil
		}
		if i >= h3MaxUnknownFrames {
			return 0, nil, errH3TooManyUnknown
		}
	}
}

// ParseSettings walks id/value pairs tolerantly (unknown ids kept, malformed
// trailing data rejected).
func ParseSettings(payload []byte) (map[uint64]uint64, error) {
	out := make(map[uint64]uint64, 4)
	for off := 0; off < len(payload); {
		id, n, err := readQUICVarintFrom(payload, off)
		if err != nil {
			return nil, fmt.Errorf("%w: settings id", errH3TruncatedFrame)
		}
		val, n2, err := readQUICVarintFrom(payload, off+n)
		if err != nil {
			return nil, fmt.Errorf("%w: settings value", errH3TruncatedFrame)
		}
		out[id] = val
		off += n + n2
	}
	return out, nil
}

// readStreamType reads the leading varint of a unidirectional stream.
func readStreamType(s *quic.ReceiveStream) (uint64, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(s, hdr[:1]); err != nil {
		return 0, err
	}
	size := 1 << (hdr[0] >> 6)
	if _, err := io.ReadFull(s, hdr[1:size]); err != nil {
		return 0, err
	}
	v, _, err := ParseVarint(hdr[:size])
	return v, err
}
