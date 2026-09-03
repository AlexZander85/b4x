// HTTP/3 framing for the fxvpn H3 CONNECT tunnel over raw quic-go streams:
// control-stream lifecycle per RFC 9114, unknown inbound frames skipped
// (max 8 in a row before declaring the dialect broken), frame payloads
// capped at 64 KiB. Client opens its own control + QPACK uni-streams; the
// fake-edge stand reuses acceptControlStreams server-side.
package fxvpn

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
)

// HTTP/3 frame types (RFC 9114 §7.2).
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
	// h3MaxFramePayload bounds any single buffered frame payload (HEADERS
	// cap per design; tunnel DATA chunks stay well below it too).
	h3MaxFramePayload = 64 << 10

	// h3MaxUnknownFrames is the inbound skip budget for consecutive unknown
	// frame types before the peer is considered non-conformant.
	h3MaxUnknownFrames = 8
)

var (
	errH3TruncatedFrame = errors.New("fxvpn: h3 truncated frame")
	errH3FrameTooLarge  = errors.New("fxvpn: h3 frame exceeds size cap")
	errH3TooManyUnknown = errors.New("fxvpn: h3 too many consecutive unknown frames")
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
// value and total bytes consumed.
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

// ParseSettings walks id/value pairs tolerantly.
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

// writeClientPreamble opens and writes the client's mandatory uni-streams:
// control (type 0x0 + SETTINGS first frame), QPACK encoder and decoder
// (types 0x2/0x3, zero instructions — we never use the dynamic table).
// The streams stay open for the connection lifetime (closing critical
// streams is H3_CLOSED_CRITICAL_STREAM).
func writeClientPreamble(conn *quic.Conn) error {
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("fxvpn: open control stream: %w", err)
	}
	settings := appendH3Frame(nil, h3FrameSettings, nil) // empty SETTINGS is legal
	if _, err := ctrl.Write(append(AppendVarint(nil, h3StreamControl), settings...)); err != nil {
		return fmt.Errorf("fxvpn: write control preamble: %w", err)
	}
	for _, typ := range []uint64{h3StreamQpackEncoder, h3StreamQpackDecoder} {
		s, err := conn.OpenUniStream()
		if err != nil {
			return fmt.Errorf("fxvpn: open qpack uni stream: %w", err)
		}
		if _, err := s.Write(AppendVarint(nil, typ)); err != nil {
			return fmt.Errorf("fxvpn: write qpack stream type: %w", err)
		}
	}
	return nil
}

// acceptControlStreams consumes inbound unidirectional streams until the peer
// control stream arrives, reading its SETTINGS. qpack encoder/decoder streams
// from a no-dynamic-table peer carry zero instructions and are left unread;
// GREASE uni streams are ignored. The returned stream stays open.
func acceptControlStreams(ctx context.Context, conn *quic.Conn) (*quic.ReceiveStream, error) {
	for i := 0; i < 8; i++ { // bounded: control must arrive early; dial budget bounds hangs anyway
		s, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return nil, err
		}
		typ, err := readStreamType(s)
		if err != nil {
			return nil, err
		}
		switch typ {
		case h3StreamControl:
			fr := newH3Framer(s)
			t, payload, err := fr.ReadFrame()
			if err != nil {
				return nil, err
			}
			if t != h3FrameSettings {
				return nil, fmt.Errorf("fxvpn: first control frame %#x is not SETTINGS", t)
			}
			if _, err := ParseSettings(payload); err != nil {
				return nil, err
			}
			return s, nil
		case h3StreamQpackEncoder, h3StreamQpackDecoder:
			continue
		default:
			continue // unknown/GREASE uni stream: ignore
		}
	}
	return nil, errors.New("fxvpn: h3 control stream did not arrive")
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
