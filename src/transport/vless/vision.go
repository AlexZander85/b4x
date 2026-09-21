package vless

import (
	"crypto/rand"
	"io"
	"math/big"
)

// XTLS Vision (flow=xtls-rprx-vision) client framing, ported from the public
// Xray-core reference (proxy/proxy.go: XtlsPadding/XtlsUnpadding/VisionWriter/
// VisionReader; MPL-2.0). b4x is authorized to reuse this algorithm.
//
// Wire format of one padding block, produced by XtlsPadding:
//
//	[ uuid(16)? ]
//	[ command(1) ][ contentLen(2, BE) ][ paddingLen(2, BE) ][ content ][ zero-padding ]
//
// The uuid prefix appears ONLY on the very first block of a direction (the
// receiver uses it to detect "vision framing vs raw"). Commands:
//
//	0x00 Continue — more padded blocks follow
//	0x01 End      — padding ends; the rest of the stream is raw
//	0x02 Direct   — like End, and the receiver may switch to zero-copy splice
//
// The client pads its uplink (inner TLS ClientHello etc.) and unpads the
// server's downlink. Padding length follows the reference testseed
// {900,500,900,256} with a hard cap of bufSize-21-contentLen.

const (
	visionBufSize = 8192

	cmdPaddingContinue byte = 0x00
	cmdPaddingEnd      byte = 0x01
	cmdPaddingDirect   byte = 0x02

	visionPreambleContentMax = 900 // testseed[0]
	visionPreamblePadRange   = 500 // testseed[1]
	visionPreamblePadBase    = 900 // testseed[2]
	visionSmallPadRange      = 256 // testseed[3]
)

// visionPaddingLen mirrors XtlsPadding's length selection.
func visionPaddingLen(contentLen int, long bool) int {
	var pad int
	if contentLen < visionPreambleContentMax && long {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(visionPreamblePadRange)))
		if err != nil {
			l = big.NewInt(0)
		}
		pad = int(l.Int64()) + visionPreamblePadBase - contentLen
	} else {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(visionSmallPadRange)))
		if err != nil {
			l = big.NewInt(0)
		}
		pad = int(l.Int64())
	}
	if max := visionBufSize - 21 - contentLen; pad > max {
		pad = max
	}
	if pad < 0 {
		pad = 0
	}
	return pad
}

// buildVisionBlock encodes one padding block. uuid is consumed by the first
// block only (callers pass nil afterwards).
func buildVisionBlock(uuid []byte, command byte, content []byte, long bool) []byte {
	pad := visionPaddingLen(len(content), long)
	out := make([]byte, 0, len(uuid)+5+len(content)+pad)
	out = append(out, uuid...)
	out = append(out, command, byte(len(content)>>8), byte(len(content)), byte(pad>>8), byte(pad))
	out = append(out, content...)
	out = append(out, make([]byte, pad)...)
	return out
}

// visionWriter pads the uplink stream.
type visionWriter struct {
	w       io.Writer
	uuid    []byte
	padding bool
	direct  bool
	isTLS   bool
	filter  int
}

func newVisionWriter(w io.Writer, uuid []byte) *visionWriter {
	return &visionWriter{w: w, uuid: uuid, padding: true, filter: 8}
}

// writePreamble emits the leading long zero-content padding block that hides
// the VLESS header (the reference's `mb[0]==nil` case).
func (v *visionWriter) writePreamble() error {
	if !v.padding {
		return nil
	}
	block := buildVisionBlock(v.uuid, cmdPaddingContinue, nil, true)
	v.uuid = nil
	_, err := v.w.Write(block)
	return err
}

func (v *visionWriter) Write(p []byte) (int, error) {
	if v.direct || len(p) == 0 {
		return v.w.Write(p)
	}
	if !v.isTLS && len(p) >= 2 && p[0] == 0x16 && p[1] == 0x03 {
		v.isTLS = true
	}
	if v.filter > 0 {
		v.filter--
	}
	appData := v.isTLS && len(p) >= 3 && p[0] == 0x17 && p[1] == 0x03 && p[2] == 0x03
	command := cmdPaddingContinue
	if appData || v.filter <= 1 {
		command = cmdPaddingEnd
		v.padding = false
	}
	block := buildVisionBlock(v.uuid, command, p, v.isTLS)
	v.uuid = nil
	if _, err := v.w.Write(block); err != nil {
		return 0, err
	}
	if command != cmdPaddingContinue {
		v.direct = true
	}
	return len(p), nil
}

// visionReader unpads the downlink stream.
type visionReader struct {
	r       io.Reader
	uuid    []byte
	buf     []byte
	out     []byte
	started bool
	direct  bool
}

func newVisionReader(r io.Reader, uuid []byte) *visionReader {
	return &visionReader{r: r, uuid: uuid}
}

// fill grows buf to at least n bytes (blocking); returns the read error only
// when it could not reach n.
func (v *visionReader) fill(n int) error {
	tmp := make([]byte, 4096)
	for len(v.buf) < n {
		m, err := v.r.Read(tmp)
		if m > 0 {
			v.buf = append(v.buf, tmp[:m]...)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (v *visionReader) Read(p []byte) (int, error) {
	for len(v.out) == 0 {
		if v.direct {
			return v.r.Read(p)
		}
		if !v.started {
			if err := v.fill(21); err != nil {
				// Not enough data for the UUID+header: treat everything as raw.
				v.direct = true
				if len(v.buf) > 0 {
					v.out = append(v.out, v.buf...)
					v.buf = nil
				}
				continue
			}
			if !bytesEqual(v.buf[:16], v.uuid) {
				v.direct = true
				v.out = append(v.out, v.buf...)
				v.buf = nil
				continue
			}
			v.buf = v.buf[16:]
			v.started = true
		}
		// Parse complete blocks. Return as soon as any content is available:
		// blocking on the NEXT block header while holding ready content would
		// deadlock against a server that waits for our next write.
		for {
			if len(v.out) > 0 {
				break
			}
			if len(v.buf) < 5 {
				if err := v.fill(5); err != nil {
					v.direct = true
					if len(v.buf) > 0 {
						v.out = append(v.out, v.buf...)
						v.buf = nil
					}
				}
				break
			}
			command := v.buf[0]
			contentLen := int(v.buf[1])<<8 | int(v.buf[2])
			paddingLen := int(v.buf[3])<<8 | int(v.buf[4])
			total := 5 + contentLen + paddingLen
			if len(v.buf) < total {
				if err := v.fill(total); err != nil {
					v.direct = true
					if len(v.buf) > 0 {
						v.out = append(v.out, v.buf...)
						v.buf = nil
					}
					break
				}
			}
			v.out = append(v.out, v.buf[5:5+contentLen]...)
			v.buf = v.buf[total:]
			if command != cmdPaddingContinue {
				// Padding ends: the remainder is raw stream.
				if len(v.buf) > 0 {
					v.out = append(v.out, v.buf...)
					v.buf = nil
				}
				v.direct = true
				break
			}
		}
	}
	n := copy(p, v.out)
	v.out = v.out[n:]
	return n, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
