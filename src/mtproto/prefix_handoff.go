package mtproto

import "io"

type PrefixHandoff struct {
	prefix []byte
	offset int
}

func CapturePrefix(b []byte) PrefixHandoff { return PrefixHandoff{prefix: append([]byte(nil), b...)} }
func (h *PrefixHandoff) Read(p []byte) (int, error) {
	if h == nil || h.offset >= len(h.prefix) {
		return 0, io.EOF
	}
	n := copy(p, h.prefix[h.offset:])
	h.offset += n
	return n, nil
}
func (h PrefixHandoff) Bytes() []byte { return append([]byte(nil), h.prefix...) }
func ReplayPrefix(prefix []byte, read func([]byte) (int, error), dst []byte) (int, error) {
	h := CapturePrefix(prefix)
	n, _ := h.Read(dst)
	if n == len(dst) {
		return n, nil
	}
	m, err := read(dst[n:])
	return n + m, err
}
