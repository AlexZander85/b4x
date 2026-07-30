package mtproto

import (
	"bytes"
	"io"
	"testing"
)

func TestPrefixHandoffPreservesAllSizes(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 63, 64, 128} {
		src := bytes.Repeat([]byte{7}, n)
		h := CapturePrefix(src)
		out := make([]byte, 0, n)
		buf := make([]byte, 11)
		for {
			m, err := h.Read(buf)
			out = append(out, buf[:m]...)
			if err == io.EOF {
				break
			}
		}
		if !bytes.Equal(src, out) {
			t.Fatalf("prefix size %d changed", n)
		}
	}
}
