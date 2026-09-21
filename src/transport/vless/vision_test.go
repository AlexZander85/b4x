package vless

import (
	"bytes"
	"io"
	"testing"
)

func TestVisionBlockFormat(t *testing.T) {
	content := []byte("abc")
	b := buildVisionBlock(nil, cmdPaddingContinue, content, false)
	if len(b) < 5+len(content) {
		t.Fatalf("block too short: %d", len(b))
	}
	if b[0] != cmdPaddingContinue {
		t.Fatalf("command = %x want %x", b[0], cmdPaddingContinue)
	}
	clen := int(b[1])<<8 | int(b[2])
	plen := int(b[3])<<8 | int(b[4])
	if clen != 3 {
		t.Fatalf("contentLen = %d want 3", clen)
	}
	if string(b[5:5+clen]) != "abc" {
		t.Fatalf("content = %q", b[5:5+clen])
	}
	if len(b) != 5+clen+plen {
		t.Fatalf("block len %d != 5+%d+%d", len(b), clen, plen)
	}
	// The UUID prefix only when provided.
	uuid := bytes.Repeat([]byte{0xAB}, 16)
	bu := buildVisionBlock(uuid, cmdPaddingEnd, nil, false)
	if !bytes.Equal(bu[:16], uuid) {
		t.Fatal("uuid prefix missing")
	}
}

func TestVisionRoundTrip(t *testing.T) {
	uuid := bytes.Repeat([]byte{0x5A}, 16)
	chunks := [][]byte{
		{0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a}, // ClientHello (handshake)
		[]byte("tls-handshake-rest"),
		{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}, // ApplicationData
		[]byte("raw-after-direct"),
	}

	var wire bytes.Buffer
	w := newVisionWriter(&wire, uuid)
	if err := w.writePreamble(); err != nil {
		t.Fatal(err)
	}
	for _, c := range chunks {
		if _, err := w.Write(c); err != nil {
			t.Fatal(err)
		}
	}

	r := newVisionReader(&wire, uuid)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var want []byte
	for _, c := range chunks {
		want = append(want, c...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestVisionReaderPassthrough(t *testing.T) {
	uuid := bytes.Repeat([]byte{0x11}, 16)
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nplain-not-vision-stream")
	r := newVisionReader(bytes.NewReader(raw), uuid)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("passthrough mismatch: %q", got)
	}
}
