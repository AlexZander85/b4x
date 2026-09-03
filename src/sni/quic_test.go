package sni

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseQUICClientHelloSNIRejectsMalformedAndECHOnlyMetadata(t *testing.T) {
	for name, payload := range map[string][]byte{
		"empty":            nil,
		"tiny initial":     {0xc0, 0, 0, 0, 1, 0, 0},
		"truncated header": {0xc0, 0, 0, 0, 1, 8},
	} {
		t.Run(name, func(t *testing.T) {
			if host, ok := ParseQUICClientHelloSNI(payload); ok || host != "" {
				t.Fatalf("malformed QUIC parsed as host=%q ok=%v", host, ok)
			}
		})
	}

	// This is a structurally valid TLS ClientHello carried by QUIC CRYPTO,
	// but it has only an ECH extension and no clear SNI. It must remain
	// non-actionable metadata rather than becoming a final unknown verdict.
	crypto := echOnlyClientHello()
	if host, err := extractSNIFromQUIC(crypto); err == nil || len(host) != 0 {
		t.Fatalf("ECH-only ClientHello exposed host=%q err=%v", host, err)
	}
}

func echOnlyClientHello() []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0) // legacy session id
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01})
	body.WriteByte(1)
	body.WriteByte(0)
	var extensions bytes.Buffer
	binary.Write(&extensions, binary.BigEndian, uint16(0xfe0d))
	binary.Write(&extensions, binary.BigEndian, uint16(3))
	extensions.Write([]byte{1, 2, 3})
	binary.Write(&body, binary.BigEndian, uint16(extensions.Len()))
	body.Write(extensions.Bytes())

	var hello bytes.Buffer
	hello.WriteByte(tlsHandshakeClientHello)
	hello.Write([]byte{0, 0, byte(body.Len())})
	hello.Write(body.Bytes())
	return hello.Bytes()
}
