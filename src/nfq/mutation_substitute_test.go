package nfq

import (
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// buildClientHelloPacket builds a minimal valid IPv4+TCP packet carrying a
// TLS ClientHello with a single server_name (SNI) extension.
func buildClientHelloPacket(t *testing.T, hostname string) []byte {
	t.Helper()

	// TLS payload: record(5) + handshake(4) + version(2) + random(32) +
	// session_id(1+0) + cipher_suites(2+2) + compression(1+1) + extensions.
	payload := []byte{
		0x16, 0x03, 0x01, 0x00, 0x00, // TLS record header (len patched below)
		0x01, 0x00, 0x00, 0x00, // Handshake ClientHello + 3-byte length
		0x03, 0x03, // client_version TLS 1.2
	}
	random := make([]byte, 32)
	payload = append(payload, random...)
	payload = append(payload, 0x00)       // session_id length
	payload = append(payload, 0x00, 0x02) // cipher suites length
	payload = append(payload, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	payload = append(payload, 0x01, 0x00) // compression methods: 1x null

	// SNI extension: type 0x0000, data = name_list_len + name_type(0) + name_len + name.
	body := make([]byte, 3+len(hostname))
	binary.BigEndian.PutUint16(body[1:3], uint16(len(hostname)))
	copy(body[3:], hostname)

	sniExt := make([]byte, 0, 4+2+len(body))
	sniExt = binary.BigEndian.AppendUint16(sniExt, 0x0000)           // ext type: server_name
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(2+len(body))) // ext len (incl. list len)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(body)))   // name list len
	sniExt = append(sniExt, body...)

	exts := make([]byte, 0, 2+len(sniExt))
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sniExt)))
	exts = append(exts, sniExt...)
	payload = append(payload, exts...)

	// Patch TLS record length + handshake length.
	recordLen := uint16(len(payload) - 5)
	binary.BigEndian.PutUint16(payload[3:5], recordLen)
	helloLen := uint32(len(payload) - 9)
	payload[6] = byte(helloLen >> 16)
	payload[7] = byte(helloLen >> 8)
	payload[8] = byte(helloLen)

	// IPv4 header (20 bytes).
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload))) // total length
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{1, 2, 3, 4})
	copy(ip[16:20], []byte{5, 6, 7, 8})

	// TCP header (20 bytes), PSH|ACK.
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	binary.BigEndian.PutUint32(tcp[8:12], 1)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	packet := append(ip, tcp...)
	packet = append(packet, payload...)
	return packet
}

// extractSNI parses the server_name back out of a mutated packet.
func extractSNI(t *testing.T, packet []byte) string {
	t.Helper()
	ipHdrLen := int((packet[0] & 0x0F) * 4)
	tcpHdrLen := int((packet[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	extOffset := (&Worker{}).findExtensionsOffset(packet[payloadStart:])
	if extOffset < 0 {
		t.Fatalf("extensions offset not found")
	}
	extPos := payloadStart + extOffset
	extLen := int(binary.BigEndian.Uint16(packet[extPos : extPos+2]))
	exts := packet[extPos+2 : extPos+2+extLen]
	start, length := findServerNameExtension(exts)
	if start < 0 {
		t.Fatalf("server_name extension not found")
	}
	sniExt := exts[start : start+length]
	if len(sniExt) < 9 || sniExt[6] != 0 {
		t.Fatalf("malformed server_name extension")
	}
	nameLen := int(binary.BigEndian.Uint16(sniExt[7:9]))
	if 9+nameLen > len(sniExt) {
		t.Fatalf("truncated SNI name")
	}
	return string(sniExt[9 : 9+nameLen])
}

func TestSubstituteSNI(t *testing.T) {
	w := &Worker{}
	cfg := &config.SetConfig{
		Faking: config.FakingConfig{
			SNI: true,
			SNIMutation: config.SNIMutationConfig{
				Mode:     "substitute",
				FakeSNIs: []string{"ya.ru"},
			},
		},
	}

	packet := buildClientHelloPacket(t, "googlevideo.com")
	if got := extractSNI(t, packet); got != "googlevideo.com" {
		t.Fatalf("precondition: SNI = %q, want googlevideo.com", got)
	}

	originalLen := len(packet)
	mutated := w.MutateClientHello(cfg, packet, nil)
	if mutated == nil {
		t.Fatalf("MutateClientHello returned nil")
	}
	if got := extractSNI(t, mutated); got != "ya.ru" {
		t.Fatalf("substitute failed: SNI = %q, want ya.ru", got)
	}
	if len(mutated) != originalLen {
		t.Fatalf("substitute changed packet size: %d -> %d (TCP hole!)", originalLen, len(mutated))
	}

	// Lengths must be consistent: ext len, TLS record len, handshake len, IP len.
	ipHdrLen := int((mutated[0] & 0x0F) * 4)
	tcpHdrLen := int((mutated[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	payload := mutated[payloadStart:]

	extOffset := w.findExtensionsOffset(payload)
	extPos := payloadStart + extOffset
	extLen := int(binary.BigEndian.Uint16(payload[extOffset : extOffset+2]))

	if extPos+2+extLen > len(mutated) {
		t.Fatalf("extensions overflow packet: extPos=%d extLen=%d packetLen=%d", extPos, extLen, len(mutated))
	}
	if got := int(binary.BigEndian.Uint16(payload[3:5])); got != len(payload)-5 {
		t.Fatalf("TLS record length = %d, want %d", got, len(payload)-5)
	}
	helloLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	if helloLen != len(payload)-9 {
		t.Fatalf("handshake length = %d, want %d", helloLen, len(payload)-9)
	}
	if got := int(binary.BigEndian.Uint16(mutated[2:4])); got != len(mutated) {
		t.Fatalf("IP total length = %d, want %d", got, len(mutated))
	}

	// Same-length swap path: identical name length must preserve packet size.
	cfg2 := &config.SetConfig{
		Faking: config.FakingConfig{
			SNI: true,
			SNIMutation: config.SNIMutationConfig{
				Mode:     "substitute",
				FakeSNIs: []string{"zzzzzzzzzzzzzzz"},
			},
		},
	}
	sameLen := buildClientHelloPacket(t, "googlevideo.com")
	mutated2 := w.MutateClientHello(cfg2, sameLen, nil)
	if got := extractSNI(t, mutated2); got != "zzzzzzzzzzzzzzz" {
		t.Fatalf("same-length substitute failed: SNI = %q, want zzzzzzzzzzzzzzz", got)
	}
	if len(mutated2) != originalLen {
		t.Fatalf("same-length substitute changed packet size: %d -> %d", originalLen, len(mutated2))
	}
}

// buildLargeClientHelloPacket builds a ClientHello whose extensions block is
// padded so the whole TLS record exceeds 1400 bytes (two TCP segments), like
// Go's default ClientHello.
func buildLargeClientHelloPacket(t *testing.T, hostname string, padLen int) []byte {
	t.Helper()
	packet := buildClientHelloPacket(t, hostname)
	if padLen <= 0 {
		return packet
	}

	ipHdrLen := int((packet[0] & 0x0F) * 4)
	tcpHdrLen := int((packet[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	extOffset := (&Worker{}).findExtensionsOffset(packet[payloadStart:])
	extPos := payloadStart + extOffset

	// Insert a padding extension (type 0x0015) before the extensions length
	// prefix, then re-patch record/handshake/IP lengths.
	padExt := make([]byte, 4+padLen)
	binary.BigEndian.PutUint16(padExt[0:2], extPadding)
	binary.BigEndian.PutUint16(padExt[2:4], uint16(padLen))

	extLen := int(binary.BigEndian.Uint16(packet[extPos : extPos+2]))
	body := make([]byte, 0, extLen+2+4+padLen)
	body = append(body, packet[extPos:extPos+2]...)
	body = append(body, packet[extPos+2:extPos+2+extLen]...)
	body = append(body, padExt...)

	newPacket := make([]byte, 0, len(packet)+4+padLen)
	newPacket = append(newPacket, packet[:extPos]...)
	newPacket = append(newPacket, body...)
	newPacket = append(newPacket, packet[extPos+2+extLen:]...)

	payload := newPacket[payloadStart:]
	binary.BigEndian.PutUint16(payload[3:5], uint16(len(payload)-5))
	helloLen := uint32(len(payload) - 9)
	payload[6] = byte(helloLen >> 16)
	payload[7] = byte(helloLen >> 8)
	payload[8] = byte(helloLen)
	binary.BigEndian.PutUint16(newPacket[2:4], uint16(len(newPacket)))
	return newPacket
}

func TestSubstituteSNIMultiSegment(t *testing.T) {
	w := &Worker{}
	cfg := &config.SetConfig{
		Faking: config.FakingConfig{
			SNI: true,
			SNIMutation: config.SNIMutationConfig{
				Mode:     "substitute",
				FakeSNIs: []string{"ya.ru"},
			},
		},
	}

	// Go's real ClientHello is ~1503 bytes > MSS 1400, so it arrives as two
	// TCP segments. The first segment carries the record + handshake headers
	// (with the FULL extension length) but only part of the extensions.
	packet := buildLargeClientHelloPacket(t, "googlevideo.com", 1400)
	if len(packet)-40 <= 1400 {
		t.Fatalf("test precondition: ClientHello must span two segments")
	}
	first := append([]byte(nil), packet[:40+1400]...)
	second := append([]byte(nil), packet[40+1400:]...)

	mutated := w.MutateClientHello(cfg, first, nil)
	if mutated == nil {
		t.Fatalf("MutateClientHello returned nil")
	}
	if got := extractSNITruncated(t, mutated); got != "ya.ru" {
		t.Fatalf("multi-segment substitute failed: SNI = %q, want ya.ru", got)
	}
	if len(mutated) != len(first) {
		t.Fatalf("substitute changed first segment size: %d -> %d (TCP hole!)", len(first), len(mutated))
	}

	// Lengths must stay consistent so the peer can reassemble the stream:
	// the full extension length, TLS record length and handshake length all
	// stay the same because the padding compensates the shorter SNI.
	ipHdrLen := int((mutated[0] & 0x0F) * 4)
	tcpHdrLen := int((mutated[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	payload := mutated[payloadStart:]
	extOffset := w.findExtensionsOffset(payload)
	extPos := payloadStart + extOffset
	extLen := int(binary.BigEndian.Uint16(payload[extOffset : extOffset+2]))

	ipHdrLen0 := int((first[0] & 0x0F) * 4)
	tcpHdrLen0 := int((first[ipHdrLen0+12] >> 4) * 4)
	payloadStart0 := ipHdrLen0 + tcpHdrLen0
	payload0 := first[payloadStart0:]
	extOffset0 := w.findExtensionsOffset(payload0)
	extLen0 := int(binary.BigEndian.Uint16(payload0[extOffset0 : extOffset0+2]))

	if extLen != extLen0 {
		t.Fatalf("extension block length changed: %d -> %d", extLen0, extLen)
	}
	if got := int(binary.BigEndian.Uint16(payload[3:5])); got != int(binary.BigEndian.Uint16(payload0[3:5])) {
		t.Fatalf("TLS record length changed")
	}
	helloLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	helloLen0 := int(payload0[6])<<16 | int(payload0[7])<<8 | int(payload0[8])
	if helloLen != helloLen0 {
		t.Fatalf("handshake length changed: %d -> %d", helloLen0, helloLen)
	}
	if got := int(binary.BigEndian.Uint16(mutated[2:4])); got != len(mutated) {
		t.Fatalf("IP total length = %d, want %d", got, len(mutated))
	}

	// The padding extension must be present and be the last extension.
	exts := mutated[extPos+2 : extPos+2+extLen]
	pos := 0
	var lastType uint16 = 0xffff
	for pos+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[pos : pos+2])
		el := int(binary.BigEndian.Uint16(exts[pos+2 : pos+4]))
		if pos+4+el > len(exts) {
			break
		}
		lastType = typ
		pos += 4 + el
	}
	if lastType != extPadding {
		t.Fatalf("padding extension missing or not last: last type = 0x%04x", lastType)
	}

	// The second segment must pass through untouched: it is not a ClientHello
	// start, so MutateClientHello must not touch it (no double-mutation).
	secondMutated := w.MutateClientHello(cfg, second, nil)
	for i := range second {
		if secondMutated[i] != second[i] {
			t.Fatalf("second segment was modified at byte %d", i)
		}
	}
}

// extractSNITruncated reads the SNI out of a packet whose extensions block is
// only partially present (multi-segment ClientHello).
func extractSNITruncated(t *testing.T, packet []byte) string {
	t.Helper()
	ipHdrLen := int((packet[0] & 0x0F) * 4)
	tcpHdrLen := int((packet[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	extOffset := (&Worker{}).findExtensionsOffset(packet[payloadStart:])
	if extOffset < 0 {
		t.Fatalf("extensions offset not found")
	}
	extPos := payloadStart + extOffset
	exts := packet[extPos+2:]
	start, length := findServerNameExtension(exts)
	if start < 0 {
		t.Fatalf("server_name extension not found in truncated block")
	}
	sniExt := exts[start : start+length]
	if len(sniExt) < 9 || sniExt[6] != 0 {
		t.Fatalf("malformed server_name extension")
	}
	nameLen := int(binary.BigEndian.Uint16(sniExt[7:9]))
	if 9+nameLen > len(sniExt) {
		t.Fatalf("truncated SNI name")
	}
	return string(sniExt[9 : 9+nameLen])
}

func TestSubstituteSNINoSNI(t *testing.T) {
	w := &Worker{}
	cfg := &config.SetConfig{
		Faking: config.FakingConfig{
			SNI: true,
			SNIMutation: config.SNIMutationConfig{
				Mode: "substitute",
			},
		},
	}
	// No FakeSNIs configured: must return the packet untouched.
	packet := buildClientHelloPacket(t, "googlevideo.com")
	orig := append([]byte(nil), packet...)
	mutated := w.MutateClientHello(cfg, packet, nil)
	if len(mutated) != len(orig) {
		t.Fatalf("packet changed without FakeSNIs: %d -> %d", len(orig), len(mutated))
	}
	for i := range orig {
		if mutated[i] != orig[i] {
			t.Fatalf("packet byte %d changed without FakeSNIs", i)
		}
	}

	// Mode off: untouched.
	cfg.Faking.SNIMutation.Mode = config.ConfigOff
	cfg.Faking.SNIMutation.FakeSNIs = []string{"ya.ru"}
	mutated = w.MutateClientHello(cfg, packet, nil)
	if len(mutated) != len(orig) {
		t.Fatalf("packet changed with mode off")
	}
}

// buildCHWithKeyShare builds a ClientHello whose extensions are:
// [0xff01 (5 bytes)] + [SNI] + [key_share 0x0033 with a large payload],
// which reproduces the field-observed shape of a real curl/Go ClientHello:
// the SNI is NOT the first extension and the tail of the block is the
// key_share data (truncated by the 1400-byte segment boundary).
func buildCHWithKeyShare(t *testing.T, hostname string, keyShareLen int) []byte {
	t.Helper()
	packet := buildClientHelloPacket(t, hostname)

	ipHdrLen := int((packet[0] & 0x0F) * 4)
	tcpHdrLen := int((packet[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	extOffset := (&Worker{}).findExtensionsOffset(packet[payloadStart:])
	extPos := payloadStart + extOffset
	extLen := int(binary.BigEndian.Uint16(packet[extPos : extPos+2]))
	exts := packet[extPos+2 : extPos+2+extLen] // SNI only

	pre := []byte{0xff, 0x01, 0x00, 0x01, 0x00} // 0xff01, payload 1
	keyShare := make([]byte, 4+keyShareLen)
	binary.BigEndian.PutUint16(keyShare[0:2], 0x0033)
	binary.BigEndian.PutUint16(keyShare[2:4], uint16(keyShareLen))

	newExts := make([]byte, 0, len(pre)+len(exts)+len(keyShare))
	newExts = append(newExts, pre...)
	newExts = append(newExts, exts...)
	newExts = append(newExts, keyShare...)

	newPacket := make([]byte, 0, extPos+2+len(newExts))
	newPacket = append(newPacket, packet[:extPos]...)
	newPacket = binary.BigEndian.AppendUint16(newPacket, uint16(len(newExts)))
	newPacket = append(newPacket, newExts...)

	payload := newPacket[payloadStart:]
	binary.BigEndian.PutUint16(payload[3:5], uint16(len(payload)-5))
	helloLen := uint32(len(payload) - 9)
	payload[6] = byte(helloLen >> 16)
	payload[7] = byte(helloLen >> 8)
	payload[8] = byte(helloLen)
	binary.BigEndian.PutUint16(newPacket[2:4], uint16(len(newPacket)))
	return newPacket
}

// TestSubstituteSNIMultiSegmentKeyShare is the regression test for the
// field-observed defect: for a multi-segment ClientHello the substitution
// rewrote the extension-length field with the truncated in-segment size
// (e.g. 1258 instead of 1431). The TLS record and handshake lengths kept
// their full values and the following segment kept its sequence numbers, so
// the peer read ~173 bytes of garbage after the extensions inside the hello
// and answered "tlsv1 alert decode error". The extension-length field must
// keep describing the FULL block, and the padding compensation must sit
// right after the substituted SNI so it cannot land inside the key_share
// data of the reassembled stream.
func TestSubstituteSNIMultiSegmentKeyShare(t *testing.T) {
	w := &Worker{}
	cfg := &config.SetConfig{
		Faking: config.FakingConfig{
			SNI: true,
			SNIMutation: config.SNIMutationConfig{
				Mode:     "substitute",
				FakeSNIs: []string{"ya.ru"},
			},
		},
	}

	packet := buildCHWithKeyShare(t, "googlevideo.com", 1350)
	if len(packet)-40 <= 1400 {
		t.Fatalf("precondition: ClientHello must span two segments (payload %d)", len(packet)-40)
	}
	first := append([]byte(nil), packet[:40+1400]...)
	second := append([]byte(nil), packet[40+1400:]...)

	ipHdrLen0 := int((first[0] & 0x0F) * 4)
	tcpHdrLen0 := int((first[ipHdrLen0+12] >> 4) * 4)
	payloadStart0 := ipHdrLen0 + tcpHdrLen0
	extOffset0 := w.findExtensionsOffset(first[payloadStart0:])
	fullExtLen := int(binary.BigEndian.Uint16(first[payloadStart0+extOffset0 : payloadStart0+extOffset0+2]))
	origRecordLen := int(binary.BigEndian.Uint16(first[payloadStart0+3 : payloadStart0+5]))
	origHelloLen := int(first[payloadStart0+6])<<16 | int(first[payloadStart0+7])<<8 | int(first[payloadStart0+8])

	mutated := w.MutateClientHello(cfg, first, nil)
	if mutated == nil {
		t.Fatalf("MutateClientHello returned nil")
	}
	if len(mutated) != len(first) {
		t.Fatalf("first segment size changed: %d -> %d (TCP hole!)", len(first), len(mutated))
	}
	if got := extractSNITruncated(t, mutated); got != "ya.ru" {
		t.Fatalf("SNI = %q, want ya.ru", got)
	}

	ipHdrLen := int((mutated[0] & 0x0F) * 4)
	tcpHdrLen := int((mutated[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	extOffset := w.findExtensionsOffset(mutated[payloadStart:])
	extPos := payloadStart + extOffset
	extLen := int(binary.BigEndian.Uint16(mutated[extPos : extPos+2]))

	// REGRESSION: the extension-length field must keep its ORIGINAL value
	// describing the full block across segments.
	if extLen != fullExtLen {
		t.Fatalf("extension length field rewritten: %d -> %d (must stay %d)", fullExtLen, extLen, fullExtLen)
	}
	if got := int(binary.BigEndian.Uint16(mutated[payloadStart+3 : payloadStart+5])); got != origRecordLen {
		t.Fatalf("TLS record length changed: %d -> %d", origRecordLen, got)
	}
	helloLen := int(mutated[payloadStart+6])<<16 | int(mutated[payloadStart+7])<<8 | int(mutated[payloadStart+8])
	if helloLen != origHelloLen {
		t.Fatalf("handshake length changed: %d -> %d", origHelloLen, helloLen)
	}

	// The padding compensation must be placed immediately after the
	// substituted SNI inside the visible head: the original tail is key_share
	// data arriving in the next segment, so padding at the end of the head
	// would corrupt the client key in the reassembled stream.
	visible := mutated[extPos+2:]
	if len(visible) < 30 {
		t.Fatalf("visible extensions too short: %d", len(visible))
	}
	if got := binary.BigEndian.Uint16(visible[19:21]); got != extPadding {
		t.Fatalf("padding not immediately after SNI: type at offset 19 = 0x%04x", got)
	}
	if got := int(binary.BigEndian.Uint16(visible[21:23])); got != 6 {
		t.Fatalf("padding length = %d, want 6 (15 - 5 - 4)", got)
	}

	// Reassemble the stream (mutated first segment + untouched second) and
	// verify the full extensions block is structurally sound: every declared
	// extension parses, the key_share keeps its full length, and the block
	// ends exactly at the end of the hello (no trailing garbage).
	stream := make([]byte, 0, len(mutated[payloadStart:])+len(second))
	stream = append(stream, mutated[payloadStart:]...)
	stream = append(stream, second...)
	if len(stream) != 9+origHelloLen {
		t.Fatalf("stream length %d != 9+helloLen %d", len(stream), 9+origHelloLen)
	}
	exts := stream[extPos-payloadStart+2 : extPos-payloadStart+2+extLen]
	if len(exts) != extLen {
		t.Fatalf("cannot read full extensions (%d) from stream", extLen)
	}
	pos := 0
	seen := 0
	for pos+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[pos : pos+2])
		el := int(binary.BigEndian.Uint16(exts[pos+2 : pos+4]))
		if pos+4+el > len(exts) {
			t.Fatalf("extension 0x%04x len %d truncated in stream at %d (avail %d)", typ, el, pos, len(exts)-pos)
		}
		if typ == extServerName {
			nameLen := int(binary.BigEndian.Uint16(exts[pos+7 : pos+9]))
			if got := string(exts[pos+9 : pos+9+nameLen]); got != "ya.ru" {
				t.Fatalf("stream SNI = %q, want ya.ru", got)
			}
			seen++
		}
		if typ == 0x0033 && el != 1350 {
			t.Fatalf("key_share length in stream = %d, want 1350 (must not be corrupted)", el)
		}
		pos += 4 + el
	}
	if pos != len(exts) {
		t.Fatalf("extensions parse to %d of %d bytes (trailing garbage)", pos, len(exts))
	}
	if seen != 1 {
		t.Fatalf("SNI seen %d times in stream, want 1", seen)
	}
}
