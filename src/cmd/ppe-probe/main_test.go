package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/quic"
)

func TestChecksum16RFC1071(t *testing.T) {
	// RFC 1071 §3 worked example: 0x0001, 0xf203, 0xf4f5, 0xf6f7 -> 0x220d.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := checksum16(data); got != 0x220d {
		t.Fatalf("checksum16 = %#04x, want 0x220d", got)
	}
	// Zero-data checksum must be 0xffff.
	if got := checksum16(nil); got != 0xffff {
		t.Fatalf("checksum16(empty) = %#04x, want 0xffff", got)
	}
	// Odd-length input is padded with a trailing zero byte.
	if got := checksum16([]byte{0x12, 0x34, 0x56}); got != checksum16([]byte{0x12, 0x34, 0x56, 0x00}) {
		t.Fatalf("odd-length padding mismatch: %#04x vs %#04x", got, checksum16([]byte{0x12, 0x34, 0x56, 0x00}))
	}
}

func TestBuildTCPPacket(t *testing.T) {
	saddr := net.IPv4(192, 168, 1, 152)
	daddr := net.IPv4(77, 88, 8, 8)
	payload := []byte("B4PPE-SELFTEST-PAYLOAD")
	packet := buildTCPPacket(saddr, daddr, 8443, 32000, 1000, 2000, flagSYN|flagACK, payload)

	if len(packet) != 20+20+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(packet), 20+20+len(payload))
	}
	if packet[0]>>4 != 4 || packet[0]&0x0f != 5 {
		t.Fatalf("IP version/IHL = %#02x, want 0x45", packet[0])
	}
	if packet[9] != protoTCP {
		t.Fatalf("IP protocol = %d, want %d", packet[9], protoTCP)
	}
	if !net.IP(packet[12:16]).Equal(saddr) || !net.IP(packet[16:20]).Equal(daddr) {
		t.Fatalf("IP addresses not copied: src=%v dst=%v", net.IP(packet[12:16]), net.IP(packet[16:20]))
	}
	tcp := packet[20:]
	if binary.BigEndian.Uint16(tcp[0:2]) != 8443 || binary.BigEndian.Uint16(tcp[2:4]) != 32000 {
		t.Fatalf("ports = %d:%d, want 8443:32000", binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]))
	}
	if binary.BigEndian.Uint32(tcp[4:8]) != 1000 || binary.BigEndian.Uint32(tcp[8:12]) != 2000 {
		t.Fatalf("seq/ack = %d/%d, want 1000/2000", binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]))
	}
	if tcp[13] != flagSYN|flagACK {
		t.Fatalf("flags = %#02x, want %#02x", tcp[13], flagSYN|flagACK)
	}
	// TCP checksum must verify: recompute over pseudo header + full TCP segment.
	if got := tcpChecksum(saddr, daddr, tcp); got != 0 {
		t.Fatalf("TCP checksum does not verify: %#04x", got)
	}
	// IP checksum must verify.
	if got := checksum16(packet[:20]); got != 0 {
		t.Fatalf("IP checksum does not verify: %#04x", got)
	}
	// Payload must trail the TCP header unchanged.
	if string(packet[40:]) != string(payload) {
		t.Fatalf("payload corrupted: %q", packet[40:])
	}
}

func TestBuildTCPPacketUsesZeroChecksumPlaceholder(t *testing.T) {
	// The caller must fill the checksum after building; verify the builder
	// leaves a placeholder (0) before the checksum is applied.
	tcp := tcpHeader(1, 2, 3, 4, flagACK, 0)
	if got := binary.BigEndian.Uint16(tcp[16:18]); got != 0 {
		t.Fatalf("checksum placeholder = %#04x, want 0", got)
	}
}

func TestEndpointAddr(t *testing.T) {
	ip, port, err := endpointAddr("77.88.8.8:443")
	if err != nil {
		t.Fatalf("endpointAddr(77.88.8.8:443): %v", err)
	}
	if !ip.Equal(net.IPv4(77, 88, 8, 8)) || port != 443 {
		t.Fatalf("got %v:%d, want 77.88.8.8:443", ip, port)
	}
	if _, _, err := endpointAddr("not-a-host"); err == nil {
		t.Fatal("endpointAddr(bad) should fail DNS resolution")
	}
	if _, _, err := endpointAddr("77.88.8.8:0"); err == nil {
		t.Fatal("endpointAddr(port 0) should fail")
	}
}

func TestEndpointAddrURL(t *testing.T) {
	// The b4 self-test controller passes the controlled endpoint as a full
	// http(s) URL; the probe must extract host:port and ignore the path.
	ip, port, err := endpointAddr("https://77.88.8.8/health")
	if err != nil {
		t.Fatalf("endpointAddr(https URL): %v", err)
	}
	if !ip.Equal(net.IPv4(77, 88, 8, 8)) || port != 443 {
		t.Fatalf("got %v:%d, want 77.88.8.8:443", ip, port)
	}
	ip, port, err = endpointAddr("http://192.168.1.40/health?x=1")
	if err != nil {
		t.Fatalf("endpointAddr(http URL): %v", err)
	}
	if !ip.Equal(net.IPv4(192, 168, 1, 40)) || port != 80 {
		t.Fatalf("got %v:%d, want 192.168.1.40:80", ip, port)
	}
	ip, port, err = endpointAddr("https://77.88.8.8:8443/deep/path")
	if err != nil {
		t.Fatalf("endpointAddr(https URL with port): %v", err)
	}
	if !ip.Equal(net.IPv4(77, 88, 8, 8)) || port != 8443 {
		t.Fatalf("got %v:%d, want 77.88.8.8:8443", ip, port)
	}
	if _, _, err := endpointAddr("ftp://77.88.8.8/health"); err == nil {
		t.Fatal("endpointAddr(ftp URL) should fail (bare-host fallback tries DNS)")
	}
	if _, _, err := endpointAddr("https:///health"); err == nil {
		t.Fatal("endpointAddr(URL without host) should fail")
	}
}

func TestParseArgs(t *testing.T) {
	a, err := parseArgs([]string{
		"--protocol", "tcp", "--family", "ipv4", "--source-port", "8443",
		"--flow-id", "auto-1-tcp", "--phase", "without_exclusion",
		"--endpoint", "77.88.8.8:443", "--timeout-ms", "5000",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if a.protocol != "tcp" || a.family != "ipv4" || a.sourcePort != 8443 ||
		a.flowID != "auto-1-tcp" || a.phase != "without_exclusion" ||
		a.endpoint != "77.88.8.8:443" || a.timeout != 5*time.Second {
		t.Fatalf("parseArgs mismatch: %+v", a)
	}
	if _, err := parseArgs([]string{"--source-port", "0", "--endpoint", "x:1"}); err == nil {
		t.Fatal("parseArgs(source-port 0) should fail")
	}
	if _, err := parseArgs([]string{"--source-port", "1000", "--endpoint", ""}); err == nil {
		t.Fatal("parseArgs(empty endpoint) should fail")
	}
}

func TestQuicInitialDatagramLooksLikeQUIC(t *testing.T) {
	datagram := quicInitialDatagram()
	if !quic.LooksLikeQUIC(datagram) {
		t.Fatalf("quicInitialDatagram not recognized as QUIC: len=%d first=%#02x", len(datagram), datagram[0])
	}
	if datagram[0]&0x80 == 0 {
		t.Fatalf("first byte %#02x: long header bit not set", datagram[0])
	}
}