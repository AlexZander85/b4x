package sock

import (
	"encoding/binary"
)

// ============================================================================
// Test Helpers - build valid packets
// ============================================================================

func buildMinimalIPv4TCPPacket(payloadSize int) []byte {
	ipHdrLen := 20
	tcpHdrLen := 20
	totalLen := ipHdrLen + tcpHdrLen + payloadSize

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64                              // TTL
	pkt[9] = 6                               // Protocol TCP
	copy(pkt[12:16], []byte{192, 168, 1, 1}) // Src IP
	copy(pkt[16:20], []byte{10, 0, 0, 1})    // Dst IP

	// TCP header
	binary.BigEndian.PutUint16(pkt[ipHdrLen:], 12345)  // Src port
	binary.BigEndian.PutUint16(pkt[ipHdrLen+2:], 443)  // Dst port
	binary.BigEndian.PutUint32(pkt[ipHdrLen+4:], 1000) // Seq
	binary.BigEndian.PutUint32(pkt[ipHdrLen+8:], 2000) // Ack
	pkt[ipHdrLen+12] = 0x50                            // Data offset 5 (20 bytes)
	pkt[ipHdrLen+13] = 0x18                            // PSH + ACK

	// Payload
	for i := 0; i < payloadSize; i++ {
		pkt[ipHdrLen+tcpHdrLen+i] = byte(i % 256)
	}

	FixIPv4Checksum(pkt[:ipHdrLen])
	FixTCPChecksum(pkt)

	return pkt
}

func buildMinimalIPv6TCPPacket(payloadSize int) []byte {
	ipv6HdrLen := 40
	tcpHdrLen := 20
	totalLen := ipv6HdrLen + tcpHdrLen + payloadSize

	pkt := make([]byte, totalLen)

	// IPv6 header
	pkt[0] = 0x60                                                       // Version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpHdrLen+payloadSize)) // Payload length
	pkt[6] = 6                                                          // Next header = TCP
	pkt[7] = 64                                                         // Hop limit

	// Src/Dst addresses (::1 for simplicity)
	pkt[23] = 1 // Src = ::1
	pkt[39] = 1 // Dst = ::1

	// TCP header
	binary.BigEndian.PutUint16(pkt[ipv6HdrLen:], 12345)
	binary.BigEndian.PutUint16(pkt[ipv6HdrLen+2:], 443)
	binary.BigEndian.PutUint32(pkt[ipv6HdrLen+4:], 1000)
	binary.BigEndian.PutUint32(pkt[ipv6HdrLen+8:], 2000)
	pkt[ipv6HdrLen+12] = 0x50
	pkt[ipv6HdrLen+13] = 0x18

	for i := 0; i < payloadSize; i++ {
		pkt[ipv6HdrLen+tcpHdrLen+i] = byte(i % 256)
	}

	FixTCPChecksumV6(pkt)

	return pkt
}

func buildTLSClientHello() []byte {
	// Minimal TLS ClientHello with SNI for www.example.com
	ipHdrLen := 20
	tcpHdrLen := 20

	// TLS record header + handshake header + client hello with SNI
	tlsPayload := []byte{
		0x16, 0x03, 0x01, 0x00, 0x50, // TLS record: handshake, version, length
		0x01, 0x00, 0x00, 0x4c, // Handshake: ClientHello, length
		0x03, 0x03, // Version TLS 1.2
	}
	// Random (32 bytes)
	tlsPayload = append(tlsPayload, make([]byte, 32)...)
	// Session ID length (0)
	tlsPayload = append(tlsPayload, 0x00)
	// Cipher suites
	tlsPayload = append(tlsPayload, 0x00, 0x02, 0x00, 0xff)
	// Compression
	tlsPayload = append(tlsPayload, 0x01, 0x00)
	// Extensions length
	tlsPayload = append(tlsPayload, 0x00, 0x15)
	// SNI extension
	tlsPayload = append(tlsPayload, 0x00, 0x00)               // Extension type: SNI
	tlsPayload = append(tlsPayload, 0x00, 0x11)               // Extension length
	tlsPayload = append(tlsPayload, 0x00, 0x0f)               // SNI list length
	tlsPayload = append(tlsPayload, 0x00)                     // Host name type
	tlsPayload = append(tlsPayload, 0x00, 0x0c)               // Host name length
	tlsPayload = append(tlsPayload, []byte("www.example")...) // 11 bytes

	totalLen := ipHdrLen + tcpHdrLen + len(tlsPayload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 1})

	binary.BigEndian.PutUint16(pkt[ipHdrLen:], 12345)
	binary.BigEndian.PutUint16(pkt[ipHdrLen+2:], 443)
	binary.BigEndian.PutUint32(pkt[ipHdrLen+4:], 1000)
	pkt[ipHdrLen+12] = 0x50
	pkt[ipHdrLen+13] = 0x18

	copy(pkt[ipHdrLen+tcpHdrLen:], tlsPayload)

	FixIPv4Checksum(pkt[:ipHdrLen])
	FixTCPChecksum(pkt)

	return pkt
}
