package action

import (
	"encoding/binary"
)

type BuiltPacket struct {
	Packet        []byte
	ProcessedMark uint32
	Sequence      uint32
	StreamStart   uint64
}

type PacketBuilder struct {
	MTU int
}

func (b PacketBuilder) Build(original []byte, write PlannedWrite, processedMark uint32) (BuiltPacket, error) {
	if processedMark == 0 || len(original) < 20 || len(write.Payload) == 0 || write.StreamEnd <= write.StreamStart || write.StreamEnd-write.StreamStart != uint64(len(write.Payload)) {
		return BuiltPacket{}, ErrInvalidPacket
	}
	version := original[0] >> 4
	var ipOffset, tcpOffset, payloadOffset, oldPayloadLen int
	switch version {
	case 4:
		var ok bool
		ipOffset, tcpOffset, payloadOffset, oldPayloadLen, ok = parseIPv4TCP(original)
		if !ok {
			return BuiltPacket{}, ErrInvalidPacket
		}
	case 6:
		var ok bool
		ipOffset, tcpOffset, payloadOffset, oldPayloadLen, ok = parseIPv6TCP(original)
		if !ok {
			return BuiltPacket{}, ErrInvalidPacket
		}
	default:
		return BuiltPacket{}, ErrInvalidPacket
	}
	if oldPayloadLen == 0 || payloadOffset+oldPayloadLen > len(original) {
		return BuiltPacket{}, ErrInvalidPacket
	}
	packet := make([]byte, payloadOffset+len(write.Payload))
	copy(packet, original[:payloadOffset])
	copy(packet[payloadOffset:], write.Payload)
	binary.BigEndian.PutUint32(packet[tcpOffset+4:tcpOffset+8], write.Sequence)
	if version == 4 {
		if len(packet) > 0xffff {
			return BuiltPacket{}, ErrMTU
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[10:12], 0)
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:ipOffset+int(packet[0]&0x0f)*4]))
	} else {
		if len(packet)-40 > 0xffff {
			return BuiltPacket{}, ErrMTU
		}
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	}
	if err := fixTCPChecksum(packet, version, tcpOffset); err != nil {
		return BuiltPacket{}, err
	}
	if b.MTU > 0 && len(packet) > b.MTU {
		return BuiltPacket{}, ErrMTU
	}
	return BuiltPacket{Packet: packet, ProcessedMark: processedMark, Sequence: write.Sequence, StreamStart: write.StreamStart}, nil
}

func ValidatePacket(packet []byte) error {
	if len(packet) < 20 {
		return ErrInvalidPacket
	}
	version := packet[0] >> 4
	var tcpOffset, payloadOffset, payloadLen int
	var ok bool
	switch version {
	case 4:
		_, tcpOffset, payloadOffset, payloadLen, ok = parseIPv4TCP(packet)
		if !ok || binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) || checksum(packet[:tcpOffset]) != 0 {
			return ErrInvalidPacket
		}
	case 6:
		_, tcpOffset, payloadOffset, payloadLen, ok = parseIPv6TCP(packet)
		if !ok || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return ErrInvalidPacket
		}
	default:
		return ErrInvalidPacket
	}
	if payloadOffset+payloadLen != len(packet) || tcpOffset+20 > payloadOffset || checksumTCP(packet, version, tcpOffset) != 0 {
		return ErrInvalidPacket
	}
	return nil
}

func parseIPv4TCP(packet []byte) (ipOffset, tcpOffset, payloadOffset, payloadLen int, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, 0, 0, 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl || packet[9] != 6 {
		return 0, 0, 0, 0, false
	}
	tcpOffset = ihl
	if len(packet) < tcpOffset+20 {
		return 0, 0, 0, 0, false
	}
	tcpHeaderLen := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeaderLen < 20 || len(packet) < tcpOffset+tcpHeaderLen {
		return 0, 0, 0, 0, false
	}
	payloadOffset = tcpOffset + tcpHeaderLen
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < payloadOffset || totalLen > len(packet) {
		return 0, 0, 0, 0, false
	}
	return 0, tcpOffset, payloadOffset, totalLen - payloadOffset, true
}

func parseIPv6TCP(packet []byte) (ipOffset, tcpOffset, payloadOffset, payloadLen int, ok bool) {
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return 0, 0, 0, 0, false
	}
	next := packet[6]
	offset := 40
	for next != 6 {
		switch next {
		case 0, 43, 60:
			if len(packet) < offset+2 {
				return 0, 0, 0, 0, false
			}
			next = packet[offset]
			offset += (int(packet[offset+1]) + 1) * 8
		case 44:
			return 0, 0, 0, 0, false
		default:
			return 0, 0, 0, 0, false
		}
		if offset > len(packet) {
			return 0, 0, 0, 0, false
		}
	}
	tcpOffset = offset
	if len(packet) < tcpOffset+20 {
		return 0, 0, 0, 0, false
	}
	tcpHeaderLen := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeaderLen < 20 || len(packet) < tcpOffset+tcpHeaderLen {
		return 0, 0, 0, 0, false
	}
	payloadOffset = tcpOffset + tcpHeaderLen
	return 0, tcpOffset, payloadOffset, len(packet) - payloadOffset, true
}

func fixTCPChecksum(packet []byte, version byte, tcpOffset int) error {
	if tcpOffset < 0 || tcpOffset+20 > len(packet) {
		return ErrInvalidPacket
	}
	tcpHeaderLen := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeaderLen < 20 || tcpOffset+tcpHeaderLen > len(packet) {
		return ErrInvalidPacket
	}
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], checksumTCPValue(packet, version, tcpOffset))
	return nil
}

func checksumTCP(packet []byte, version byte, tcpOffset int) uint16 {
	return checksumTCPValue(packet, version, tcpOffset)
}

func checksumTCPValue(packet []byte, version byte, tcpOffset int) uint16 {
	tcp := packet[tcpOffset:]
	sum := uint32(0)
	if version == 4 {
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
		}
		sum += uint32(6)
		sum += uint32(len(tcp))
	} else {
		for i := 8; i < 40; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
		}
		length := uint32(len(tcp))
		sum += length >> 16
		sum += length & 0xffff
		sum += uint32(6)
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 != 0 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
