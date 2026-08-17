package sni

import (
	"fmt"
	"strings"
)

const (
	// TLSClientHelloMetadataMaxBytes bounds parser work for a single observed
	// input. Android ClientHello fixtures are below 2 KiB; the larger cap keeps
	// normal padding valid without allowing attacker-sized allocation.
	TLSClientHelloMetadataMaxBytes   = 32 * 1024
	TLSClientHelloMetadataMaxRecords = 8
)

// TLSClientHelloMetadata is the bounded, observe-only result for TLS records
// carrying a ClientHello. NeedBytes is the exact number of additional bytes
// required for the current incomplete structure when it is knowable.
type TLSClientHelloMetadata struct {
	Complete          bool
	NeedBytes         int
	RecordNeedBytes   int
	SNI               string
	ALPN              []string
	SupportedVersions []uint16
	ECHPresent        bool
	ECHOuterName      string
	ClientHelloSize   int
	RecordCount       int
	TrailingDataBytes int
	LegacyVersion     uint16
	MaxVersion        uint16
	ParseError        string
}

// ParseTLSClientHelloMetadata parses only bounded TLS record and ClientHello
// structures. It never allocates based on an unbounded attacker length and
// treats incomplete input as a normal state rather than as a final verdict.
func ParseTLSClientHelloMetadata(input []byte) TLSClientHelloMetadata {
	metadata := TLSClientHelloMetadata{ALPN: make([]string, 0, 4), SupportedVersions: make([]uint16, 0, 4)}
	view := input
	if len(view) > TLSClientHelloMetadataMaxBytes {
		view = view[:TLSClientHelloMetadataMaxBytes]
	}

	handshake := make([]byte, 0, minMetadataInt(len(view), TLSClientHelloMetadataMaxBytes))
	pos := 0
	for pos < len(view) {
		if metadata.RecordCount >= TLSClientHelloMetadataMaxRecords {
			metadata.ParseError = "tls record count exceeds bound"
			return metadata
		}
		if len(view)-pos < 5 {
			metadata.Incomplete(len(view) - pos)
			metadata.RecordNeedBytes = 5 - (len(view) - pos)
			return metadata
		}
		recordType := view[pos]
		recordLength := int(view[pos+3])<<8 | int(view[pos+4])
		if recordLength > 16384 {
			metadata.ParseError = "tls record exceeds protocol bound"
			return metadata
		}
		recordEnd := pos + 5 + recordLength
		if recordEnd > len(view) {
			metadata.Incomplete(recordEnd - len(view))
			metadata.RecordNeedBytes = recordEnd - len(view)
			// The record is truncated at the segment boundary. When it carries
			// a ClientHello, the available prefix still usually contains the
			// SNI extension (it precedes padding and large key shares). Parse
			// the prefix leniently so the hostname can be observed without
			// waiting for a reassembled record.
			if recordType == 0x16 && recordLength > 0 {
				handshake = appendBounded(handshake, view[pos+5:], TLSClientHelloMetadataMaxBytes)
				if len(handshake) >= 4 && handshake[0] == tlsHandshakeClientHello {
					bodyLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
					helloLength := 4 + bodyLength
					if helloLength <= TLSClientHelloMetadataMaxBytes {
						parseClientHelloBodyPartial(handshake[4:], &metadata)
					}
				}
			}
			return metadata
		}
		metadata.RecordCount++
		record := view[pos+5 : recordEnd]
		pos = recordEnd

		if recordType != 0x16 { // handshake content type
			continue
		}
		previousHandshakeBytes := len(handshake)
		handshake = appendBounded(handshake, record, TLSClientHelloMetadataMaxBytes)
		if len(handshake) < 4 {
			if pos < len(view) {
				continue
			}
			metadata.Incomplete(4 - len(handshake))
			return metadata
		}
		if handshake[0] != tlsHandshakeClientHello {
			metadata.ParseError = fmt.Sprintf("unexpected first handshake type 0x%02x", handshake[0])
			return metadata
		}
		bodyLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		helloLength := 4 + bodyLength
		if helloLength > TLSClientHelloMetadataMaxBytes {
			metadata.ParseError = "client hello exceeds parser bound"
			return metadata
		}
		if len(handshake) < helloLength {
			if pos < len(view) {
				continue
			}
			metadata.Incomplete(helloLength - len(handshake))
			// Handshake message spans multiple TLS records and the view is
			// exhausted: parse the collected prefix leniently for SNI.
			if len(handshake) >= 4 && handshake[0] == tlsHandshakeClientHello {
				parseClientHelloBodyPartial(handshake[4:], &metadata)
			}
			return metadata
		}

		if err := parseClientHelloBody(handshake[4:helloLength], &metadata); err != nil {
			metadata.ParseError = err.Error()
			return metadata
		}
		metadata.Complete = true
		metadata.NeedBytes = 0
		metadata.RecordNeedBytes = 0
		metadata.ClientHelloSize = helloLength
		consumedInRecord := helloLength - previousHandshakeBytes
		if consumedInRecord < 0 {
			consumedInRecord = 0
		}
		helloEnd := recordEnd - len(record) + consumedInRecord
		if helloEnd < 0 || helloEnd > len(input) {
			helloEnd = len(view)
		}
		metadata.TrailingDataBytes = len(input) - helloEnd
		if metadata.TrailingDataBytes < 0 {
			metadata.TrailingDataBytes = 0
		}
		return metadata
	}

	metadata.Incomplete(4)
	return metadata
}

func (m *TLSClientHelloMetadata) Incomplete(need int) {
	m.Complete = false
	if need < 1 {
		need = 1
	}
	m.NeedBytes = need
}

func appendBounded(dst, src []byte, limit int) []byte {
	if len(dst) >= limit {
		return dst
	}
	if len(src) > limit-len(dst) {
		src = src[:limit-len(dst)]
	}
	return append(dst, src...)
}

func minMetadataInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseClientHelloBody(body []byte, metadata *TLSClientHelloMetadata) error {
	p := 0
	legacyVersion, err := readMetadataU16(body, &p)
	if err != nil {
		return err
	}
	metadata.LegacyVersion = legacyVersion
	if !skipMetadata(body, &p, 32) {
		return errTLSMetadata("random")
	}
	if !skipMetadataVector8(body, &p) || !skipMetadataVector16(body, &p) || !skipMetadataVector8(body, &p) {
		return errTLSMetadata("ClientHello vector")
	}
	extensions, err := readMetadataVector16(body, &p)
	if err != nil {
		return errTLSMetadata("extensions")
	}
	if p != len(body) {
		return errTLSMetadata("trailing ClientHello body")
	}
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return errTLSMetadata("extension header")
		}
		extensionType := uint16(extensions[0])<<8 | uint16(extensions[1])
		extensionLength := int(extensions[2])<<8 | int(extensions[3])
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return errTLSMetadata("extension length")
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		switch extensionType {
		case 0x0000:
			host, err := parseMetadataSNI(extensionData)
			if err != nil {
				return err
			}
			if host != "" {
				metadata.SNI = host
			}
		case 0x0010:
			if err := parseMetadataALPN(extensionData, metadata); err != nil {
				return err
			}
		case 0x002b:
			if err := parseMetadataVersions(extensionData, metadata); err != nil {
				return err
			}
		case 0xfe0d, 0xfe0e, 0xfe0f:
			metadata.ECHPresent = true
		}
	}
	if len(metadata.SupportedVersions) > 0 {
		for _, version := range metadata.SupportedVersions {
			if version > metadata.MaxVersion {
				metadata.MaxVersion = version
			}
		}
	}
	if metadata.MaxVersion == 0 {
		metadata.MaxVersion = metadata.LegacyVersion
	}
	if metadata.ECHPresent && metadata.SNI != "" {
		metadata.ECHOuterName = metadata.SNI
	}
	return nil
}

func readMetadataU16(b []byte, p *int) (uint16, error) {
	if *p+2 > len(b) {
		return 0, errTLSMetadata("uint16")
	}
	v := uint16(b[*p])<<8 | uint16(b[*p+1])
	*p += 2
	return v, nil
}

func skipMetadata(b []byte, p *int, n int) bool {
	if n < 0 || *p+n > len(b) {
		return false
	}
	*p += n
	return true
}

func skipMetadataVector8(b []byte, p *int) bool {
	if *p >= len(b) {
		return false
	}
	return skipMetadata(b, p, 1+int(b[*p]))
}

func skipMetadataVector16(b []byte, p *int) bool {
	if *p+2 > len(b) {
		return false
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	return skipMetadata(b, p, 2+n)
}

func readMetadataVector16(b []byte, p *int) ([]byte, error) {
	if *p+2 > len(b) {
		return nil, errTLSMetadata("vector16 length")
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	*p += 2
	if *p+n > len(b) {
		return nil, errTLSMetadata("vector16 data")
	}
	v := b[*p : *p+n]
	*p += n
	return v, nil
}

func parseMetadataSNI(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errTLSMetadata("SNI list length")
	}
	listLength := int(data[0])<<8 | int(data[1])
	if listLength != len(data)-2 {
		return "", errTLSMetadata("SNI list bounds")
	}
	p := 2
	var host string
	for p < len(data) {
		if p+3 > len(data) {
			return "", errTLSMetadata("SNI entry")
		}
		nameType := data[p]
		nameLength := int(data[p+1])<<8 | int(data[p+2])
		p += 3
		if nameType != 0 || nameLength == 0 || p+nameLength > len(data) {
			return "", errTLSMetadata("SNI name bounds")
		}
		candidate := string(data[p : p+nameLength])
		if !validateSNI(candidate) {
			return "", errTLSMetadata("invalid SNI")
		}
		if host == "" {
			host = strings.ToLower(candidate)
		}
		p += nameLength
	}
	return host, nil
}

func parseMetadataALPN(data []byte, metadata *TLSClientHelloMetadata) error {
	if len(data) < 2 {
		return errTLSMetadata("ALPN list length")
	}
	listLength := int(data[0])<<8 | int(data[1])
	if listLength != len(data)-2 {
		return errTLSMetadata("ALPN list bounds")
	}
	p := 2
	for p < len(data) {
		length := int(data[p])
		p++
		if length == 0 || p+length > len(data) {
			return errTLSMetadata("ALPN entry bounds")
		}
		metadata.ALPN = append(metadata.ALPN, string(data[p:p+length]))
		p += length
	}
	return nil
}

func parseMetadataVersions(data []byte, metadata *TLSClientHelloMetadata) error {
	if len(data) < 1 {
		return errTLSMetadata("supported_versions length")
	}
	listLength := int(data[0])
	if listLength != len(data)-1 || listLength == 0 || listLength%2 != 0 {
		return errTLSMetadata("supported_versions bounds")
	}
	for p := 1; p < len(data); p += 2 {
		metadata.SupportedVersions = append(metadata.SupportedVersions, uint16(data[p])<<8|uint16(data[p+1]))
	}
	return nil
}

func errTLSMetadata(field string) error { return fmt.Errorf("malformed TLS ClientHello: %s", field) }

// parseClientHelloBodyPartial extracts available metadata from a truncated
// ClientHello body. It never fails on missing bytes: every structure is
// walked while enough data remains and parsing stops silently at the first
// shortage. A truncated SNI name is ignored rather than partially recorded.
// parseClientHelloBody remains the strict full-body path.
func parseClientHelloBodyPartial(body []byte, metadata *TLSClientHelloMetadata) {
	if len(body) < 2 {
		return
	}
	metadata.LegacyVersion = uint16(body[0])<<8 | uint16(body[1])
	p := 2
	if !skipMetadata(body, &p, 32) || !skipMetadataVector8(body, &p) || !skipMetadataVector16(body, &p) || !skipMetadataVector8(body, &p) {
		return
	}
	extensions, ok := partialReadMetadataVector16(body, &p)
	if !ok {
		return
	}
	for len(extensions) >= 4 {
		extensionType := uint16(extensions[0])<<8 | uint16(extensions[1])
		extensionLength := int(extensions[2])<<8 | int(extensions[3])
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			// Truncated extension data: the remaining prefix is not part of
			// this extension. Stop walking; metadata already collected (SNI,
			// supported versions) stays valid.
			break
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		switch extensionType {
		case 0x0000:
			if host, err := parseMetadataSNI(extensionData); err == nil && host != "" {
				metadata.SNI = host
			}
		case 0x0010:
			_ = parseMetadataALPN(extensionData, metadata)
		case 0x002b:
			_ = parseMetadataVersions(extensionData, metadata)
		case 0xfe0d, 0xfe0e, 0xfe0f:
			metadata.ECHPresent = true
		}
	}
	if len(metadata.SupportedVersions) > 0 {
		for _, version := range metadata.SupportedVersions {
			if version > metadata.MaxVersion {
				metadata.MaxVersion = version
			}
		}
	}
	if metadata.MaxVersion == 0 {
		metadata.MaxVersion = metadata.LegacyVersion
	}
	if metadata.ECHPresent && metadata.SNI != "" {
		metadata.ECHOuterName = metadata.SNI
	}
}

// partialReadMetadataVector16 returns the available prefix of a 16-bit
// length vector: the length prefix plus as much data as is present. ok is
// false only when the length prefix itself is missing.
func partialReadMetadataVector16(b []byte, p *int) ([]byte, bool) {
	if *p+2 > len(b) {
		return nil, false
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	*p += 2
	if n == 0 {
		return nil, true
	}
	avail := len(b) - *p
	if avail <= 0 {
		return nil, true
	}
	if avail > n {
		avail = n
	}
	v := b[*p : *p+avail]
	*p += avail
	return v, true
}
