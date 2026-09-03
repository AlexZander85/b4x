package action

import "strings"

type LogicalMarkerKind string

const (
	MarkerClientHelloStart  LogicalMarkerKind = "clienthello-start"
	MarkerClientHelloEnd    LogicalMarkerKind = "clienthello-end"
	MarkerSNIExtensionStart LogicalMarkerKind = "sni-extension-start"
	MarkerHostStart         LogicalMarkerKind = "host-start"
	MarkerHostEnd           LogicalMarkerKind = "host-end"
	MarkerSLDMiddle         LogicalMarkerKind = "sld-middle"
)

type LogicalMarker struct {
	Kind      LogicalMarkerKind
	Offset    uint64
	Available bool
	Reason    string
}

type MarkerSet struct {
	Markers  []LogicalMarker
	Host     string
	ECH      bool
	Complete bool
	Reason   string
}

func (m MarkerSet) Find(kind LogicalMarkerKind) (LogicalMarker, bool) {
	for _, marker := range m.Markers {
		if marker.Kind == kind {
			return marker, marker.Available
		}
	}
	return LogicalMarker{Kind: kind, Reason: "marker not present"}, false
}

func (m MarkerSet) HostMarkersAvailable() bool {
	if m.ECH || m.Host == "" {
		return false
	}
	start, startOK := m.Find(MarkerHostStart)
	end, endOK := m.Find(MarkerHostEnd)
	return startOK && endOK && end.Offset > start.Offset
}

// DiscoverTLSMarkers locates semantic offsets in a bounded TLS ClientHello.
// It deliberately exposes no host marker for ECH-only or incomplete input.
func DiscoverTLSMarkers(input []byte) MarkerSet {
	const maxInput = 32 * 1024
	markers := MarkerSet{Markers: make([]LogicalMarker, 0, 6)}
	if len(input) > maxInput {
		input = input[:maxInput]
	}
	addUnavailable := func(kind LogicalMarkerKind, reason string) {
		markers.Markers = append(markers.Markers, LogicalMarker{Kind: kind, Reason: reason})
	}
	if len(input) < 9 || input[0] != 0x16 {
		markers.Reason = "not an accessible TLS handshake record"
		addUnavailable(MarkerClientHelloStart, markers.Reason)
		return markers
	}
	recordLength := int(input[3])<<8 | int(input[4])
	if recordLength > 16384 || 5+recordLength > len(input) {
		markers.Reason = "incomplete TLS record"
		addUnavailable(MarkerClientHelloStart, markers.Reason)
		return markers
	}
	if input[5] != 1 || recordLength < 4 {
		markers.Reason = "first handshake is not ClientHello"
		addUnavailable(MarkerClientHelloStart, markers.Reason)
		return markers
	}
	bodyLength := int(input[6])<<16 | int(input[7])<<8 | int(input[8])
	helloEnd := 5 + 4 + bodyLength
	if helloEnd > len(input) || helloEnd > 5+recordLength {
		markers.Reason = "incomplete ClientHello"
		markers.Markers = append(markers.Markers, LogicalMarker{Kind: MarkerClientHelloStart, Offset: 0, Available: true}, LogicalMarker{Kind: MarkerClientHelloEnd, Reason: markers.Reason})
		return markers
	}
	markers.Markers = append(markers.Markers,
		LogicalMarker{Kind: MarkerClientHelloStart, Offset: 0, Available: true},
		LogicalMarker{Kind: MarkerClientHelloEnd, Offset: uint64(helloEnd), Available: true},
	)
	body := input[9:helloEnd]
	p := 2 + 32
	if !skipMarkerVector8(body, &p) || !skipMarkerVector16(body, &p) || !skipMarkerVector8(body, &p) || p+2 > len(body) {
		markers.Reason = "malformed ClientHello vectors"
		return markers
	}
	extLength := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+extLength > len(body) {
		markers.Reason = "malformed ClientHello extensions"
		return markers
	}
	exts := body[p : p+extLength]
	extOffset := uint64(9 + p)
	for len(exts) >= 4 {
		extType := uint16(exts[0])<<8 | uint16(exts[1])
		extLen := int(exts[2])<<8 | int(exts[3])
		extHeaderOffset := extOffset
		exts = exts[4:]
		extOffset += 4
		if extLen > len(exts) {
			markers.Reason = "malformed extension length"
			return markers
		}
		data := exts[:extLen]
		if extType == 0xfe0d || extType == 0xfe0e || extType == 0xfe0f {
			markers.ECH = true
		}
		if extType == 0 && len(data) >= 5 {
			listLen := int(data[0])<<8 | int(data[1])
			nameLen := int(data[3])<<8 | int(data[4])
			if listLen == len(data)-2 && data[2] == 0 && 5+nameLen <= len(data) {
				markers.Host = strings.ToLower(string(data[5 : 5+nameLen]))
				markers.Markers = append(markers.Markers,
					LogicalMarker{Kind: MarkerSNIExtensionStart, Offset: extHeaderOffset, Available: true},
					LogicalMarker{Kind: MarkerHostStart, Offset: extHeaderOffset + 4 + 5, Available: true},
					LogicalMarker{Kind: MarkerHostEnd, Offset: extHeaderOffset + 4 + 5 + uint64(nameLen), Available: true},
				)
			}
		}
		exts = exts[extLen:]
		extOffset += uint64(extLen)
	}
	if markers.ECH && markers.Host == "" {
		markers.Reason = "ECH without clear host marker"
	}
	if markers.Host != "" && !markers.ECH {
		if start, ok := markers.Find(MarkerHostStart); ok {
			if middle, found := sldMiddle(markers.Host); found {
				markers.Markers = append(markers.Markers, LogicalMarker{Kind: MarkerSLDMiddle, Offset: start.Offset + uint64(middle), Available: true})
			}
		}
	}
	markers.Complete = true
	return markers
}

func skipMarkerVector8(b []byte, p *int) bool {
	if *p >= len(b) {
		return false
	}
	n := int(b[*p])
	*p = *p + 1
	if *p+n > len(b) {
		return false
	}
	*p += n
	return true
}

func skipMarkerVector16(b []byte, p *int) bool {
	if *p+2 > len(b) {
		return false
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	*p += 2
	if *p+n > len(b) {
		return false
	}
	*p += n
	return true
}

func sldMiddle(host string) (int, bool) {
	last := strings.LastIndexByte(host, '.')
	if last <= 0 {
		return 0, false
	}
	previous := strings.LastIndexByte(host[:last], '.')
	start := previous + 1
	if start >= last {
		return 0, false
	}
	return start + (last-start)/2, true
}
