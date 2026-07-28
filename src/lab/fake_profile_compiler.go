package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/sni"
)

type CompileMode string

const (
	CompileRawCaptured           CompileMode = "raw-captured"
	CompileCompactCompatible     CompileMode = "compact-compatible"
	CompileFingerprintPreserving CompileMode = "fingerprint-preserving"
	CompileSinglePacketSafe      CompileMode = "single-packet-safe"
	CompileMultiPacketFake       CompileMode = "multi-packet-fake"
)

var (
	ErrInvalidSourceArtifact = errors.New("invalid ClientHello source artifact")
	ErrMultiPacketDisabled   = errors.New("multi-packet fake profile is disabled until sequence-aware executor gates pass")
	ErrSNIAbsent             = errors.New("ClientHello has no structurally replaceable SNI")
	ErrInvalidReplacementSNI = errors.New("replacement SNI is invalid")
	ErrMTUExceeded           = errors.New("compiled ClientHello exceeds single-packet MTU budget")
	ErrCompiledInvalid       = errors.New("compiled ClientHello failed validation")
)

type RawClientHelloArtifact struct {
	ID         string
	Source     CapturedHelloProfile
	SHA256     string
	Provenance string
	bytes      []byte
}

// NewRawClientHelloArtifact is an explicit local artifact boundary. The input
// is copied, validated by the production parser, and never mutated by the
// compiler.
func NewRawClientHelloArtifact(id string, source CapturedHelloProfile, raw []byte, provenance string) (RawClientHelloArtifact, error) {
	if strings.TrimSpace(id) == "" || len(id) > 96 || len(raw) == 0 || len(raw) > sni.TLSClientHelloMetadataMaxBytes {
		return RawClientHelloArtifact{}, ErrInvalidSourceArtifact
	}
	metadata := sni.ParseTLSClientHelloMetadata(raw)
	if !metadata.Complete || metadata.ParseError != "" {
		return RawClientHelloArtifact{}, fmt.Errorf("%w: parser=%s", ErrInvalidSourceArtifact, metadata.ParseError)
	}
	copyBytes := append([]byte(nil), raw...)
	sum := sha256.Sum256(copyBytes)
	hash := hex.EncodeToString(sum[:])
	if source.HelloHash != "" && source.HelloHash != hash {
		return RawClientHelloArtifact{}, fmt.Errorf("%w: source hello hash mismatch", ErrInvalidSourceArtifact)
	}
	if source.SHA256 != "" && source.SHA256 != hash {
		return RawClientHelloArtifact{}, fmt.Errorf("%w: source hash mismatch", ErrInvalidSourceArtifact)
	}
	return RawClientHelloArtifact{ID: id, Source: source, SHA256: hash, Provenance: limitString(provenance, 128), bytes: copyBytes}, nil
}

func (a RawClientHelloArtifact) Validate() error {
	if strings.TrimSpace(a.ID) == "" || len(a.bytes) == 0 || len(a.bytes) > sni.TLSClientHelloMetadataMaxBytes {
		return ErrInvalidSourceArtifact
	}
	metadata := sni.ParseTLSClientHelloMetadata(a.bytes)
	if !metadata.Complete || metadata.ParseError != "" {
		return fmt.Errorf("%w: parser=%s", ErrInvalidSourceArtifact, metadata.ParseError)
	}
	if a.SHA256 != "" {
		sum := sha256.Sum256(a.bytes)
		if a.SHA256 != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("%w: artifact hash mismatch", ErrInvalidSourceArtifact)
		}
	}
	return nil
}

// Raw returns an explicit copy for local compile/export operations. The
// artifact itself remains immutable; callers own and must clear this copy.
func (a RawClientHelloArtifact) Raw() []byte { return append([]byte(nil), a.bytes...) }

type MTUEstimator struct {
	Family          string
	MTU             int
	TCPOptionsBytes int
}

func (e MTUEstimator) MaxPayload() (int, error) {
	mtu := e.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	if mtu < 576 || mtu > 9216 {
		return 0, fmt.Errorf("MTU %d is outside bounded Ethernet range", mtu)
	}
	options := e.TCPOptionsBytes
	if options < 0 || options > 40 {
		return 0, errors.New("TCP options exceed bounded header budget")
	}
	ipHeader := 0
	switch strings.ToLower(e.Family) {
	case "ipv4", "4":
		ipHeader = 20
	case "ipv6", "6":
		ipHeader = 40
	default:
		return 0, errors.New("IP family is required for MTU estimation")
	}
	payload := mtu - ipHeader - 20 - options
	if payload <= 0 {
		return 0, errors.New("MTU leaves no TCP payload budget")
	}
	return payload, nil
}

type CompileRequest struct {
	Source           RawClientHelloArtifact
	Mode             CompileMode
	ReplacementSNI   string
	RemoveExtensions []uint16
	RequiredALPN     []string
	AllowedVersions  []uint16
	MTU              MTUEstimator
	Seed             int64
	Provenance       string
}

type ExtensionChange struct {
	Type   uint16 `json:"type"`
	Action string `json:"action"`
}

type ChangeReport struct {
	Seed               int64             `json:"seed"`
	OriginalSHA256     string            `json:"original_sha256"`
	CompiledSHA256     string            `json:"compiled_sha256"`
	OriginalSNIHash    string            `json:"original_sni_hash,omitempty"`
	ReplacementSNIHash string            `json:"replacement_sni_hash,omitempty"`
	OriginalSize       int               `json:"original_size"`
	CompiledSize       int               `json:"compiled_size"`
	OriginalRecords    int               `json:"original_records"`
	CompiledRecords    int               `json:"compiled_records"`
	MaxPayload         int               `json:"max_payload"`
	FitsMTU            bool              `json:"fits_mtu"`
	Changed            bool              `json:"changed"`
	Extensions         []ExtensionChange `json:"extensions,omitempty"`
	Validation         string            `json:"validation"`
}

type CompiledProfile struct {
	ID               string       `json:"id"`
	SourceArtifactID string       `json:"source_artifact_id"`
	Mode             CompileMode  `json:"mode"`
	SHA256           string       `json:"sha256"`
	Size             int          `json:"size"`
	TLSVersion       uint16       `json:"tls_version"`
	ALPN             []string     `json:"alpn,omitempty"`
	ECHPresent       bool         `json:"ech_present"`
	MTUFits          bool         `json:"mtu_fits"`
	Active           bool         `json:"active"`
	Provenance       string       `json:"provenance"`
	ChangeReport     ChangeReport `json:"change_report"`
}

type CompiledArtifact struct {
	Profile CompiledProfile
	bytes   []byte
}

func (a CompiledArtifact) Bytes() []byte { return append([]byte(nil), a.bytes...) }

func CompileFakeProfile(request CompileRequest) (CompiledArtifact, error) {
	if err := request.Source.Validate(); err != nil {
		return CompiledArtifact{}, err
	}
	if err := validateCompileMode(request.Mode); err != nil {
		return CompiledArtifact{}, err
	}
	if request.ReplacementSNI != "" && !validSNI(request.ReplacementSNI) {
		return CompiledArtifact{}, ErrInvalidReplacementSNI
	}
	if request.Mode == CompileMultiPacketFake {
		return CompiledArtifact{}, ErrMultiPacketDisabled
	}
	input := request.Source.Raw()
	compiled, report, metadata, err := compileWire(input, request)
	clear(input)
	if err != nil {
		return CompiledArtifact{}, err
	}
	compiledHash := sha256.Sum256(compiled)
	report.CompiledSHA256 = hex.EncodeToString(compiledHash[:])
	report.CompiledSize = len(compiled)
	report.CompiledRecords = countTLSRecords(compiled)
	mtu := request.MTU
	if mtu.Family == "" {
		mtu.Family = request.Source.Source.IPFamily
	}
	maxPayload, err := mtu.MaxPayload()
	if err != nil {
		clear(compiled)
		return CompiledArtifact{}, err
	}
	report.MaxPayload = maxPayload
	report.FitsMTU = len(compiled) <= maxPayload
	if request.Mode == CompileSinglePacketSafe && !report.FitsMTU {
		clear(compiled)
		return CompiledArtifact{}, ErrMTUExceeded
	}
	if err := validateCompiled(compiled, request, metadata); err != nil {
		clear(compiled)
		return CompiledArtifact{}, err
	}
	report.Validation = "valid"
	profileHash := hashIdentifier(request.Source.ID + ":" + report.CompiledSHA256 + ":" + fmt.Sprintf("%d", request.Seed))
	profile := CompiledProfile{
		ID:               profileHash,
		SourceArtifactID: request.Source.ID,
		Mode:             request.Mode,
		SHA256:           report.CompiledSHA256,
		Size:             len(compiled),
		TLSVersion:       metadata.MaxVersion,
		ALPN:             append([]string(nil), metadata.ALPN...),
		ECHPresent:       metadata.ECHPresent,
		MTUFits:          report.FitsMTU,
		Active:           false,
		Provenance:       limitString(request.Provenance+";source="+request.Source.Provenance, 256),
		ChangeReport:     report,
	}
	return CompiledArtifact{Profile: profile, bytes: compiled}, nil
}

func ValidateCompiledProfile(artifact CompiledArtifact, request CompileRequest) error {
	if artifact.Profile.Active {
		return errors.New("compiled profile cannot be active from the compiler")
	}
	if len(artifact.bytes) == 0 || artifact.Profile.SHA256 == "" {
		return ErrCompiledInvalid
	}
	if err := request.Source.Validate(); err != nil {
		return err
	}
	if err := validateCompileMode(artifact.Profile.Mode); err != nil {
		return err
	}
	sum := sha256.Sum256(artifact.bytes)
	if artifact.Profile.SHA256 != hex.EncodeToString(sum[:]) {
		return ErrCompiledInvalid
	}
	metadata := sni.ParseTLSClientHelloMetadata(artifact.bytes)
	if artifact.Profile.Mode == CompileSinglePacketSafe && !artifact.Profile.MTUFits {
		return ErrMTUExceeded
	}
	return validateCompiled(artifact.bytes, request, metadata)
}

type tlsRecord struct {
	Type    byte
	Version [2]byte
	Payload []byte
}

type helloExtension struct {
	Type uint16
	Data []byte
}

func compileWire(input []byte, request CompileRequest) ([]byte, ChangeReport, sni.TLSClientHelloMetadata, error) {
	records, handshake, err := parseTLSRecords(input)
	if err != nil {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, err
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, fmt.Errorf("%w: first handshake is not ClientHello", ErrInvalidSourceArtifact)
	}
	bodyLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if bodyLength <= 0 || len(handshake) < 4+bodyLength {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, ErrInvalidSourceArtifact
	}
	body := handshake[4 : 4+bodyLength]
	parsed, err := parseHelloBody(body)
	if err != nil {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, err
	}
	report := ChangeReport{Seed: request.Seed, OriginalSHA256: request.Source.SHA256, OriginalSize: len(input), OriginalRecords: len(records), OriginalSNIHash: observability.RedactDomain(parsed.sni)}
	remove := make(map[uint16]struct{}, len(request.RemoveExtensions)+1)
	for _, extension := range request.RemoveExtensions {
		remove[extension] = struct{}{}
	}
	if request.Mode == CompileCompactCompatible || request.Mode == CompileSinglePacketSafe {
		remove[0x0015] = struct{}{} // padding
	}
	newExtensions := make([]helloExtension, 0, len(parsed.extensions))
	foundSNI := false
	for _, extension := range parsed.extensions {
		if _, excluded := remove[extension.Type]; excluded {
			report.Extensions = append(report.Extensions, ExtensionChange{Type: extension.Type, Action: "removed"})
			continue
		}
		data := append([]byte(nil), extension.Data...)
		if extension.Type == 0x0000 && request.ReplacementSNI != "" {
			data, err = replaceSNIExtension(data, request.ReplacementSNI)
			if err != nil {
				return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, err
			}
			foundSNI = true
			report.ReplacementSNIHash = observability.RedactDomain(request.ReplacementSNI)
			report.Extensions = append(report.Extensions, ExtensionChange{Type: extension.Type, Action: "sni-replaced"})
		}
		newExtensions = append(newExtensions, helloExtension{Type: extension.Type, Data: data})
	}
	if request.ReplacementSNI != "" && !foundSNI {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, ErrSNIAbsent
	}
	newBody := rebuildHelloBody(parsed.prefix, newExtensions)
	newHandshake := make([]byte, 4, 4+len(newBody)+len(handshake)-(4+bodyLength))
	newHandshake[0] = 1
	newHandshake[1] = byte(len(newBody) >> 16)
	newHandshake[2] = byte(len(newBody) >> 8)
	newHandshake[3] = byte(len(newBody))
	newHandshake = append(newHandshake, newBody...)
	newHandshake = append(newHandshake, handshake[4+bodyLength:]...)
	compiled := serializeTLSRecords(records, newHandshake)
	report.Changed = !bytes.Equal(input, compiled)
	metadata := sni.ParseTLSClientHelloMetadata(compiled)
	if !metadata.Complete || metadata.ParseError != "" {
		return nil, ChangeReport{}, sni.TLSClientHelloMetadata{}, fmt.Errorf("%w: parser=%s", ErrCompiledInvalid, metadata.ParseError)
	}
	return compiled, report, metadata, nil
}

type parsedHello struct {
	prefix     []byte
	extensions []helloExtension
	sni        string
}

func parseHelloBody(body []byte) (parsedHello, error) {
	if len(body) < 2+32+1+2+1+2 {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	pos := 0
	pos += 2 + 32
	if pos >= len(body) {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	sessionLength := int(body[pos])
	pos++
	if pos+sessionLength+2 > len(body) {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	pos += sessionLength
	cipherLength := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if cipherLength == 0 || cipherLength%2 != 0 || pos+cipherLength+1 > len(body) {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	pos += cipherLength
	compressionLength := int(body[pos])
	pos++
	if compressionLength == 0 || pos+compressionLength+2 > len(body) {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	pos += compressionLength
	extensionsLength := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extensionsLength != len(body) {
		return parsedHello{}, ErrInvalidSourceArtifact
	}
	prefix := append([]byte(nil), body[:pos-2]...)
	extensionBytes := body[pos : pos+extensionsLength]
	parsed := parsedHello{prefix: prefix, extensions: make([]helloExtension, 0, 16)}
	for offset := 0; offset < len(extensionBytes); {
		if len(extensionBytes)-offset < 4 {
			return parsedHello{}, ErrInvalidSourceArtifact
		}
		typ := binary.BigEndian.Uint16(extensionBytes[offset : offset+2])
		length := int(binary.BigEndian.Uint16(extensionBytes[offset+2 : offset+4]))
		offset += 4
		if length > len(extensionBytes)-offset {
			return parsedHello{}, ErrInvalidSourceArtifact
		}
		data := append([]byte(nil), extensionBytes[offset:offset+length]...)
		if typ == 0x0000 {
			parsed.sni = parseSNIExtension(data)
		}
		parsed.extensions = append(parsed.extensions, helloExtension{Type: typ, Data: data})
		offset += length
	}
	return parsed, nil
}

func rebuildHelloBody(prefix []byte, extensions []helloExtension) []byte {
	var ext bytes.Buffer
	for _, extension := range extensions {
		var header [4]byte
		binary.BigEndian.PutUint16(header[0:2], extension.Type)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(extension.Data)))
		ext.Write(header[:])
		ext.Write(extension.Data)
	}
	body := append([]byte(nil), prefix...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(ext.Len()))
	body = append(body, length[:]...)
	body = append(body, ext.Bytes()...)
	return body
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLength := int(binary.BigEndian.Uint16(data[:2]))
	if listLength != len(data)-2 {
		return ""
	}
	for offset := 2; offset < len(data); {
		if len(data)-offset < 3 {
			return ""
		}
		nameType := data[offset]
		nameLength := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if nameLength == 0 || offset+nameLength > len(data) {
			return ""
		}
		if nameType == 0 {
			return string(data[offset : offset+nameLength])
		}
		offset += nameLength
	}
	return ""
}

func replaceSNIExtension(data []byte, replacement string) ([]byte, error) {
	if parseSNIExtension(data) == "" {
		return nil, ErrSNIAbsent
	}
	host := []byte(replacement)
	list := make([]byte, 0, len(data)+len(host))
	list = append(list, 0, 0)
	replaced := false
	for offset := 2; offset < len(data); {
		nameType := data[offset]
		nameLength := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		name := data[offset : offset+nameLength]
		offset += nameLength
		if nameType == 0 && !replaced {
			name = host
			replaced = true
		}
		list = append(list, nameType, byte(len(name)>>8), byte(len(name)))
		list = append(list, name...)
	}
	binary.BigEndian.PutUint16(list[:2], uint16(len(list)-2))
	return list, nil
}

func parseTLSRecords(input []byte) ([]tlsRecord, []byte, error) {
	records := make([]tlsRecord, 0, 4)
	handshake := make([]byte, 0, len(input))
	for offset := 0; offset < len(input); {
		if len(input)-offset < 5 {
			return nil, nil, ErrInvalidSourceArtifact
		}
		length := int(binary.BigEndian.Uint16(input[offset+3 : offset+5]))
		if length > 16384 || offset+5+length > len(input) {
			return nil, nil, ErrInvalidSourceArtifact
		}
		record := tlsRecord{Type: input[offset], Version: [2]byte{input[offset+1], input[offset+2]}, Payload: append([]byte(nil), input[offset+5:offset+5+length]...)}
		records = append(records, record)
		if record.Type == 0x16 {
			handshake = append(handshake, record.Payload...)
		}
		offset += 5 + length
	}
	if len(records) == 0 || len(handshake) == 0 {
		return nil, nil, ErrInvalidSourceArtifact
	}
	return records, handshake, nil
}

func serializeTLSRecords(source []tlsRecord, handshake []byte) []byte {
	version := [2]byte{0x03, 0x03}
	if len(source) > 0 {
		version = source[0].Version
	}
	var out bytes.Buffer
	for len(handshake) > 0 {
		chunk := len(handshake)
		if chunk > 16384 {
			chunk = 16384
		}
		header := []byte{0x16, version[0], version[1], byte(chunk >> 8), byte(chunk)}
		out.Write(header)
		out.Write(handshake[:chunk])
		handshake = handshake[chunk:]
	}
	for _, record := range source {
		if record.Type == 0x16 {
			continue
		}
		length := len(record.Payload)
		if length > 16384 {
			length = 16384
		}
		out.Write([]byte{record.Type, record.Version[0], record.Version[1], byte(length >> 8), byte(length)})
		out.Write(record.Payload[:length])
	}
	return out.Bytes()
}

func validateCompiled(compiled []byte, request CompileRequest, metadata sni.TLSClientHelloMetadata) error {
	if !metadata.Complete || metadata.ParseError != "" {
		return ErrCompiledInvalid
	}
	if len(request.AllowedVersions) > 0 {
		allowed := make(map[uint16]struct{}, len(request.AllowedVersions))
		for _, version := range request.AllowedVersions {
			allowed[version] = struct{}{}
		}
		if _, ok := allowed[metadata.MaxVersion]; !ok {
			return fmt.Errorf("%w: TLS version %#x is not allowed", ErrCompiledInvalid, metadata.MaxVersion)
		}
	}
	if len(request.RequiredALPN) > 0 {
		for _, required := range request.RequiredALPN {
			found := false
			for _, actual := range metadata.ALPN {
				if actual == required {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: required ALPN %q is absent", ErrCompiledInvalid, required)
			}
		}
	}
	if len(compiled) == 0 {
		return ErrCompiledInvalid
	}
	return nil
}

func validateCompileMode(mode CompileMode) error {
	switch mode {
	case CompileRawCaptured, CompileCompactCompatible, CompileFingerprintPreserving, CompileSinglePacketSafe:
		return nil
	case CompileMultiPacketFake:
		return ErrMultiPacketDisabled
	default:
		return fmt.Errorf("unsupported fake profile compiler mode %q", mode)
	}
}

func validSNI(host string) bool {
	if host != strings.TrimSpace(host) {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n") {
		return false
	}
	if host != "localhost" && !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func countTLSRecords(input []byte) int {
	count := 0
	for offset := 0; offset+5 <= len(input); {
		length := int(binary.BigEndian.Uint16(input[offset+3 : offset+5]))
		if offset+5+length > len(input) {
			break
		}
		count++
		offset += 5 + length
	}
	return count
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func limitString(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
