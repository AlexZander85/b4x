// Package lab provides a bounded, observe-only ClientHello laboratory. It
// consumes capture-boundary TCP segments and deliberately reuses the
// production classifier reassembler and TLS metadata parser.
package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/sni"
)

var (
	ErrCaptureSourceNil = errors.New("clienthello capture source is nil")
	ErrCaptureFilter    = errors.New("clienthello capture requires a selected client, IP, or MAC")
	ErrCaptureSegment   = errors.New("clienthello capture segment is outside the bounded TCP/443 filter")
	ErrRetentionFull    = errors.New("clienthello profile retention is full")
	ErrSourceClosed     = errors.New("clienthello capture source closed")
	ErrNoTraffic        = errors.New("clienthello capture observed no traffic")
)

type ClientFilter struct {
	Client classifier.ClientKey
	IP     netip.Addr
	MAC    [6]byte
	HasMAC bool
}

func (f ClientFilter) Validate() error {
	if f.Client.IsZero() && !f.IP.IsValid() && !f.HasMAC {
		return ErrCaptureFilter
	}
	if f.IP.IsValid() && !f.IP.Is4() && !f.IP.Is6() {
		return ErrCaptureFilter
	}
	if f.HasMAC && f.MAC == [6]byte{} {
		return ErrCaptureFilter
	}
	return nil
}

func (f ClientFilter) Match(client classifier.ClientKey) bool {
	client.SourceIP = client.SourceIP.Unmap()
	if !f.Client.IsZero() {
		want := f.Client
		want.SourceIP = want.SourceIP.Unmap()
		if client != want {
			return false
		}
	}
	if f.IP.IsValid() && client.SourceIP != f.IP.Unmap() {
		return false
	}
	return !f.HasMAC || client.SourceMAC == f.MAC
}

// CaptureSegment is the normalized output of the real capture source. It is
// intentionally packet-oriented but carries only fields needed by the
// production TCP reassembly contract; callers must not pass server-to-client
// packets here.
type CaptureSegment struct {
	At       time.Time
	Client   classifier.ClientKey
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Sequence uint32
	Flags    byte
	Payload  []byte
}

type SegmentSource interface {
	Receive(context.Context) (CaptureSegment, error)
}

type SegmentSink interface {
	Submit(CaptureSegment) bool
}

// ChannelSink is the bounded bridge from the NFQUEUE capture path to a lab
// session. A full channel drops only diagnostic capture; it never blocks or
// changes the production verdict path.
type ChannelSink struct {
	Segments   chan<- CaptureSegment
	MaxPayload int
}

func (s ChannelSink) Submit(segment CaptureSegment) bool {
	if s.Segments == nil {
		return false
	}
	maxPayload := s.MaxPayload
	if maxPayload <= 0 || maxPayload > classifier.TLSClientHelloBound() {
		maxPayload = classifier.TLSClientHelloBound()
	}
	if len(segment.Payload) > maxPayload {
		return false
	}
	segment.Payload = append([]byte(nil), segment.Payload...)
	select {
	case s.Segments <- segment:
		return true
	default:
		return false
	}
}

type SliceSource struct {
	Segments []CaptureSegment
	Index    int
}

func (s *SliceSource) Receive(context.Context) (CaptureSegment, error) {
	if s == nil || s.Index >= len(s.Segments) {
		return CaptureSegment{}, ErrSourceClosed
	}
	segment := s.Segments[s.Index]
	s.Index++
	return segment, nil
}

type ChannelSource struct {
	Segments <-chan CaptureSegment
}

func (s ChannelSource) Receive(ctx context.Context) (CaptureSegment, error) {
	if s.Segments == nil {
		return CaptureSegment{}, ErrSourceClosed
	}
	select {
	case <-ctx.Done():
		return CaptureSegment{}, ctx.Err()
	case segment, ok := <-s.Segments:
		if !ok {
			return CaptureSegment{}, ErrSourceClosed
		}
		return segment, nil
	}
}

type CaptureRequest struct {
	Filter             ClientFilter
	Duration           time.Duration
	MaxFlows           int
	MaxProfiles        int
	MaxBytesPerFlow    int
	MaxBytesTotal      int
	MaxSegmentsPerFlow int
	ConfigGeneration   uint64
	Source             string
	SourceApp          string
	Interface          string
	EnvelopeRole       capture.QueueRole
	Retention          ProfileRetention
	Clock              clock.Clock
}

func DefaultCaptureRequest() CaptureRequest {
	return CaptureRequest{Duration: 30 * time.Second, MaxFlows: 64, MaxProfiles: 64, MaxBytesPerFlow: 32 * 1024, MaxBytesTotal: 512 * 1024, MaxSegmentsPerFlow: 64, Source: "capture-envelope", Interface: "unknown", EnvelopeRole: capture.QueueRoleProduction, Clock: clock.RealClock{}}
}

func (r CaptureRequest) normalized() (CaptureRequest, error) {
	d := DefaultCaptureRequest()
	if err := r.Filter.Validate(); err != nil {
		return CaptureRequest{}, err
	}
	if r.Duration <= 0 {
		r.Duration = d.Duration
	}
	if r.Duration > 5*time.Minute {
		r.Duration = 5 * time.Minute
	}
	if r.MaxFlows <= 0 {
		r.MaxFlows = d.MaxFlows
	}
	if r.MaxFlows > 256 {
		r.MaxFlows = 256
	}
	if r.MaxProfiles <= 0 {
		r.MaxProfiles = d.MaxProfiles
	}
	if r.MaxProfiles > 256 {
		r.MaxProfiles = 256
	}
	if r.MaxBytesPerFlow <= 0 {
		r.MaxBytesPerFlow = d.MaxBytesPerFlow
	}
	if r.MaxBytesPerFlow > classifier.TLSClientHelloBound() {
		r.MaxBytesPerFlow = classifier.TLSClientHelloBound()
	}
	if r.MaxBytesTotal <= 0 {
		r.MaxBytesTotal = d.MaxBytesTotal
	}
	if r.MaxBytesTotal > 4*1024*1024 {
		r.MaxBytesTotal = 4 * 1024 * 1024
	}
	if r.MaxSegmentsPerFlow <= 0 {
		r.MaxSegmentsPerFlow = d.MaxSegmentsPerFlow
	}
	if r.MaxSegmentsPerFlow > 256 {
		r.MaxSegmentsPerFlow = 256
	}
	if len(r.Source) > 64 {
		r.Source = r.Source[:64]
	}
	if strings.TrimSpace(r.Source) == "" {
		r.Source = d.Source
	}
	if len(r.SourceApp) > 64 {
		r.SourceApp = r.SourceApp[:64]
	}
	if len(r.Interface) > 64 {
		r.Interface = r.Interface[:64]
	}
	if strings.TrimSpace(r.Interface) == "" {
		r.Interface = d.Interface
	}
	if r.Clock == nil {
		r.Clock = d.Clock
	}
	return r, nil
}

type ClientHelloMetadata struct {
	SNIHash           string   `json:"sni_hash,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	SupportedVersions []uint16 `json:"supported_versions,omitempty"`
	ECHPresent        bool     `json:"ech_present"`
	ECHOuterNameHash  string   `json:"ech_outer_name_hash,omitempty"`
	ClientHelloSize   int      `json:"clienthello_size"`
	RecordCount       int      `json:"record_count"`
	LegacyVersion     uint16   `json:"legacy_version"`
	MaxVersion        uint16   `json:"max_version"`
}

type CaptureProvenance struct {
	Source           string    `json:"source"`
	Interface        string    `json:"interface"`
	EnvelopeRole     string    `json:"envelope_role"`
	Parser           string    `json:"parser"`
	ConfigGeneration uint64    `json:"config_generation"`
	CapturedAt       time.Time `json:"captured_at"`
}

type ClientHelloProfile struct {
	ID              string              `json:"id"`
	FlowID          string              `json:"flow_id"`
	ClientID        string              `json:"client_id"`
	DestinationID   string              `json:"destination_id"`
	DestinationPort uint16              `json:"destination_port"`
	IPFamily        string              `json:"ip_family"`
	HelloHash       string              `json:"hello_hash"`
	SourceApp       string              `json:"source_app,omitempty"`
	ObservedDomain  string              `json:"observed_domain,omitempty"`
	TLSVersion      uint16              `json:"tls_version"`
	ALPN            []string            `json:"alpn,omitempty"`
	RawSize         int                 `json:"raw_size"`
	CompiledSize    int                 `json:"compiled_size,omitempty"`
	SHA256          string              `json:"sha256"`
	PrivacyState    string              `json:"privacy_state"`
	Metadata        ClientHelloMetadata `json:"metadata"`
	Provenance      CaptureProvenance   `json:"provenance"`
	FirstSeen       time.Time           `json:"first_seen"`
	CompletedAt     time.Time           `json:"completed_at"`
	PrivacySafe     bool                `json:"privacy_safe"`
}

// CapturedHelloProfile is the architecture-facing name used by the lab and
// future profile compiler. It aliases the privacy-safe capture artifact so no
// second mutable representation can drift from the capture result.
type CapturedHelloProfile = ClientHelloProfile

type CaptureResult struct {
	Profiles          []ClientHelloProfile `json:"profiles"`
	StartedAt         time.Time            `json:"started_at"`
	CompletedAt       time.Time            `json:"completed_at"`
	AcceptedSegments  int                  `json:"accepted_segments"`
	RejectedSegments  int                  `json:"rejected_segments"`
	DuplicateSegments int                  `json:"duplicate_segments"`
	CompletedFlows    int                  `json:"completed_flows"`
	RetentionErrors   []string             `json:"retention_errors,omitempty"`
	StopReason        string               `json:"stop_reason"`
	PrivacySafe       bool                 `json:"privacy_safe"`
}

type ProfileRetention interface {
	Store(ClientHelloProfile) error
}

type MemoryRetention struct {
	mu       sync.Mutex
	max      int
	profiles []ClientHelloProfile
}

func NewMemoryRetention(max int) *MemoryRetention {
	if max <= 0 {
		max = 256
	}
	if max > 256 {
		max = 256
	}
	return &MemoryRetention{max: max, profiles: make([]ClientHelloProfile, 0, max)}
}

func (r *MemoryRetention) Store(profile ClientHelloProfile) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.profiles {
		if existing.ID == profile.ID {
			return nil
		}
	}
	if len(r.profiles) >= r.max {
		copy(r.profiles, r.profiles[1:])
		r.profiles = r.profiles[:r.max-1]
	}
	r.profiles = append(r.profiles, profile)
	return nil
}

func (r *MemoryRetention) List() []ClientHelloProfile {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ClientHelloProfile(nil), r.profiles...)
}

type JSONLRetention struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
}

func (r *JSONLRetention) Store(profile ClientHelloProfile) error {
	if r == nil || strings.TrimSpace(r.Path) == "" {
		return nil
	}
	line, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	maxBytes := r.MaxBytes
	if maxBytes <= 0 || maxBytes > 16*1024*1024 {
		maxBytes = 4 * 1024 * 1024
	}
	stat, err := os.Stat(r.Path)
	if err == nil && stat.Size()+int64(len(line)) > maxBytes {
		return ErrRetentionFull
	}
	if !os.IsNotExist(err) && err != nil {
		return err
	}
	file, err := os.OpenFile(r.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(line)
	return err
}

func CaptureClientHellos(ctx context.Context, request CaptureRequest, source SegmentSource) (CaptureResult, error) {
	if source == nil {
		return CaptureResult{}, ErrCaptureSourceNil
	}
	request, err := request.normalized()
	if err != nil {
		return CaptureResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	started := request.Clock.Now()
	result := CaptureResult{StartedAt: started, PrivacySafe: true, Profiles: make([]ClientHelloProfile, 0, request.MaxProfiles)}
	ctx, cancel := context.WithTimeout(ctx, request.Duration)
	defer cancel()
	reassembly := classifier.NewTCPReassemblyStore(classifier.TCPReassemblyConfig{
		MaxFlows:        request.MaxFlows,
		MaxBytesPerFlow: request.MaxBytesPerFlow,
		MaxBytesTotal:   request.MaxBytesTotal,
		MaxSegments:     request.MaxSegmentsPerFlow,
		MaxClientHello:  request.MaxBytesPerFlow,
		Timeout:         request.Duration,
		Clock:           request.Clock,
	})
	completed := make(map[classifier.FlowKey]struct{}, request.MaxProfiles)
	firstSeen := make(map[classifier.FlowKey]time.Time, request.MaxFlows)
	for {
		segment, receiveErr := source.Receive(ctx)
		if receiveErr != nil {
			result.StopReason = stopReason(receiveErr, ctx)
			if errors.Is(receiveErr, ErrSourceClosed) || errors.Is(receiveErr, ErrNoTraffic) || errors.Is(receiveErr, context.DeadlineExceeded) || errors.Is(receiveErr, context.Canceled) {
				break
			}
			result.CompletedAt = request.Clock.Now()
			return result, receiveErr
		}
		if err := validateSegment(segment, request.Filter); err != nil {
			result.RejectedSegments++
			continue
		}
		result.AcceptedSegments++
		key := classifier.NewFlowKey(segment.Client, segment.SrcIP, segment.DstIP, segment.SrcPort, segment.DstPort, capture.ProtocolTCP)
		at := segment.At
		if at.IsZero() {
			at = request.Clock.Now()
		}
		if _, ok := firstSeen[key]; !ok {
			if len(firstSeen) >= request.MaxFlows {
				for oldKey := range firstSeen {
					delete(firstSeen, oldKey)
					break
				}
			}
			firstSeen[key] = at
		}
		reassembly.GC(at)
		if segment.Flags&classifier.TCPFlagSYN != 0 && segment.Flags&classifier.TCPFlagACK == 0 {
			reassembly.Start(key, segment.Sequence+1, request.ConfigGeneration)
			if len(segment.Payload) == 0 {
				continue
			}
		}
		if len(segment.Payload) == 0 {
			continue
		}
		payload := segment.Payload
		if len(payload) > request.MaxBytesPerFlow {
			result.RejectedSegments++
			continue
		}
		sequence := segment.Sequence
		if segment.Flags&classifier.TCPFlagSYN != 0 && segment.Flags&classifier.TCPFlagACK == 0 {
			sequence++
		}
		outcome := reassembly.Observe(key, sequence, payload, request.ConfigGeneration)
		if outcome.Duplicate {
			result.DuplicateSegments++
		}
		if outcome.Status != classifier.ReassemblyComplete {
			if outcome.Status == classifier.ReassemblyAborted && outcome.Metadata.ParseError != "" {
				result.RejectedSegments++
			}
			continue
		}
		if _, ok := completed[key]; ok {
			continue
		}
		if len(result.Profiles) >= request.MaxProfiles {
			result.StopReason = "profile-budget"
			break
		}
		completed[key] = struct{}{}
		profile, ok := makeProfile(reassembly, key, outcome, firstSeen[key], at, request)
		if !ok {
			continue
		}
		result.Profiles = append(result.Profiles, profile)
		result.CompletedFlows++
		if request.Retention != nil {
			if err := request.Retention.Store(profile); err != nil && len(result.RetentionErrors) < 8 {
				result.RetentionErrors = append(result.RetentionErrors, redactError(err))
			}
		}
	}
	if result.StopReason == "" {
		result.StopReason = "source_closed"
	}
	if result.AcceptedSegments == 0 && result.StopReason == "source-closed" {
		result.StopReason = "no-traffic"
	}
	result.CompletedAt = request.Clock.Now()
	sort.Slice(result.Profiles, func(a, b int) bool {
		if !result.Profiles[a].CompletedAt.Equal(result.Profiles[b].CompletedAt) {
			return result.Profiles[a].CompletedAt.Before(result.Profiles[b].CompletedAt)
		}
		return result.Profiles[a].ID < result.Profiles[b].ID
	})
	return result, nil
}

func validateSegment(segment CaptureSegment, filter ClientFilter) error {
	if !segment.Client.SourceIP.IsValid() || !filter.Match(segment.Client) || !segment.SrcIP.IsValid() || !segment.DstIP.IsValid() || segment.SrcPort == 0 || segment.DstPort != 443 || segment.SrcIP.Is4() != segment.DstIP.Is4() {
		return ErrCaptureSegment
	}
	return nil
}

func makeProfile(reassembly *classifier.TCPReassemblyStore, key classifier.FlowKey, outcome classifier.TCPReassemblyResult, firstSeen, completedAt time.Time, request CaptureRequest) (ClientHelloProfile, bool) {
	bytes, ok := reassembly.ClientHelloBytes(key)
	if !ok {
		return ClientHelloProfile{}, false
	}
	sum := sha256.Sum256(bytes)
	clear(bytes)
	metadata := outcome.Metadata
	flowID := hashIdentifier(fmt.Sprintf("%v", key))
	profileID := hashIdentifier(flowID + ":" + hex.EncodeToString(sum[:]))
	destinationIP, destinationPort := key.DstIP, key.DstPort
	if key.Client.SourceIP.IsValid() && key.SrcIP != key.Client.SourceIP {
		destinationIP, destinationPort = key.SrcIP, key.SrcPort
	}
	return ClientHelloProfile{
		ID:              profileID,
		FlowID:          flowID,
		ClientID:        hashIdentifier(fmt.Sprintf("%v", key.Client)),
		DestinationID:   hashIdentifier(destinationIP.String()),
		DestinationPort: destinationPort,
		IPFamily:        ipFamily(destinationIP),
		HelloHash:       hex.EncodeToString(sum[:]),
		SourceApp:       request.SourceApp,
		ObservedDomain:  observability.RedactDomain(metadata.SNI),
		TLSVersion:      metadata.MaxVersion,
		ALPN:            append([]string(nil), metadata.ALPN...),
		RawSize:         metadata.ClientHelloSize,
		SHA256:          hex.EncodeToString(sum[:]),
		PrivacyState:    "redacted-metadata-only",
		Metadata:        privacyMetadata(metadata),
		Provenance:      CaptureProvenance{Source: request.Source, Interface: request.Interface, EnvelopeRole: string(request.EnvelopeRole), Parser: "classifier.TCPReassemblyStore+sni.ParseTLSClientHelloMetadata", ConfigGeneration: request.ConfigGeneration, CapturedAt: completedAt},
		FirstSeen:       firstSeen,
		CompletedAt:     completedAt,
		PrivacySafe:     true,
	}, true
}

func privacyMetadata(metadata sni.TLSClientHelloMetadata) ClientHelloMetadata {
	out := ClientHelloMetadata{
		SNIHash:          observability.RedactDomain(metadata.SNI),
		ECHPresent:       metadata.ECHPresent,
		ECHOuterNameHash: observability.RedactDomain(metadata.ECHOuterName),
		ClientHelloSize:  metadata.ClientHelloSize,
		RecordCount:      metadata.RecordCount,
		LegacyVersion:    metadata.LegacyVersion,
		MaxVersion:       metadata.MaxVersion,
	}
	for _, alpn := range metadata.ALPN {
		if len(out.ALPN) >= 4 || len(alpn) > 32 {
			break
		}
		out.ALPN = append(out.ALPN, alpn)
	}
	for _, version := range metadata.SupportedVersions {
		if len(out.SupportedVersions) >= 8 {
			break
		}
		out.SupportedVersions = append(out.SupportedVersions, version)
	}
	return out
}

func hashIdentifier(value string) string {
	sum := sha256.Sum256([]byte("b4-lab:" + value))
	return hex.EncodeToString(sum[:8])
}

func ipFamily(address netip.Addr) string {
	if address.Is4() {
		return "ipv4"
	}
	if address.Is6() {
		return "ipv6"
	}
	return "unknown"
}

func stopReason(receiveErr error, ctx context.Context) string {
	switch {
	case errors.Is(receiveErr, ErrNoTraffic):
		return "no-traffic"
	case errors.Is(receiveErr, context.DeadlineExceeded):
		return "duration"
	case errors.Is(receiveErr, context.Canceled) && ctx.Err() != nil:
		return "canceled"
	default:
		return "source-closed"
	}
}

func redactError(err error) string {
	if err == nil {
		return ""
	}
	return observability.RedactIdentifier(err.Error())
}
