package monitor

import (
	"fmt"
	"sync"
	"time"
)

type ResolvedEndpoint struct {
	IPHash       string
	IPFamily     string
	AddressIndex uint16
	TTL          uint32
}
type ClientResolutionSnapshot struct {
	SchemaVersion                                                            uint16
	SnapshotID, ClientKeyHash, NetworkContextID                              string
	ConfigGeneration                                                         uint64
	OriginalQNameHash, QueryIDHash, QueryType, ResolverID, ResolverTransport string
	CNAMEChainHashes                                                         []string
	Answers                                                                  []ResolvedEndpoint
	AnswerOrder                                                              []uint16
	TTLs                                                                     []uint32
	ObservedAt, ValidUntil                                                   time.Time
	ProvenanceRefs                                                           []string
}
type AddressOutcome struct {
	EndpointHash                                     string
	AddressIndex                                     uint16
	TCPOutcome, TLSOutcome, HTTPOutcome, QUICOutcome string
	LatencyMS                                        uint32
	UniqueBodyBytes                                  uint64
	Attribution                                      FailureAttribution
}

type MonitorSubject struct {
	SubjectID                                                string
	Scope                                                    MonitorScopeKey
	Origin                                                   string
	Enabled                                                  bool
	Priority                                                 uint8
	MonitoringPolicyID                                       string
	FirstObservedAt, LastObservedAt, LastDemandAt, ExpiresAt time.Time
	ResolutionRefs, DeclaredControls                         []string
	PrivacyClass                                             string
}
type ObservedDemandTarget struct {
	ObservationID, ClientKeyHash, DomainIdentityID, ServiceProfileID, ComponentID, ObservationSource, NetworkContextID string
	ConfigGeneration                                                                                                   uint64
	FirstObservedAt, LastObservedAt, ExpiresAt                                                                         time.Time
	ObservationCount                                                                                                   uint32
}

type IntakeConfig struct {
	MaxSubjects  int
	MaxPerClient int
}
type DemandInbox struct {
	mu          sync.Mutex
	cfg         IntakeConfig
	subjects    map[string]MonitorSubject
	demands     map[string]ObservedDemandTarget
	resolutions map[string]ClientResolutionSnapshot
	perClient   map[string]int
	next        uint64
}

func NewDemandInbox(cfg IntakeConfig) *DemandInbox {
	if cfg.MaxSubjects <= 0 {
		cfg.MaxSubjects = 2048
	}
	if cfg.MaxPerClient <= 0 {
		cfg.MaxPerClient = 32
	}
	return &DemandInbox{cfg: cfg, subjects: map[string]MonitorSubject{}, demands: map[string]ObservedDemandTarget{}, resolutions: map[string]ClientResolutionSnapshot{}, perClient: map[string]int{}}
}
func (s *DemandInbox) PutResolution(r ClientResolutionSnapshot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.SchemaVersion != SchemaVersion || r.SnapshotID == "" || r.ClientKeyHash == "" || r.NetworkContextID == "" || r.ConfigGeneration == 0 || r.ValidUntil.IsZero() {
		return false
	}
	r.Answers = append([]ResolvedEndpoint(nil), r.Answers...)
	r.CNAMEChainHashes = append([]string(nil), r.CNAMEChainHashes...)
	s.resolutions[r.SnapshotID] = r
	return true
}
func (s *DemandInbox) Resolution(id string, now time.Time) (ClientResolutionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resolutions[id]
	if !ok || !now.Before(r.ValidUntil) {
		return ClientResolutionSnapshot{}, false
	}
	r.Answers = append([]ResolvedEndpoint(nil), r.Answers...)
	return r, true
}
func (s *DemandInbox) Demand(d ObservedDemandTarget) (MonitorSubject, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ObservationID == "" || d.ClientKeyHash == "" || d.DomainIdentityID == "" || d.ConfigGeneration == 0 || d.ExpiresAt.IsZero() {
		return MonitorSubject{}, false
	}
	if old, ok := s.demands[d.DomainIdentityID+"|"+d.ClientKeyHash+"|"+d.ComponentID]; ok {
		old.LastObservedAt = d.LastObservedAt
		old.ObservationCount++
		s.demands[d.DomainIdentityID+"|"+d.ClientKeyHash+"|"+d.ComponentID] = old
		return s.subjects[old.ObservationID], true
	}
	if len(s.demands) >= s.cfg.MaxSubjects || s.perClient[d.ClientKeyHash] >= s.cfg.MaxPerClient {
		return MonitorSubject{}, false
	}
	s.next++
	id := fmt.Sprintf("demand-%d", s.next)
	d.ObservationID = id
	d.FirstObservedAt = d.LastObservedAt
	s.demands[d.DomainIdentityID+"|"+d.ClientKeyHash+"|"+d.ComponentID] = d
	s.perClient[d.ClientKeyHash]++
	sub := MonitorSubject{SubjectID: id, Origin: "observed-demand", Enabled: true, Priority: 1, FirstObservedAt: d.FirstObservedAt, LastObservedAt: d.LastObservedAt, LastDemandAt: d.LastObservedAt, ExpiresAt: d.ExpiresAt, PrivacyClass: "redacted"}
	s.subjects[id] = sub
	return sub, true
}
func (s *DemandInbox) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.demands) }
