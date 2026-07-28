// Package diagnostics contains bounded, passive diagnostic state. It never
// mutates traffic or starts an action merely because a failure signal arrived.
package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
)

type FailureSignal string

const (
	SignalConntrackUnreplied  FailureSignal = "conntrack_unreplied"
	SignalConntrackSynSent    FailureSignal = "conntrack_syn_sent"
	SignalClassifierAmbiguous FailureSignal = "classifier_ambiguous"
	SignalReassemblyAbort     FailureSignal = "reassembly_abort"
	SignalFlowRetry           FailureSignal = "flow_retry"
	SignalQueueDrop           FailureSignal = "queue_drop"
	SignalOffloadSuspicion    FailureSignal = "offload_suspicion"
	SignalProbeFailure        FailureSignal = "probe_failure"
)

type SuggestedAction string

const (
	ActionTrace        SuggestedAction = "trace"
	ActionPCAP         SuggestedAction = "pcap"
	ActionClientHello  SuggestedAction = "clienthello_capture"
	ActionDiscovery    SuggestedAction = "isolated_discovery"
	ActionIssueBundle  SuggestedAction = "issue_bundle"
	ActionScopedCanary SuggestedAction = "scoped_canary"
)

var (
	ErrFailureClientRequired = errors.New("failure candidate requires a source-scoped client")
	ErrFailureDestination    = errors.New("failure candidate requires a valid destination and protocol")
	ErrFailureUnknownSignal  = errors.New("unknown failure signal")
	ErrFailureTooFresh       = errors.New("SYN_SENT observation has not aged past the failure threshold")
)

type FailureEvidence struct {
	Source     string    `json:"source"`
	DomainID   string    `json:"domain_id,omitempty"`
	SetID      string    `json:"set_id,omitempty"`
	Confidence uint8     `json:"confidence"`
	ECH        bool      `json:"ech"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// FailureCandidate is the passive inbox model. Identifiers derived from DNS,
// QUIC and set evidence are redacted at insertion; raw packet bytes and clear
// ClientHello data are never retained here.
type FailureCandidate struct {
	ID               string               `json:"id"`
	Client           classifier.ClientKey `json:"client"`
	DestinationIP    netip.Addr           `json:"destination_ip"`
	DestinationPort  uint16               `json:"destination_port"`
	Protocol         uint8                `json:"protocol"`
	ConntrackState   string               `json:"conntrack_state,omitempty"`
	FirstSeen        time.Time            `json:"first_seen"`
	LastSeen         time.Time            `json:"last_seen"`
	ExpiresAt        time.Time            `json:"expires_at"`
	DNSCandidates    []FailureEvidence    `json:"dns_candidates,omitempty"`
	QUICCandidates   []FailureEvidence    `json:"quic_candidates,omitempty"`
	SetCandidates    []string             `json:"set_candidates,omitempty"`
	FlowRetries      int                  `json:"flow_retries"`
	SuggestedAction  SuggestedAction      `json:"suggested_action"`
	AvailableActions []SuggestedAction    `json:"available_actions"`
	Signals          []FailureSignal      `json:"signals"`
	Reasons          []string             `json:"reasons,omitempty"`
}

type FailureObservation struct {
	Signal          FailureSignal
	Client          classifier.ClientKey
	DestinationIP   netip.Addr
	DestinationPort uint16
	Protocol        uint8
	ConntrackState  string
	FirstSeen       time.Time
	ObservedAt      time.Time
	DNSCandidates   []classifier.Evidence
	QUICCandidates  []classifier.Evidence
	SetCandidates   []string
	FlowRetries     int
	Reason          string
}

type OffloadObservation struct {
	Client             classifier.ClientKey
	DestinationIP      netip.Addr
	DestinationPort    uint16
	Protocol           uint8
	ObservedAt         time.Time
	CounterSampleFresh bool
	Report             capture.OffloadReport
}

type InboxConfig struct {
	MaxCandidates           int
	MaxEvidencePerCandidate int
	MaxSetCandidates        int
	MaxSignals              int
	MaxReasons              int
	Retention               time.Duration
	MinSynSentAge           time.Duration
}

var DefaultInboxConfig = InboxConfig{
	MaxCandidates:           512,
	MaxEvidencePerCandidate: 16,
	MaxSetCandidates:        16,
	MaxSignals:              8,
	MaxReasons:              8,
	Retention:               2 * time.Minute,
	MinSynSentAge:           3 * time.Second,
}

type failureKey struct {
	Client          classifier.ClientKey
	DestinationIP   netip.Addr
	DestinationPort uint16
	Protocol        uint8
}

type FailureInbox struct {
	mu         sync.Mutex
	config     InboxConfig
	clock      clock.Clock
	candidates map[failureKey]*FailureCandidate
}

func NewFailureInbox(config InboxConfig, clk clock.Clock) *FailureInbox {
	defaults := DefaultInboxConfig
	if config.MaxCandidates <= 0 {
		config.MaxCandidates = defaults.MaxCandidates
	}
	if config.MaxCandidates > 4096 {
		config.MaxCandidates = 4096
	}
	if config.MaxEvidencePerCandidate <= 0 {
		config.MaxEvidencePerCandidate = defaults.MaxEvidencePerCandidate
	}
	if config.MaxEvidencePerCandidate > 64 {
		config.MaxEvidencePerCandidate = 64
	}
	if config.MaxSetCandidates <= 0 {
		config.MaxSetCandidates = defaults.MaxSetCandidates
	}
	if config.MaxSetCandidates > 64 {
		config.MaxSetCandidates = 64
	}
	if config.MaxSignals <= 0 {
		config.MaxSignals = defaults.MaxSignals
	}
	if config.MaxSignals > 32 {
		config.MaxSignals = 32
	}
	if config.MaxReasons <= 0 {
		config.MaxReasons = defaults.MaxReasons
	}
	if config.MaxReasons > 32 {
		config.MaxReasons = 32
	}
	if config.Retention <= 0 {
		config.Retention = defaults.Retention
	}
	if config.Retention > 24*time.Hour {
		config.Retention = 24 * time.Hour
	}
	if config.MinSynSentAge <= 0 {
		config.MinSynSentAge = defaults.MinSynSentAge
	}
	if config.MinSynSentAge > time.Minute {
		config.MinSynSentAge = time.Minute
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &FailureInbox{config: config, clock: clk, candidates: make(map[failureKey]*FailureCandidate, config.MaxCandidates)}
}

var defaultInbox = NewFailureInbox(DefaultInboxConfig, clock.RealClock{})

func Default() *FailureInbox { return defaultInbox }

func (i *FailureInbox) Observe(observation FailureObservation) (*FailureCandidate, error) {
	if i == nil {
		return nil, errors.New("failure inbox is nil")
	}
	if err := validateObservation(observation); err != nil {
		observability.Default().Metrics.Inc(observability.MetricFailureCandidateRejected, map[string]string{"reason": errorReason(err)}, 1)
		return nil, err
	}
	now := observation.ObservedAt
	if now.IsZero() {
		now = i.clock.Now()
	}
	if now.After(i.clock.Now()) {
		now = i.clock.Now()
	}
	firstSeen := observation.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	if firstSeen.After(now) {
		return nil, errors.New("failure observation first_seen is in the future")
	}
	if observation.Signal == SignalConntrackSynSent && now.Sub(firstSeen) < i.config.MinSynSentAge {
		return nil, ErrFailureTooFresh
	}
	key := makeFailureKey(observation)

	i.mu.Lock()
	defer i.mu.Unlock()
	i.pruneLocked(now)
	candidate, exists := i.candidates[key]
	if !exists {
		if len(i.candidates) >= i.config.MaxCandidates && !i.evictOldestLocked() {
			return nil, errors.New("failure inbox capacity is exhausted")
		}
		candidate = &FailureCandidate{
			ID:               failureID(key),
			Client:           key.Client,
			DestinationIP:    key.DestinationIP,
			DestinationPort:  key.DestinationPort,
			Protocol:         key.Protocol,
			ConntrackState:   normalizeConntrackState(observation.ConntrackState),
			FirstSeen:        firstSeen,
			LastSeen:         now,
			ExpiresAt:        firstSeen.Add(i.config.Retention),
			AvailableActions: allActions(),
		}
		i.candidates[key] = candidate
		observability.Default().Metrics.Inc(observability.MetricFailureCandidateObserved, map[string]string{"signal": string(observation.Signal)}, 1)
	} else {
		candidate.LastSeen = now
		if observation.ConntrackState != "" {
			candidate.ConntrackState = normalizeConntrackState(observation.ConntrackState)
		}
	}
	if observation.FlowRetries > candidate.FlowRetries {
		candidate.FlowRetries = observation.FlowRetries
	}
	candidate.SuggestedAction = suggestedAction(observation.Signal)
	appendUniqueSignal(candidate, observation.Signal, i.config.MaxSignals)
	appendBoundedReason(candidate, observation.Reason, i.config.MaxReasons)
	for _, setID := range observation.SetCandidates {
		appendSetCandidate(candidate, setID, i.config.MaxSetCandidates)
	}
	appendEvidence(observation.DNSCandidates, key, i.clock.Now(), candidate, i.config.MaxEvidencePerCandidate)
	appendEvidence(observation.QUICCandidates, key, i.clock.Now(), candidate, i.config.MaxEvidencePerCandidate)
	observability.Default().Trace.Record(observability.TraceEvent{
		ClientID: observability.RedactIdentifier(fmt.Sprintf("%v", candidate.Client)),
		FlowID:   candidate.ID,
		Kind:     "failure_candidate",
		Fields: map[string]string{
			"signal":           string(observation.Signal),
			"destination_id":   observability.RedactIdentifier(candidate.DestinationIP.String()),
			"candidate_id":     candidate.ID,
			"suggested_action": string(candidate.SuggestedAction),
			"dns_candidates":   fmt.Sprintf("%d", len(candidate.DNSCandidates)),
			"quic_candidates":  fmt.Sprintf("%d", len(candidate.QUICCandidates)),
		},
	})
	return cloneCandidate(candidate), nil
}

// ObserveOffload turns only a fresh, positive offload report into an inbox
// signal. Counter resets, stale snapshots and insufficient observations are
// intentionally ignored.
func (i *FailureInbox) ObserveOffload(observation OffloadObservation) (*FailureCandidate, error) {
	if !observation.CounterSampleFresh || !observation.Report.FlowOffloadBypassSuspected {
		return nil, nil
	}
	return i.Observe(FailureObservation{
		Signal:          SignalOffloadSuspicion,
		Client:          observation.Client,
		DestinationIP:   observation.DestinationIP,
		DestinationPort: observation.DestinationPort,
		Protocol:        observation.Protocol,
		ObservedAt:      observation.ObservedAt,
		Reason:          strings.Join(observation.Report.Reasons, "; "),
	})
}

// UpdateEvidence attaches a later DNS/QUIC observation to an existing failure
// key. It does not create a candidate, so normal DNS traffic cannot fill the
// inbox without a passive failure signal.
func (i *FailureInbox) UpdateEvidence(client classifier.ClientKey, destinationIP netip.Addr, destinationPort uint16, protocol uint8, evidence []classifier.Evidence) bool {
	if i == nil || client.IsZero() || !destinationIP.IsValid() {
		return false
	}
	now := i.clock.Now()
	key := failureKey{Client: normalizeClient(client), DestinationIP: destinationIP.Unmap(), DestinationPort: destinationPort, Protocol: protocol}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pruneLocked(now)
	candidate, ok := i.candidates[key]
	if !ok {
		return false
	}
	for _, item := range evidence {
		if item.Client != (classifier.ClientKey{}) && normalizeClient(item.Client) != key.Client {
			continue
		}
		if item.DestinationIP.IsValid() && item.DestinationIP.Unmap() != key.DestinationIP {
			continue
		}
		if item.DestinationPort != 0 && item.DestinationPort != key.DestinationPort || item.L4Proto != 0 && item.L4Proto != key.Protocol {
			continue
		}
		appendOneEvidence(candidate, item, now, i.config.MaxEvidencePerCandidate)
	}
	return true
}

func (i *FailureInbox) List(limit int) []FailureCandidate {
	if i == nil {
		return nil
	}
	now := i.clock.Now()
	i.mu.Lock()
	i.pruneLocked(now)
	out := make([]FailureCandidate, 0, len(i.candidates))
	for _, candidate := range i.candidates {
		out = append(out, *cloneCandidate(candidate))
	}
	i.mu.Unlock()
	sort.Slice(out, func(a, b int) bool {
		if !out[a].LastSeen.Equal(out[b].LastSeen) {
			return out[a].LastSeen.After(out[b].LastSeen)
		}
		return out[a].ID < out[b].ID
	})
	if limit <= 0 || limit > len(out) {
		limit = len(out)
	}
	return out[:limit]
}

func (i *FailureInbox) Len() int {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	i.pruneLocked(i.clock.Now())
	n := len(i.candidates)
	i.mu.Unlock()
	return n
}

func (i *FailureInbox) Clear() int {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	n := len(i.candidates)
	i.candidates = make(map[failureKey]*FailureCandidate, i.config.MaxCandidates)
	i.mu.Unlock()
	return n
}

func validateObservation(observation FailureObservation) error {
	if observation.Client.IsZero() {
		return ErrFailureClientRequired
	}
	if !observation.DestinationIP.IsValid() || observation.DestinationPort == 0 || (observation.Protocol != 6 && observation.Protocol != 17) {
		return ErrFailureDestination
	}
	if !validSignal(observation.Signal) {
		return ErrFailureUnknownSignal
	}
	return nil
}

func validSignal(signal FailureSignal) bool {
	switch signal {
	case SignalConntrackUnreplied, SignalConntrackSynSent, SignalClassifierAmbiguous, SignalReassemblyAbort,
		SignalFlowRetry, SignalQueueDrop, SignalOffloadSuspicion, SignalProbeFailure:
		return true
	default:
		return false
	}
}

func makeFailureKey(observation FailureObservation) failureKey {
	return failureKey{Client: normalizeClient(observation.Client), DestinationIP: observation.DestinationIP.Unmap(), DestinationPort: observation.DestinationPort, Protocol: observation.Protocol}
}

func normalizeClient(client classifier.ClientKey) classifier.ClientKey {
	client.SourceIP = client.SourceIP.Unmap()
	return client
}

func failureID(key failureKey) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v|%s|%d|%d", key.Client, key.DestinationIP, key.DestinationPort, key.Protocol)))
	return hex.EncodeToString(sum[:8])
}

func (i *FailureInbox) pruneLocked(now time.Time) {
	for key, candidate := range i.candidates {
		if !now.Before(candidate.ExpiresAt) {
			delete(i.candidates, key)
			observability.Default().Metrics.Inc(observability.MetricFailureCandidateExpired, nil, 1)
		}
	}
}

func (i *FailureInbox) evictOldestLocked() bool {
	var oldestKey failureKey
	var oldest time.Time
	found := false
	for key, candidate := range i.candidates {
		if !found || candidate.LastSeen.Before(oldest) {
			oldestKey, oldest, found = key, candidate.LastSeen, true
		}
	}
	if found {
		delete(i.candidates, oldestKey)
	}
	return found
}

func appendUniqueSignal(candidate *FailureCandidate, signal FailureSignal, max int) {
	for _, existing := range candidate.Signals {
		if existing == signal {
			return
		}
	}
	if len(candidate.Signals) < max {
		candidate.Signals = append(candidate.Signals, signal)
	}
}

func appendBoundedReason(candidate *FailureCandidate, reason string, max int) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	for _, existing := range candidate.Reasons {
		if existing == reason {
			return
		}
	}
	if len(candidate.Reasons) < max {
		candidate.Reasons = append(candidate.Reasons, reason)
	}
}

func appendSetCandidate(candidate *FailureCandidate, setID string, max int) {
	setID = observability.RedactIdentifier(setID)
	if setID == "" {
		return
	}
	for _, existing := range candidate.SetCandidates {
		if existing == setID {
			return
		}
	}
	if len(candidate.SetCandidates) < max {
		candidate.SetCandidates = append(candidate.SetCandidates, setID)
	}
}

func appendEvidence(values []classifier.Evidence, key failureKey, now time.Time, candidate *FailureCandidate, max int) {
	for _, evidence := range values {
		if evidence.Client != (classifier.ClientKey{}) && normalizeClient(evidence.Client) != key.Client {
			continue
		}
		if evidence.DestinationIP.IsValid() && evidence.DestinationIP.Unmap() != key.DestinationIP {
			continue
		}
		if evidence.DestinationPort != 0 && evidence.DestinationPort != key.DestinationPort || evidence.L4Proto != 0 && evidence.L4Proto != key.Protocol {
			continue
		}
		if evidence.Source != classifier.EvidenceDNSAnswer && evidence.Source != classifier.EvidenceDNSHTTPS && evidence.Source != classifier.EvidenceQUICSNI {
			continue
		}
		if evidence.ExpiresAt.IsZero() || now.Before(evidence.ExpiresAt) {
			appendOneEvidence(candidate, evidence, now, max)
		}
	}
}

func appendOneEvidence(candidate *FailureCandidate, evidence classifier.Evidence, now time.Time, max int) {
	item := FailureEvidence{Source: evidence.Source.String(), DomainID: observability.RedactDomain(evidence.Domain), SetID: observability.RedactIdentifier(evidence.SetID), Confidence: evidence.Confidence, ECH: evidence.ECHRelated, ExpiresAt: evidence.ExpiresAt}
	target := &candidate.DNSCandidates
	if evidence.Source == classifier.EvidenceQUICSNI {
		target = &candidate.QUICCandidates
	}
	for _, existing := range *target {
		if existing.Source == item.Source && existing.DomainID == item.DomainID && existing.SetID == item.SetID {
			return
		}
	}
	if len(*target) < max {
		*target = append(*target, item)
	}
	appendSetCandidate(candidate, evidence.SetID, max)
	_ = now
}

func suggestedAction(signal FailureSignal) SuggestedAction {
	switch signal {
	case SignalQueueDrop, SignalOffloadSuspicion:
		return ActionPCAP
	case SignalReassemblyAbort:
		return ActionClientHello
	case SignalFlowRetry:
		return ActionDiscovery
	case SignalProbeFailure:
		return ActionIssueBundle
	default:
		return ActionTrace
	}
}

func allActions() []SuggestedAction {
	return []SuggestedAction{ActionTrace, ActionPCAP, ActionClientHello, ActionDiscovery, ActionIssueBundle, ActionScopedCanary}
}

func cloneCandidate(in *FailureCandidate) *FailureCandidate {
	if in == nil {
		return nil
	}
	out := *in
	out.DNSCandidates = append([]FailureEvidence(nil), in.DNSCandidates...)
	out.QUICCandidates = append([]FailureEvidence(nil), in.QUICCandidates...)
	out.SetCandidates = append([]string(nil), in.SetCandidates...)
	out.AvailableActions = append([]SuggestedAction(nil), in.AvailableActions...)
	out.Signals = append([]FailureSignal(nil), in.Signals...)
	out.Reasons = append([]string(nil), in.Reasons...)
	return &out
}

func normalizeConntrackState(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) > 32 {
		value = value[:32]
	}
	return value
}

func errorReason(err error) string {
	switch {
	case errors.Is(err, ErrFailureClientRequired):
		return "client"
	case errors.Is(err, ErrFailureDestination):
		return "destination"
	case errors.Is(err, ErrFailureUnknownSignal):
		return "signal"
	default:
		return "invalid"
	}
}
