// Package dnspath implements the canonical adaptive DNS path control model
// from B4X_POST_V23_ADAPTIVE_DNS_DETECTOR_PATH_CONTROLLER_AND_MANAGED_DNSCRYPT_BACKEND_ADDENDUM_v1.0.md.
//
// Object boundary (addendum §4): DNSObservation ≠ DNSPathProbeOutcome ≠
// DNSFailureHypothesis ≠ DNSPathProfile ≠ DiscoverySearchPrior ≠
// DNSPathCandidate ≠ DNSPathBinding ≠ TransportAuthorization ≠ promotion.
// No type in this package implicitly converts into another stage.
package dnspath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DNSOperatingMode is the user-facing DNS mode (addendum §19).
type DNSOperatingMode string

const (
	DNSModeCurrent    DNSOperatingMode = "current"
	DNSModeManual     DNSOperatingMode = "manual"
	DNSModeAdaptive   DNSOperatingMode = "adaptive"
	DNSModeDiagnostic DNSOperatingMode = "diagnostic-only"
)

func (m DNSOperatingMode) Valid() bool {
	switch m {
	case DNSModeCurrent, DNSModeManual, DNSModeAdaptive, DNSModeDiagnostic:
		return true
	}
	return false
}

// DNSPathFamily identifies the protocol family of a DNS path (addendum §24).
type DNSPathFamily string

const (
	DNSPathSystemForward      DNSPathFamily = "system-forward"
	DNSPathUDP                DNSPathFamily = "udp"
	DNSPathTCP                DNSPathFamily = "tcp"
	DNSPathTCPSegmented       DNSPathFamily = "tcp-segmented"
	DNSPathDoT                DNSPathFamily = "dot"
	DNSPathDoH                DNSPathFamily = "doh"
	DNSPathDoH3               DNSPathFamily = "doh3"
	DNSPathDoQ                DNSPathFamily = "doq"
	DNSPathDNSCrypt           DNSPathFamily = "dnscrypt"
	DNSPathPQDNSCrypt         DNSPathFamily = "pqdnscrypt"
	DNSPathAnonymizedDNSCrypt DNSPathFamily = "anonymized-dnscrypt"
	DNSPathODoH               DNSPathFamily = "odoh"
)

func (f DNSPathFamily) Valid() bool {
	switch f {
	case DNSPathSystemForward, DNSPathUDP, DNSPathTCP, DNSPathTCPSegmented,
		DNSPathDoT, DNSPathDoH, DNSPathDoH3, DNSPathDoQ,
		DNSPathDNSCrypt, DNSPathPQDNSCrypt, DNSPathAnonymizedDNSCrypt, DNSPathODoH:
		return true
	}
	return false
}

// Managed reports whether the family is served by the managed dnscrypt-proxy
// backend. DoT/DoQ are native by owner decision (ADR-ADNS-003) and are never
// attributed to the backend.
func (f DNSPathFamily) Managed() bool {
	switch f {
	case DNSPathDNSCrypt, DNSPathPQDNSCrypt, DNSPathAnonymizedDNSCrypt, DNSPathODoH:
		return true
	}
	return false
}

// Encrypted reports whether the family hides DNS traffic from the on-path
// observer.
func (f DNSPathFamily) Encrypted() bool {
	switch f {
	case DNSPathDoT, DNSPathDoH, DNSPathDoH3, DNSPathDoQ,
		DNSPathDNSCrypt, DNSPathPQDNSCrypt, DNSPathAnonymizedDNSCrypt, DNSPathODoH:
		return true
	}
	return false
}

// Complexity ranks families for the minimum-complexity preference
// (ADR-ADNS-014): simpler native paths beat managed/anonymized ones at equal
// correctness and stability.
func (f DNSPathFamily) Complexity() int {
	switch f {
	case DNSPathSystemForward:
		return 0
	case DNSPathUDP:
		return 1
	case DNSPathTCP:
		return 2
	case DNSPathTCPSegmented:
		return 3
	case DNSPathDoT:
		return 4
	case DNSPathDoH:
		return 5
	case DNSPathDoH3, DNSPathDoQ:
		return 6
	case DNSPathDNSCrypt:
		return 7
	case DNSPathPQDNSCrypt:
		return 8
	case DNSPathAnonymizedDNSCrypt:
		return 9
	case DNSPathODoH:
		return 10
	}
	return 100
}

// DNSPathID is the canonical path identity (addendum §24). Raw endpoint
// IP/domain is never used as a metric label; EndpointID/ResolverID are
// stable hashes.
type DNSPathID struct {
	Family          DNSPathFamily `json:"family"`
	ResolverID      string        `json:"resolver_id"`
	RelayID         string        `json:"relay_id,omitempty"`
	EndpointID      string        `json:"endpoint_id,omitempty"`
	IPFamily        string        `json:"ip_family"` // ipv4 | ipv6
	RouteBindingID  string        `json:"route_binding_id,omitempty"`
	ProviderVersion string        `json:"provider_version,omitempty"`
	CatalogVersion  string        `json:"catalog_version,omitempty"`
}

// Canonical returns the deterministic serialization of the path identity.
func (p DNSPathID) Canonical() string {
	return strings.Join([]string{
		string(p.Family), p.ResolverID, p.RelayID, p.EndpointID,
		p.IPFamily, p.RouteBindingID, p.ProviderVersion, p.CatalogVersion,
	}, "|")
}

// Hash returns the stable short hash of the canonical identity.
func (p DNSPathID) Hash() string {
	sum := sha256.Sum256([]byte(p.Canonical()))
	return hex.EncodeToString(sum[:8])
}

func (p DNSPathID) Valid() bool {
	if !p.Family.Valid() || p.ResolverID == "" {
		return false
	}
	if p.IPFamily != "ipv4" && p.IPFamily != "ipv6" {
		return false
	}
	// Anonymized paths must bind both resolver and relay identities.
	if (p.Family == DNSPathAnonymizedDNSCrypt || p.Family == DNSPathODoH) && p.RelayID == "" {
		return false
	}
	return true
}

// SamePathAlias reports whether two IDs are aliases of the same causal path:
// identical family+resolver+endpoint+route, ignoring catalog/provider version
// noise. Used to reject non-diverse fallback ladders (addendum §27.7).
func (p DNSPathID) SamePathAlias(o DNSPathID) bool {
	return p.Family == o.Family &&
		p.ResolverID == o.ResolverID &&
		p.RelayID == o.RelayID &&
		p.EndpointID == o.EndpointID &&
		p.RouteBindingID == o.RouteBindingID
}

// CapabilityState is the provider capability state machine (addendum §41).
type CapabilityState string

const (
	CapUnknown              CapabilityState = "UNKNOWN"
	CapUnsupported          CapabilityState = "UNSUPPORTED"
	CapAvailable            CapabilityState = "AVAILABLE"
	CapReady                CapabilityState = "READY"
	CapDegraded             CapabilityState = "DEGRADED"
	CapStale                CapabilityState = "STALE"
	CapFailed               CapabilityState = "FAILED"
	CapBlockedByPolicy      CapabilityState = "BLOCKED_BY_POLICY"
	CapBlockedByDependency  CapabilityState = "BLOCKED_BY_DEPENDENCY"
	CapBlockedByCapability  CapabilityState = "BLOCKED_BY_CAPABILITY"
	CapBlockedByBootstrap   CapabilityState = "BLOCKED_BOOTSTRAP"
	CapRepresentationUnknown CapabilityState = "BLOCKED_REPRESENTATION_UNKNOWN"
)

// Terminal reports whether the state can never be promoted to READY without
// new external evidence (addendum §41: UNSUPPORTED/SKIPPED/MISSING/STALE
// never convert to READY).
func (s CapabilityState) Terminal() bool {
	switch s {
	case CapUnsupported, CapStale, CapBlockedByPolicy, CapBlockedByCapability:
		return true
	}
	return false
}

// OutcomeClass is the normalized probe outcome class (addendum §58).
type OutcomeClass string

const (
	OutcomePassCorrect            OutcomeClass = "PASS_CORRECT"
	OutcomePassDifferentButValid  OutcomeClass = "PASS_DIFFERENT_BUT_VALID"
	OutcomeTimeout                OutcomeClass = "TIMEOUT"
	OutcomeConnectionRefused      OutcomeClass = "CONNECTION_REFUSED"
	OutcomeTLSCertFailure         OutcomeClass = "TLS_CERT_FAILURE"
	OutcomeTLSAlert               OutcomeClass = "TLS_ALERT"
	OutcomeHTTPStatusFailure      OutcomeClass = "HTTP_STATUS_FAILURE"
	OutcomeQUICUnavailable        OutcomeClass = "QUIC_UNAVAILABLE"
	OutcomeMalformedDNS           OutcomeClass = "MALFORMED_DNS"
	OutcomeQuestionMismatch       OutcomeClass = "QUESTION_MISMATCH"
	OutcomeRCodeMismatch          OutcomeClass = "RCODE_MISMATCH"
	OutcomeAnswerConflict         OutcomeClass = "ANSWER_CONFLICT"
	OutcomeEarlyInjectionSuspected OutcomeClass = "EARLY_INJECTION_SUSPECTED"
	OutcomeTruncatedRequiresTCP   OutcomeClass = "TRUNCATED_REQUIRES_TCP"
	OutcomeDNSSECInvalid          OutcomeClass = "DNSSEC_INVALID"
	OutcomeResolverPolicyFiltered OutcomeClass = "RESOLVER_POLICY_FILTERED"
	OutcomeCacheStale             OutcomeClass = "CACHE_STALE"
	OutcomeInconclusive           OutcomeClass = "INCONCLUSIVE"
	OutcomeObserverUnavailable    OutcomeClass = "OBSERVER_UNAVAILABLE"
)

// Pass reports whether the outcome carries usable correctness evidence.
func (c OutcomeClass) Pass() bool {
	return c == OutcomePassCorrect || c == OutcomePassDifferentButValid
}

// TransportStage names the explicit stage an encrypted path reached
// (addendum §62). Connect/TLS success is not DNS success.
type TransportStage string

const (
	StageRouteBootstrap TransportStage = "route_bootstrap"
	StageConnect        TransportStage = "connect"
	StageTLS            TransportStage = "tls"
	StageHTTP           TransportStage = "http"
	StageDNSMessage     TransportStage = "dns_message"
	StageAnswer         TransportStage = "answer_correctness"
	StageControl        TransportStage = "control_comparison"
)

// DNSPathProbeOutcome is the normalized outcome of one probe attempt
// (addendum §25).
type DNSPathProbeOutcome struct {
	PathID       DNSPathID `json:"path_id"`
	QuerySuiteID string    `json:"query_suite_id"`
	Attempt      uint16    `json:"attempt"`

	Stage      TransportStage `json:"transport_stage"`
	Class      OutcomeClass   `json:"response_class"`
	RCode      int            `json:"rcode"`
	Truncated  bool           `json:"truncated"`
	DNSSECState string        `json:"dnssec_state,omitempty"`

	AnswerFingerprint string `json:"answer_fingerprint,omitempty"`
	CNAMEFingerprint  string `json:"cname_fingerprint,omitempty"`
	HTTPSFingerprint  string `json:"https_fingerprint,omitempty"`

	Latency            time.Duration `json:"latency"`
	ResponseCount      uint16        `json:"response_count"`
	ArrivalOrderDigest string        `json:"arrival_order_digest,omitempty"`

	FailureCode  string   `json:"failure_code,omitempty"`
	Attribution  string   `json:"attribution,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// DNSPathExclusion records why a path is excluded from the profile.
type DNSPathExclusion struct {
	Path         DNSPathID `json:"path"`
	Reason       string    `json:"reason"`
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
}

// ConfidenceSummary aggregates support/contradiction counts (addendum §26).
type ConfidenceSummary struct {
	Score          float64 `json:"score"`
	Supports       int     `json:"supports"`
	Contradictions int     `json:"contradictions"`
}

// Profile status values.
const (
	ProfileStatusDraft     = "draft"
	ProfileStatusReady     = "ready"
	ProfileStatusStale     = "stale"
	ProfileStatusExpired   = "expired"
	ProfileStatusInvalid   = "invalid"
)

// DNSPathProfile is the single new persisted diagnostic/runtime profile
// payload (addendum §26). CandidateOutcomes and Exclusions are nested
// records, not competing profile stores.
type DNSPathProfile struct {
	ProfileID        string `json:"profile_id"`
	Status           string `json:"status"`
	NetworkContextID string `json:"network_context_id"`
	ConfigGeneration uint64 `json:"config_generation"`
	RuntimeEpoch     string `json:"runtime_epoch"`

	SourceBlockingProfileID string `json:"source_blocking_profile_id,omitempty"`
	QuerySuiteVersion       string `json:"query_suite_version"`
	ResolverCatalogVersion  string `json:"resolver_catalog_version"`
	PolicyDigest            string `json:"policy_digest"`

	CandidateOutcomes []DNSPathProbeOutcome `json:"candidate_outcomes"`
	Primary           DNSPathID             `json:"primary"`
	Fallbacks         []DNSPathID           `json:"fallbacks,omitempty"`
	Excluded          []DNSPathExclusion    `json:"excluded,omitempty"`

	PoisoningDetected    bool `json:"poisoning_detected"`
	InjectionDetected    bool `json:"injection_detected"`
	UDPDropDetected      bool `json:"udp_drop_detected"`
	Port53Blocked        bool `json:"port53_blocked"`
	EncryptedPathBlocked bool `json:"encrypted_path_blocked"`
	ResolverSpecific     bool `json:"resolver_specific"`
	IPFamilySpecific     bool `json:"ip_family_specific"`

	Confidence  ConfidenceSummary `json:"confidence"`
	CreatedAt   time.Time         `json:"created_at"`
	ValidatedAt time.Time         `json:"validated_at"`
	ValidUntil  time.Time         `json:"valid_until"`
	ContentHash string            `json:"content_hash"`
}

// KnownSuiteVersions and KnownCatalogVersions are populated by the registry;
// the profile validity check refuses unknown versions (addendum §27.3).
var (
	KnownSuiteVersions   = map[string]bool{"adns-suite-v1": true}
	KnownCatalogVersions = map[string]bool{}
)

// CanonicalPayload returns the deterministic JSON payload used for the
// content hash (ContentHash field excluded).
func (p *DNSPathProfile) CanonicalPayload() ([]byte, error) {
	cp := *p
	cp.ContentHash = ""
	// json.Marshal of a struct is field-order deterministic; sort slices whose
	// order is not semantically significant for identity.
	sort.Slice(cp.Excluded, func(i, j int) bool {
		return cp.Excluded[i].Path.Canonical() < cp.Excluded[j].Path.Canonical()
	})
	return json.Marshal(cp)
}

// ComputeContentHash recomputes the canonical content hash.
func (p *DNSPathProfile) ComputeContentHash() (string, error) {
	payload, err := p.CanonicalPayload()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// Seal recomputes and stores the content hash.
func (p *DNSPathProfile) Seal() error {
	h, err := p.ComputeContentHash()
	if err != nil {
		return err
	}
	p.ContentHash = h
	return nil
}

// Valid implements the ten-point validity contract (addendum §27).
func (p *DNSPathProfile) Valid(now time.Time) error {
	if p.ProfileID == "" {
		return errors.New("profile id required")
	}
	if p.Status != ProfileStatusReady {
		return fmt.Errorf("profile status %q is not ready", p.Status)
	}
	if p.NetworkContextID == "" || p.ConfigGeneration == 0 || p.RuntimeEpoch == "" {
		return errors.New("scope/network context/generation/epoch incomplete")
	}
	if !KnownSuiteVersions[p.QuerySuiteVersion] {
		return fmt.Errorf("unknown query suite version %q", p.QuerySuiteVersion)
	}
	if len(KnownCatalogVersions) > 0 && !KnownCatalogVersions[p.ResolverCatalogVersion] {
		return fmt.Errorf("unknown resolver catalog version %q", p.ResolverCatalogVersion)
	}
	if !p.Primary.Valid() {
		return errors.New("primary path identity invalid")
	}
	// 4-6: primary and fallbacks must appear among validated candidate
	// outcomes with passing correctness.
	passing := map[string]bool{}
	for _, o := range p.CandidateOutcomes {
		if o.Class.Pass() {
			passing[o.PathID.Hash()] = true
		}
	}
	if !passing[p.Primary.Hash()] {
		return errors.New("primary missing from validated passing candidate outcomes")
	}
	for _, fb := range p.Fallbacks {
		if !fb.Valid() {
			return fmt.Errorf("fallback identity invalid: %s", fb.Canonical())
		}
		if !passing[fb.Hash()] {
			return fmt.Errorf("fallback %s missing passing outcome", fb.Family)
		}
		// 7: fallbacks must not be aliases of one path or of the primary.
		if fb.SamePathAlias(p.Primary) {
			return fmt.Errorf("fallback %s is an alias of primary", fb.Family)
		}
	}
	for i := 0; i < len(p.Fallbacks); i++ {
		for j := i + 1; j < len(p.Fallbacks); j++ {
			if p.Fallbacks[i].SamePathAlias(p.Fallbacks[j]) {
				return errors.New("fallbacks are identical aliases of one path")
			}
		}
	}
	// 8: expiry/staleness.
	if p.Status == ProfileStatusStale || p.Status == ProfileStatusExpired {
		return errors.New("profile stale or expired")
	}
	if !p.ValidUntil.IsZero() && !now.Before(p.ValidUntil) {
		return errors.New("profile expired")
	}
	// 9: content hash must match canonical payload.
	want, err := p.ComputeContentHash()
	if err != nil {
		return err
	}
	if p.ContentHash == "" || p.ContentHash != want {
		return errors.New("content hash mismatch")
	}
	return nil
}

// MarkStale transitions the profile to STALE (WAN change, generation change,
// provider binary change — addendum §23).
func (p *DNSPathProfile) MarkStale() error {
	if err := p.Seal(); err != nil {
		return err
	}
	p.Status = ProfileStatusStale
	return p.Seal()
}

// DNSCachePartitionKey isolates cache entries by context/generation/path
// (addendum §29). Cached positive answers from an old path/generation are
// never fresh proof for a new one.
type DNSCachePartitionKey struct {
	NetworkContextID string `json:"network_context_id"`
	ConfigGeneration uint64  `json:"config_generation"`
	PathHash         string  `json:"path_hash"`
	QueryNameHash    string  `json:"query_name_hash"`
	QType            uint16  `json:"qtype"`
	DNSSECPolicy     string  `json:"dnssec_policy"`
	ClientScopeClass string  `json:"client_scope_class"`
}

// String returns the canonical partition key string.
func (k DNSCachePartitionKey) String() string {
	return fmt.Sprintf("%s/%d/%s/%s/%d/%s/%s",
		k.NetworkContextID, k.ConfigGeneration, k.PathHash,
		k.QueryNameHash, k.QType, k.DNSSECPolicy, k.ClientScopeClass)
}

// HashQName produces the privacy-preserving query name hash used in cache
// keys and diagnostics. Raw qnames are never exported (addendum §50).
func HashQName(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSuffix(name, "."))))
	return hex.EncodeToString(sum[:8])
}

// DNSPathBinding is runtime state, not a second diagnostic profile
// (addendum §30).
type DNSPathBinding struct {
	BindingID        string      `json:"binding_id"`
	Scope            string      `json:"scope"`
	ProfileID        string      `json:"profile_id"`
	Primary          DNSPathID   `json:"primary"`
	Fallbacks        []DNSPathID `json:"fallbacks,omitempty"`
	ConfigGeneration uint64      `json:"config_generation"`
	RuntimeEpoch     string      `json:"runtime_epoch"`
	PreparedAt       time.Time   `json:"prepared_at"`
	PromotedAt       time.Time   `json:"promoted_at,omitempty"`
	ValidUntil       time.Time   `json:"valid_until"`
}

// Promoted reports whether the binding has been atomically promoted.
func (b *DNSPathBinding) Promoted() bool { return !b.PromotedAt.IsZero() }

// CompatibleWith reports whether the binding still matches the live
// generation/epoch and has not expired.
func (b *DNSPathBinding) CompatibleWith(generation uint64, epoch string, now time.Time) bool {
	if b.ConfigGeneration != generation || b.RuntimeEpoch != epoch {
		return false
	}
	if !b.ValidUntil.IsZero() && !now.Before(b.ValidUntil) {
		return false
	}
	return true
}
