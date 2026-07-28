package config

const ClassifierAPIV23 = "b4.classifier.v2.3"

const (
	PrivacyTelemetryRedacted = "redacted"
	PrivacyTelemetryLocal    = "local"
	PrivacyTelemetryOff      = "off"

	FallbackDirect  = "direct"
	FallbackGeneric = "generic"
	FallbackProxy   = "proxy"
)

// ClassifierRuntimeConfig is the persisted, versioned control plane for the
// classifier/action/discovery pipeline. Runtime packages consume immutable
// snapshots derived from these values; they must not retain pointers to it.
type ClassifierRuntimeConfig struct {
	ClientIdentity ClientIdentityRuntimeConfig `json:"client_identity"`
	Confidence     ConfidenceRuntimeConfig     `json:"confidence"`
	Hints          HintStoreRuntimeConfig      `json:"hints"`
	Capture        CaptureRuntimeConfig        `json:"capture"`
	Reassembly     ReassemblyRuntimeConfig     `json:"reassembly"`
	HoldReplay     HoldReplayRuntimeConfig     `json:"hold_replay"`
	Actions        ActionBudgetRuntimeConfig   `json:"actions"`
	Discovery      DiscoveryRuntimeConfig      `json:"discovery"`
	FailureInbox   FailureInboxRuntimeConfig   `json:"failure_inbox"`
	ClientHelloLab ClientHelloLabRuntimeConfig `json:"clienthello_lab"`
	Rollout        RolloutRuntimeConfig        `json:"rollout"`
	Strategies     StrategyCatalogConfig       `json:"strategies"`
	Fallback       FallbackRuntimeConfig       `json:"fallback"`
	Privacy        PrivacyRuntimeConfig        `json:"privacy"`
}

type ClientIdentityRuntimeConfig struct {
	MaxEntries        int  `json:"max_entries"`
	TTLSeconds        int  `json:"ttl_seconds"`
	AllowIPOnly       bool `json:"allow_ip_only"`
	LateARPEnrichment bool `json:"late_arp_enrichment"`
}

type ConfidenceRuntimeConfig struct {
	Classify      uint8 `json:"classify"`
	Mutate        uint8 `json:"mutate"`
	Destructive   uint8 `json:"destructive"`
	ProxyFallback uint8 `json:"proxy_fallback"`
}

type HintStoreRuntimeConfig struct {
	MaxEntries          int `json:"max_entries"`
	MaxEntriesPerClient int `json:"max_entries_per_client"`
	MaxCandidatesPerKey int `json:"max_candidates_per_key"`
	MaxBytesPerClient   int `json:"max_bytes_per_client"`
	DNSMaxTTLSeconds    int `json:"dns_max_ttl_seconds"`
	QUICTTLSeconds      int `json:"quic_ttl_seconds"`
	LearnedTTLSeconds   int `json:"learned_ttl_seconds"`
}

type CaptureRuntimeConfig struct {
	OutgoingPacketLimit  uint32 `json:"outgoing_packet_limit"`
	IncomingPacketLimit  uint32 `json:"incoming_packet_limit"`
	AlwaysQueueSynAck    bool   `json:"always_queue_syn_ack"`
	AlwaysQueueFIN       bool   `json:"always_queue_fin"`
	AlwaysQueueRST       bool   `json:"always_queue_rst"`
	AlwaysQueueQUIC      bool   `json:"always_queue_quic_initial"`
	ProcessedMark        uint32 `json:"processed_mark"`
	ProcessedMarkMask    uint32 `json:"processed_mark_mask"`
	QueueBypass          bool   `json:"queue_bypass"`
	CandidateQueueOffset int    `json:"candidate_queue_offset"`
	ReadinessTimeoutMS   int    `json:"readiness_timeout_ms"`
	OffloadSelfCheck     bool   `json:"offload_self_check"`
}

type ReassemblyRuntimeConfig struct {
	MaxFlows        int `json:"max_flows"`
	MaxBytesPerFlow int `json:"max_bytes_per_flow"`
	MaxBytesTotal   int `json:"max_bytes_total"`
	MaxSegments     int `json:"max_segments"`
	MaxClientHello  int `json:"max_client_hello"`
	TimeoutMS       int `json:"timeout_ms"`
}

type HoldReplayRuntimeConfig struct {
	MaxFlows          int  `json:"max_flows"`
	MaxPacketsPerFlow int  `json:"max_packets_per_flow"`
	MaxBytesTotal     int  `json:"max_bytes_total"`
	TimeoutMS         int  `json:"timeout_ms"`
	ReleaseOnPressure bool `json:"release_on_pressure"`
}

type ActionBudgetRuntimeConfig struct {
	MaxWritesPerHello int     `json:"max_writes_per_hello"`
	MaxFakeBytes      int     `json:"max_fake_bytes"`
	MaxAmplification  float64 `json:"max_amplification"`
}

type DiscoveryRuntimeConfig struct {
	SandboxMaxActive  int  `json:"sandbox_max_active"`
	SandboxMaxEvents  int  `json:"sandbox_max_events"`
	MaxProbes         int  `json:"max_probes"`
	MaxConcurrency    int  `json:"max_concurrency"`
	SamplesPerVariant int  `json:"samples_per_variant"`
	StableSuccesses   int  `json:"stable_successes"`
	MaxShadowProbes   int  `json:"max_shadow_probes"`
	RequireBaselines  bool `json:"require_baselines"`
	NoAutomaticApply  bool `json:"no_automatic_apply"`
}

type FailureInboxRuntimeConfig struct {
	MaxCandidates           int `json:"max_candidates"`
	MaxEvidencePerCandidate int `json:"max_evidence_per_candidate"`
	MaxSetCandidates        int `json:"max_set_candidates"`
	MaxSignals              int `json:"max_signals"`
	MaxReasons              int `json:"max_reasons"`
	RetentionSeconds        int `json:"retention_seconds"`
	MinSYNSentAgeMS         int `json:"min_syn_sent_age_ms"`
}

type ClientHelloLabRuntimeConfig struct {
	CaptureDurationSeconds int  `json:"capture_duration_seconds"`
	MaxFlows               int  `json:"max_flows"`
	MaxProfiles            int  `json:"max_profiles"`
	MaxBytesPerFlow        int  `json:"max_bytes_per_flow"`
	MaxBytesTotal          int  `json:"max_bytes_total"`
	MaxSegmentsPerFlow     int  `json:"max_segments_per_flow"`
	RequireProvenance      bool `json:"require_provenance"`
}

type RolloutRuntimeConfig struct {
	LastGoodRetentionHours  int     `json:"last_good_retention_hours"`
	CanaryDurationSeconds   int     `json:"canary_duration_seconds"`
	CanaryNewFlowPercent    uint8   `json:"canary_new_flow_percent"`
	CanaryMinSamples        uint64  `json:"canary_min_samples"`
	CanaryMaxFailures       uint64  `json:"canary_max_failures"`
	CanaryMaxFailureRate    float64 `json:"canary_max_failure_rate"`
	CooldownSeconds         int     `json:"cooldown_seconds"`
	RequireReadiness        bool    `json:"require_readiness"`
	StopOnQueueDrops        bool    `json:"stop_on_queue_drops"`
	StopOnCaptureIncomplete bool    `json:"stop_on_capture_incomplete"`
}

type StrategyCatalogConfig struct {
	MarkerMultiSplit    bool `json:"marker_multisplit"`
	MarkerMultiDisorder bool `json:"marker_multidisorder"`
	HostFakeSplit       bool `json:"hostfakesplit"`
	FakePayloadCatalog  bool `json:"fake_payload_catalog"`
	FakeDSplit          bool `json:"fakedsplit"`
	FakeDDisorder       bool `json:"fakeddisorder"`
	TLSRecordSplit      bool `json:"tls_record_split"`
	ControlledRST       bool `json:"controlled_rst"`
}

type FallbackCapabilityConfig struct {
	NativeTCP  bool `json:"native_tcp"`
	NativeUDP  bool `json:"native_udp"`
	DirectTCP  bool `json:"direct_tcp"`
	DirectUDP  bool `json:"direct_udp"`
	GenericTCP bool `json:"generic_tcp"`
	GenericUDP bool `json:"generic_udp"`
	ProxyTCP   bool `json:"proxy_tcp"`
	ProxyUDP   bool `json:"proxy_udp"`
	IPv4       bool `json:"ipv4"`
	IPv6       bool `json:"ipv6"`
}

type FallbackRuntimeConfig struct {
	Enabled            bool                     `json:"enabled"`
	Policy             string                   `json:"policy"`
	NativeConfidence   uint8                    `json:"native_confidence"`
	BypassMark         uint32                   `json:"bypass_mark"`
	GenericMark        uint32                   `json:"generic_mark"`
	RuleTable          int                      `json:"rule_table"`
	ProxyRouteID       string                   `json:"proxy_route_id"`
	CooldownSeconds    int                      `json:"cooldown_seconds"`
	LastGoodTTLSeconds int                      `json:"last_good_ttl_seconds"`
	HealthTTLSeconds   int                      `json:"health_ttl_seconds"`
	MaxScopes          int                      `json:"max_scopes"`
	MaxIdlePerScope    int                      `json:"max_idle_per_scope"`
	MaxUDPSessions     int                      `json:"max_udp_sessions"`
	UDPIdleTimeoutSec  int                      `json:"udp_idle_timeout_seconds"`
	Capabilities       FallbackCapabilityConfig `json:"capabilities"`
}

type PrivacyRuntimeConfig struct {
	TelemetryMode              string `json:"telemetry_mode"`
	MetadataRetentionHours     int    `json:"metadata_retention_hours"`
	RawCaptureRetentionMinutes int    `json:"raw_capture_retention_minutes"`
	HashClientIdentifiers      bool   `json:"hash_client_identifiers"`
	HashDomains                bool   `json:"hash_domains"`
	IncludeRawInExport         bool   `json:"include_raw_in_export"`
	AutomaticRawUpload         bool   `json:"automatic_raw_upload"`
}

var DefaultClassifierRuntimeConfig = ClassifierRuntimeConfig{
	ClientIdentity: ClientIdentityRuntimeConfig{MaxEntries: 4096, TTLSeconds: 300, AllowIPOnly: true, LateARPEnrichment: true},
	Confidence:     ConfidenceRuntimeConfig{Classify: 55, Mutate: 75, Destructive: 85, ProxyFallback: 35},
	Hints:          HintStoreRuntimeConfig{MaxEntries: 4096, MaxEntriesPerClient: 64, MaxCandidatesPerKey: 8, MaxBytesPerClient: 64 * 1024, DNSMaxTTLSeconds: 300, QUICTTLSeconds: 60, LearnedTTLSeconds: 60},
	Capture:        CaptureRuntimeConfig{OutgoingPacketLimit: 20, IncomingPacketLimit: 20, AlwaysQueueSynAck: true, AlwaysQueueFIN: true, AlwaysQueueRST: true, AlwaysQueueQUIC: true, ProcessedMarkMask: 1 << 27, QueueBypass: true, CandidateQueueOffset: 1, ReadinessTimeoutMS: 3000, OffloadSelfCheck: true},
	Reassembly:     ReassemblyRuntimeConfig{MaxFlows: 1024, MaxBytesPerFlow: 32 * 1024, MaxBytesTotal: 4 * 1024 * 1024, MaxSegments: 64, MaxClientHello: 32 * 1024, TimeoutMS: 5000},
	HoldReplay:     HoldReplayRuntimeConfig{MaxFlows: 256, MaxPacketsPerFlow: 8, MaxBytesTotal: 64 * 1024, TimeoutMS: 750, ReleaseOnPressure: true},
	Actions:        ActionBudgetRuntimeConfig{MaxWritesPerHello: 16, MaxFakeBytes: 64 * 1024, MaxAmplification: 4},
	Discovery:      DiscoveryRuntimeConfig{SandboxMaxActive: 8, SandboxMaxEvents: 256, MaxProbes: 32, MaxConcurrency: 2, SamplesPerVariant: 1, StableSuccesses: 2, MaxShadowProbes: 3, RequireBaselines: true, NoAutomaticApply: true},
	FailureInbox:   FailureInboxRuntimeConfig{MaxCandidates: 512, MaxEvidencePerCandidate: 16, MaxSetCandidates: 16, MaxSignals: 8, MaxReasons: 8, RetentionSeconds: 120, MinSYNSentAgeMS: 3000},
	ClientHelloLab: ClientHelloLabRuntimeConfig{CaptureDurationSeconds: 30, MaxFlows: 64, MaxProfiles: 64, MaxBytesPerFlow: 32 * 1024, MaxBytesTotal: 512 * 1024, MaxSegmentsPerFlow: 64, RequireProvenance: true},
	Rollout:        RolloutRuntimeConfig{LastGoodRetentionHours: 24 * 7, CanaryDurationSeconds: 300, CanaryNewFlowPercent: 10, CanaryMinSamples: 20, CanaryMaxFailures: 3, CanaryMaxFailureRate: 0.10, CooldownSeconds: 300, RequireReadiness: true, StopOnQueueDrops: true, StopOnCaptureIncomplete: true},
	Strategies:     StrategyCatalogConfig{},
	Fallback:       FallbackRuntimeConfig{Policy: FallbackDirect, NativeConfidence: 75, CooldownSeconds: 30, LastGoodTTLSeconds: 300, HealthTTLSeconds: 30, MaxScopes: 512, MaxIdlePerScope: 4, MaxUDPSessions: 1024, UDPIdleTimeoutSec: 60, Capabilities: FallbackCapabilityConfig{NativeTCP: true, NativeUDP: true, DirectTCP: true, DirectUDP: true, GenericTCP: true, ProxyTCP: true, IPv4: true, IPv6: true}},
	Privacy:        PrivacyRuntimeConfig{TelemetryMode: PrivacyTelemetryRedacted, MetadataRetentionHours: 24, RawCaptureRetentionMinutes: 30, HashClientIdentifiers: true, HashDomains: true},
}
