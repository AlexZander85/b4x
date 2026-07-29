export interface ClassifierFeatureFlags {
  classifier_v2_enabled: boolean;
  scoped_dns_hints_enabled: boolean;
  quic_tcp_handoff_enabled: boolean;
  tcp_fsm_enabled: boolean;
  capture_envelope_enabled: boolean;
  tcp_reassembly_mode: string;
  auto_hold_replay_enabled: boolean;
  tcp_hold_replay_mode: string;
  action_planner_v2_enabled: boolean;
  discovery_v23_enabled: boolean;
  clienthello_lab_enabled: boolean;
  failure_inbox_enabled: boolean;
  transactional_apply_enabled: boolean;
  proxy_fallback_enabled: boolean;
}

export interface ClassifierRuntimeConfig {
  confidence: {
    classify: number;
    mutate: number;
    destructive: number;
    proxy_fallback: number;
  };
  capture: {
    outgoing_packet_limit: number;
    incoming_packet_limit: number;
    processed_mark: number;
    processed_mark_mask: number;
    candidate_queue_offset: number;
    readiness_timeout_ms: number;
    require_queue_owner: boolean;
    require_processed_bypass: boolean;
    require_reply_visibility: boolean;
    offload_self_check: boolean;
  };
  reassembly: {
    max_flows: number;
    max_bytes_per_flow: number;
    max_bytes_total: number;
    max_segments: number;
    max_client_hello: number;
    timeout_ms: number;
  };
  hold_replay: {
    max_flows: number;
    max_packets_per_flow: number;
    max_bytes_total: number;
    timeout_ms: number;
    release_on_pressure: boolean;
  };
  actions: {
    max_writes_per_hello: number;
    max_fake_bytes: number;
    max_amplification: number;
  };
  discovery: {
    no_automatic_apply: boolean;
    max_probes: number;
    max_concurrency: number;
    samples_per_variant: number;
    stable_successes: number;
  };
  rollout: {
    last_good_retention_hours: number;
    canary_duration_seconds: number;
    canary_new_flow_percent: number;
    canary_min_samples: number;
    canary_max_failures: number;
    canary_max_failure_rate: number;
    cooldown_seconds: number;
    require_readiness: boolean;
  };
  strategies: Record<string, boolean>;
  privacy: {
    telemetry_mode: string;
    metadata_retention_hours: number;
    raw_capture_retention_minutes: number;
    include_raw_in_export: boolean;
    automatic_raw_upload: boolean;
  };
}

export interface ClassifierConfig {
  schema_version: number;
  api_version: string;
  domain_only_mode: string;
  flags: ClassifierFeatureFlags;
  runtime: ClassifierRuntimeConfig;
}

export interface ClassifierConfigEnvelope {
  api_version: string;
  schema_version: number;
  runtime_generation?: string;
  exported_at?: string;
  config: ClassifierConfig;
  raw_artifacts_included: boolean;
  warnings?: string[];
}

export interface EvidenceSummary {
  source: string;
  set_id?: string;
  domain_id?: string;
  confidence: number;
  ech: boolean;
  fresh: boolean;
}

export interface QueueSummary {
  ready: boolean;
  processed_mark_verified: boolean;
  offload_suspected: boolean;
  queue_drops: number;
  user_drops: number;
  status: string;
}

export interface TraceEvent {
  timestamp: string;
  client_id?: string;
  flow_id?: string;
  kind: string;
  fields?: Record<string, string>;
}

export interface ProbeOutcomeSummary {
  target_profile?: string;
  verdict: string;
  failure_stage?: string;
  failure_offset?: number;
  body_bytes: number;
  throughput_bps: number;
}

export interface MetricSample {
  name: string;
  labels?: Record<string, string>;
  value: number;
}

export interface ClassifierIsolationSetStatus {
  set_id: string;
  domain_only: boolean;
  configured_policy: string;
  effective_policy: string;
  unsafe_legacy: boolean;
  migration_required: boolean;
  migration_target?: string;
  reason_code?: string;
}

export interface ClassifierNegativeControlStatus {
  status: "not_run" | "passed" | "failed";
  unrelated_control_action_total: number;
  promotion_allowed: boolean;
  reason?: string;
}

export interface ClassifierIsolationStatus {
  api_version: string;
  generated_at: string;
  config_generation?: string;
  sets: ClassifierIsolationSetStatus[];
  metrics: MetricSample[];
  recent_events?: TraceEvent[];
  warnings?: string[];
  negative_control: ClassifierNegativeControlStatus;
  raw_hostnames: boolean;
}

export interface MetricsSnapshot {
  generated_at: string;
  counters: MetricSample[];
  histograms: Array<{
    name: string;
    labels?: Record<string, string>;
    count: number;
    sum: number;
  }>;
}

export interface IssueBundle {
  schema_version: string;
  generated_at: string;
  versions: Record<string, string>;
  metrics: MetricsSnapshot;
  evidence?: EvidenceSummary[];
  trace?: TraceEvent[];
  queue: QueueSummary;
  probe_outcomes?: ProbeOutcomeSummary[];
  raw_capture: boolean;
}

export interface FailureCandidate {
  id: string;
  destination_ip: string;
  destination_port: number;
  protocol: number;
  conntrack_state?: string;
  first_seen: string;
  last_seen: string;
  expires_at: string;
  set_candidates?: string[];
  flow_retries: number;
  suggested_action: string;
  available_actions: string[];
  signals: string[];
  reasons?: string[];
}

export interface FailureCandidatesResponse {
  success: boolean;
  generated_at: string;
  candidates: FailureCandidate[];
}

export interface ClientHelloProfile {
  id: string;
  flow_id: string;
  client_id: string;
  destination_id: string;
  destination_port: number;
  ip_family: string;
  hello_hash: string;
  source_app?: string;
  observed_domain?: string;
  tls_version: number;
  alpn?: string[];
  raw_size: number;
  compiled_size?: number;
  sha256: string;
  privacy_state: string;
  first_seen: string;
  completed_at: string;
  privacy_safe: boolean;
  metadata?: Record<string, unknown>;
  provenance?: Record<string, unknown>;
}

export interface ClientHelloProfilesResponse {
  success: boolean;
  generated_at: string;
  profiles: ClientHelloProfile[];
}

export interface FlowDiagnostic {
  id: string;
  clientId: string;
  lastSeen: string;
  phase: string;
  confidence?: number;
  source?: string;
  setId?: string;
  reassembly: string;
  lastKind: string;
  events: TraceEvent[];
}

export interface StrategyDryRunInput {
  setId: string;
  strategy: string;
  confidence: number;
  ech: boolean;
  clearHost: boolean;
  amplification: number;
  maxAmplification: number;
  thresholds: ClassifierRuntimeConfig["confidence"];
}

export interface StrategyDryRunResult {
  allowed: boolean;
  level: "safe" | "warning" | "blocked";
  reasons: string[];
  requiredConfidence: number;
}

const HOST_MARKER_STRATEGIES = new Set([
  "host_fake_split",
  "marker_multi_split",
  "marker_multi_disorder",
]);
const DESTRUCTIVE_STRATEGIES = new Set([
  "controlled_rst",
  "fake_d_disorder",
]);

export function evaluateStrategyDryRun(
  input: StrategyDryRunInput,
): StrategyDryRunResult {
  const reasons: string[] = [];
  if (!input.setId.trim()) {
    reasons.push("set or strategy scope is required");
  }
  const destructive = DESTRUCTIVE_STRATEGIES.has(input.strategy);
  const requiredConfidence = destructive
    ? input.thresholds.destructive
    : input.thresholds.mutate;

  if (input.confidence < requiredConfidence) {
    reasons.push(
      `confidence ${input.confidence} is below required threshold ${requiredConfidence}`,
    );
  }
  if (HOST_MARKER_STRATEGIES.has(input.strategy) && !input.clearHost) {
    reasons.push(
      input.ech
        ? "ECH flow cannot use host-marker actions without a corroborated clear/reassembled host"
        : "host marker is unavailable without a clear/reassembled host",
    );
  }
  const amplificationLimit = Math.min(input.maxAmplification, 4);
  if (input.amplification > amplificationLimit) {
    reasons.push(
      `packet amplification ${input.amplification}x exceeds allowed ${amplificationLimit}x`,
    );
  }

  const blocked = reasons.length > 0;
  return {
    allowed: !blocked,
    level: blocked ? "blocked" : input.amplification > 2 ? "warning" : "safe",
    reasons: blocked
      ? reasons
      : ["dry-run preconditions passed; no packet will be sent"],
    requiredConfidence,
  };
}

export function deriveFlowDiagnostics(trace: TraceEvent[]): FlowDiagnostic[] {
  const byFlow = new Map<string, TraceEvent[]>();
  for (const event of trace) {
    if (!event.flow_id) continue;
    const events = byFlow.get(event.flow_id) ?? [];
    events.push(event);
    byFlow.set(event.flow_id, events);
  }

  return [...byFlow.entries()]
    .map(([id, events]) => {
      events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
      const last = events.at(-1)!;
      const fields = last.fields ?? {};
      const reassemblyEvent = [...events]
        .reverse()
        .find((event) => event.kind.includes("reassembly"));
      const confidence = Number(fields.confidence);
      return {
        id,
        clientId: last.client_id ?? "—",
        lastSeen: last.timestamp,
        phase: fields.phase ?? fields.tcp_phase ?? "inspecting",
        confidence: Number.isFinite(confidence) ? confidence : undefined,
        source: fields.source ?? fields.evidence_source,
        setId: fields.set ?? fields.set_id,
        reassembly:
          reassemblyEvent?.fields?.reason ??
          reassemblyEvent?.fields?.status ??
          (reassemblyEvent ? reassemblyEvent.kind : "not observed"),
        lastKind: last.kind,
        events,
      };
    })
    .sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}

export interface RuntimeGenerationMeta {
  id: string;
  config_hash: string;
  schema_version: number;
  strategy_ids?: string[];
  set_ids?: string[];
  created_at: string;
}

export interface RuntimeReadiness {
  ready: boolean;
  checked_at: string;
  reason?: string;
  queue_drops?: number;
  user_drops?: number;
}

export interface RuntimeCanarySpec {
  client_group: string;
  set_id: string;
  protocol: "tcp" | "udp";
  new_flow_percent: number;
  duration: number;
  min_samples: number;
  stop_conditions: {
    max_failures?: number;
    max_failure_rate?: number;
    stop_on_queue_drops?: boolean;
    stop_on_capture_incomplete?: boolean;
  };
}

export interface RuntimeCanaryOutcome {
  passed: boolean;
  flows_started?: number;
  samples: number;
  incoming_progress?: number;
  incomplete_flows?: number;
  failures: number;
  failure_rate: number;
  queue_drops?: number;
  capture_incomplete?: boolean;
  stop_reason?: string;
  started_at: string;
  completed_at: string;
}

export interface RuntimePendingGeneration {
  generation: RuntimeGenerationMeta;
  readiness: RuntimeReadiness;
  canary_spec: RuntimeCanarySpec;
  canary?: RuntimeCanaryOutcome;
  canary_complete: boolean;
  prepared_at: string;
}

export interface RuntimeHistoryEntry {
  action: string;
  generation: string;
  reason?: string;
  success: boolean;
  at: string;
  canary?: RuntimeCanaryOutcome;
}

export interface RuntimeLastGood {
  generation_hash: string;
  config_hash: string;
  b4_version: string;
  timestamp: string;
  set_ids?: string[];
  strategy_ids?: string[];
  canary_outcome: RuntimeCanaryOutcome;
}

export interface RuntimeControlStatus {
  enabled: boolean;
  active?: RuntimeGenerationMeta;
  pending?: RuntimePendingGeneration;
  last_good?: RuntimeLastGood;
  history?: RuntimeHistoryEntry[];
}

export interface RuntimePrepareRequest {
  candidate: {
    classifier?: ClassifierConfig;
    sets?: unknown[];
  };
  canary: {
    client_group: string;
    set_id: string;
    protocol: "tcp" | "udp";
    new_flow_percent: number;
    duration_seconds: number;
    min_samples: number;
    max_failures: number;
    max_failure_rate: number;
    stop_on_queue_drops: boolean;
    stop_on_capture_incomplete: boolean;
  };
}
