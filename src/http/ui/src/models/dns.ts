// Adaptive DNS control plane models (addendum §84, §88).
// Field names match the backend JSON exactly (snake_case).

export type DNSMode = "current" | "manual" | "adaptive" | "diagnostic";

export type DNSPreference =
  | "lowest-latency"
  | "balanced"
  | "privacy"
  | "minimum-dependency";

export interface DNSAdaptivePolicy {
  enabled: boolean;
  allow_native_classic: boolean;
  allow_native_encrypted: boolean;
  allow_managed_dnscrypt_backend: boolean;
  allow_anonymized_dnscrypt: boolean;
  allow_odoh: boolean;
  allow_pqdnscrypt: boolean;
  preference: DNSPreference;
  require_dnssec_capable: boolean;
  require_nolog_claim: boolean;
  require_nofilter_claim: boolean;
  max_quick_candidates: number;
  max_deep_candidates: number;
  max_parallel_probes: number;
  /** Go duration strings, e.g. "10m" */
  cooldown: string;
  failed_search_cooldown: string;
  recovery_hysteresis: string;
  profile_ttl: string;
  manual_exclusions: string[];
  pinned_primary: string;
  pinned_fallbacks: string[];
}

export interface DNSConfigResponse {
  mode: DNSMode;
  policy: DNSAdaptivePolicy;
}

export interface DNSDiagnosis {
  udp_injection_suspected: boolean;
  poisoning_detected: boolean;
  port53_blocked: boolean;
  confidence: number;
}

export interface DNSPathView {
  family: string;
  resolver_id_hash?: string;
  health: string;
}

export interface DNSStatus {
  mode: DNSMode;
  verdict: string;
  network_context_id: string;
  config_generation: number;
  profile_id?: string;
  primary?: DNSPathView;
  fallbacks?: DNSPathView[];
  diagnosis?: DNSDiagnosis;
  rollback_ready: boolean;
  axes?: Record<string, string>;
}

export interface DNSProvider {
  family: string;
  hash: string;
  state: string;
  reason?: string;
}

export interface DNSDiagnoseResponse {
  run_id: string;
  result: {
    profile_id: string;
    primary_family: string;
    fallback_families: string[];
    poisoning_detected: boolean;
    injection_detected: boolean;
    udp_drop_detected: boolean;
    confidence: number;
    explanation: string[];
  };
}
