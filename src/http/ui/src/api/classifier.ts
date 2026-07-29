import { apiGet, apiPost } from "./apiClient";
import type {
  ClassifierConfigEnvelope,
  ClassifierIsolationStatus,
  ClientHelloProfilesResponse,
  FailureCandidatesResponse,
  IssueBundle,
  MetricsSnapshot,
  RuntimeCanaryOutcome,
  RuntimeControlStatus,
  RuntimePrepareRequest,
} from "@models/classifier";
import type { DiscoverySuite, HistoryEntry } from "@b4.discovery";

export interface PPEVisibilityState {
  mode: "complete" | "outgoing-only" | "unknown" | "incomplete";
  enforced: boolean;
  generation?: string;
  last_verdict?: string;
  reason?: string;
}

export interface PPEProductStatus {
  effective: "monitoring" | "per-flow-exclusion" | "unavailable";
  rules_present: boolean;
  capabilities: { supported: boolean; state: string; platform?: { platform?: string; soc_family?: string; kernel?: string; arch?: string } };
  desired?: { generation: string; source_scope: string; connskip_packets: number; effective_tcp_ports?: number[]; effective_udp_ports?: number[] };
  visibility: PPEVisibilityState;
  reconciler: { running: boolean; rules_present: boolean; reapplied: number; failures: number; last_error?: string };
  last_self_test?: { run_id: string; verdict: string; production_ready: boolean; failure_stage?: string; evidence?: string[] };
  features?: Record<string, { allowed: boolean; reason?: string }>;
}

export interface PPESelfTestRequest {
  expected_generation: string;
  idempotency_key: string;
  controlled_endpoint?: string;
  family: "ipv4" | "ipv6";
  tcp_source_port: number;
  quic_source_port?: number;
  require_quic: boolean;
  timeout_ms?: number;
}

const idempotencyKey = (operation: string) =>
  `${operation}-${Date.now()}-${Math.random().toString(16).slice(2)}`;

export const classifierApi = {
  config: () =>
    apiGet<ClassifierConfigEnvelope>("/api/v2/classifier/config"),
  isolation: () =>
    apiGet<ClassifierIsolationStatus>("/api/v2/classifier/isolation"),
  issueBundle: () =>
    apiGet<IssueBundle>("/api/diagnostics/issue-bundle"),
  metrics: () =>
    apiGet<MetricsSnapshot>("/api/observability/metrics"),
  failures: () =>
    apiGet<FailureCandidatesResponse>("/api/diagnostics/failures?limit=128"),
  clientHelloProfiles: () =>
    apiGet<ClientHelloProfilesResponse>("/api/lab/clienthello"),
  discoveryCurrent: () =>
    apiGet<DiscoverySuite | null>("/api/discovery/current"),
  discoveryHistory: () =>
    apiGet<HistoryEntry[]>("/api/discovery/history"),
  runtimeStatus: () =>
    apiGet<RuntimeControlStatus>("/api/v2/runtime-control/status"),
  runtimePrepare: (request: RuntimePrepareRequest) =>
    apiPost("/api/v2/runtime-control/prepare", request),
  runtimeCanary: () =>
    apiPost<RuntimeCanaryOutcome>("/api/v2/runtime-control/canary"),
  runtimePromote: () =>
    apiPost("/api/v2/runtime-control/promote"),
  runtimeAbort: (reason: string) =>
    apiPost("/api/v2/runtime-control/abort", { reason }),
  runtimeRollback: (reason: string) =>
    apiPost("/api/v2/runtime-control/rollback", { reason }),
  ppeStatus: () =>
    apiGet<PPEProductStatus>("/api/v1/capture/offload/status"),
  ppeApply: (expectedGeneration: string) =>
    apiPost<PPEProductStatus>("/api/v1/capture/offload/apply", {
      expected_generation: expectedGeneration,
      idempotency_key: idempotencyKey("ppe-apply"),
    }),
  ppeRollback: (expectedGeneration: string) =>
    apiPost<PPEProductStatus>("/api/v1/capture/offload/rollback", {
      expected_generation: expectedGeneration,
      idempotency_key: idempotencyKey("ppe-rollback"),
    }),
  ppeSelfTest: (request: Omit<PPESelfTestRequest, "idempotency_key">) =>
    apiPost("/api/v1/capture/offload/self-test", {
      ...request,
      idempotency_key: idempotencyKey("ppe-self-test"),
    }),
  ppeIssueBundle: async () => {
    const response = await fetch("/api/v1/capture/offload/issue-bundle");
    if (!response.ok) throw new Error(`PPE issue bundle failed (${response.status})`);
    return response.blob();
  },
  exportConfig: async (includeRaw = false, confirmRaw = false) => {
    const query = new URLSearchParams();
    if (includeRaw) query.set("include_raw", "true");
    if (confirmRaw) query.set("confirm_raw", "true");
    const suffix = query.size ? `?${query.toString()}` : "";
    const response = await fetch(`/api/v2/classifier/export${suffix}`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `Export failed (${response.status})`);
    }
    return response.blob();
  },
};
