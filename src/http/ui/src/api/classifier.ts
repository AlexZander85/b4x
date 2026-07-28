import { apiGet, apiPost } from "./apiClient";
import type {
  ClassifierConfigEnvelope,
  ClientHelloProfilesResponse,
  FailureCandidatesResponse,
  IssueBundle,
  MetricsSnapshot,
  RuntimeCanaryOutcome,
  RuntimeControlStatus,
  RuntimePrepareRequest,
} from "@models/classifier";
import type { DiscoverySuite, HistoryEntry } from "@b4.discovery";

export const classifierApi = {
  config: () =>
    apiGet<ClassifierConfigEnvelope>("/api/v2/classifier/config"),
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
