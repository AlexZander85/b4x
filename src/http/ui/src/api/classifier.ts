import { apiGet } from "./apiClient";
import type {
  ClassifierConfigEnvelope,
  ClientHelloProfilesResponse,
  FailureCandidatesResponse,
  IssueBundle,
  MetricsSnapshot,
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
