import { apiFetch } from "./apiClient";
import {
  DNSAdaptivePolicy,
  DNSConfigResponse,
  DNSDiagnoseResponse,
  DNSMode,
  DNSProvider,
  DNSStatus,
} from "@models/dns";

// Write endpoints enforce generation precondition and idempotency (§83).
const writeHeaders = (generation: number) => ({
  "X-Config-Generation": String(generation),
  "X-Idempotency-Key": crypto.randomUUID(),
});

export const dnsApi = {
  status: () => apiFetch<DNSStatus>("/api/dns/v1/status"),
  config: () => apiFetch<DNSConfigResponse>("/api/dns/v1/config"),
  providers: () => apiFetch<DNSProvider[]>("/api/dns/v1/providers"),
  updateConfig: (
    mode: DNSMode,
    policy: DNSAdaptivePolicy | undefined,
    generation: number,
  ) =>
    apiFetch<{ mode: DNSMode; applied: boolean }>("/api/dns/v1/config", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...writeHeaders(generation),
      },
      body: JSON.stringify({ mode, policy }),
    }),
  diagnose: (generation: number) =>
    apiFetch<DNSDiagnoseResponse>("/api/dns/v1/diagnose", {
      method: "POST",
      headers: writeHeaders(generation),
    }),
  revalidate: (generation: number) =>
    apiFetch<{ revalidated: boolean; reason?: string }>(
      "/api/dns/v1/revalidate",
      { method: "POST", headers: writeHeaders(generation) },
    ),
  rollback: (generation: number) =>
    apiFetch<{ rolled_back: boolean; reason?: string }>(
      "/api/dns/v1/rollback",
      { method: "POST", headers: writeHeaders(generation) },
    ),
};
