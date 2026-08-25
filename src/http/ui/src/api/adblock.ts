import { apiFetch, apiPost, apiPut } from "./apiClient";
import { AdBlockConfigPatch, AdBlockStatus } from "@models/adblock";

export const adblockApi = {
  status: () => apiFetch<AdBlockStatus>("/api/adblock"),
  updateConfig: (patch: AdBlockConfigPatch) =>
    apiPut<AdBlockStatus>("/api/adblock/config", patch),
  addList: (source: string) =>
    apiPost<AdBlockStatus>("/api/adblock/lists/add", { source }),
  removeList: (source: string) =>
    apiPost<AdBlockStatus>("/api/adblock/lists/remove", { source }),
  toggleList: (source: string, enabled: boolean) =>
    apiPost<AdBlockStatus>("/api/adblock/lists/toggle", { source, enabled }),
  refresh: () => apiPost<{ status: string }>("/api/adblock/refresh"),
};
