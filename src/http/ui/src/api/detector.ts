import { apiPost, apiGet, apiDelete } from "./apiClient";
import type { DetectorResponse, DetectorSuite, DetectorTestType, DetectorHistoryEntry } from "@models/detector";

export const detectorApi = {
  start: (tests: DetectorTestType[]) =>
    apiPost<DetectorResponse>("/api/detector/start", { tests }),
  status: (id: string) =>
    apiGet<DetectorSuite>(`/api/detector/status/${id}`),
  cancel: (id: string) =>
    apiDelete(`/api/detector/cancel/${id}`),
  history: () =>
    apiGet<DetectorHistoryEntry[]>("/api/detector/history"),
  clearHistory: () =>
    apiPost("/api/detector/history/clear", {}),
  deleteHistoryEntry: (id: string) =>
    apiDelete(`/api/detector/history/${encodeURIComponent(id)}`),
};
