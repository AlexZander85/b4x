import { useState, useCallback, useEffect, useRef } from "react";
import { ApiError } from "@api/apiClient";
import { detectorApi } from "@api/detector";
import type { DetectorSuite, DetectorTestType, DetectorHistoryEntry } from "@models/detector";

export function useDetector() {
  const [running, setRunning] = useState(false);
  const [suiteId, setSuiteId] = useState<string | null>(null);
  const [suite, setSuite] = useState<DetectorSuite | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<DetectorHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const initRef = useRef(false);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const entries = await detectorApi.history();
      setHistory(entries ?? []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  // On mount: restore suiteId and load history
  useEffect(() => {
    if (initRef.current) return;
    initRef.current = true;

    const saved = localStorage.getItem("detector_suiteId");
    if (saved) {
      setSuiteId(saved);
      setRunning(true);
    }

    void loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    if (suiteId) {
      localStorage.setItem("detector_suiteId", suiteId);
    }
  }, [suiteId]);

  useEffect(() => {
    if (!suiteId || !running) return;

    const fetchStatus = async () => {
      try {
        const data = await detectorApi.status(suiteId);
        setSuite(data);
        if (["complete", "failed", "canceled"].includes(data.status)) {
          setRunning(false);
          localStorage.removeItem("detector_suiteId");
          void loadHistory();
        }
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
          setRunning(false);
          localStorage.removeItem("detector_suiteId");
          setSuiteId(null);
          void loadHistory();
          return;
        }
        setError(e instanceof Error ? e.message : "Unknown error");
        setRunning(false);
      }
    };

    pollRef.current = setInterval(() => void fetchStatus(), 1500);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [suiteId, running, loadHistory]);

  const startDetector = useCallback(
    async (tests: DetectorTestType[]) => {
      setError(null);
      setSuite(null);
      setRunning(true);
      try {
        const res = await detectorApi.start(tests);
        setSuiteId(res.id);
      } catch (e) {
        setRunning(false);
        setError(e instanceof Error ? e.message : "Failed to start detector");
      }
    },
    [],
  );

  const cancelDetector = useCallback(async () => {
    if (!suiteId) return;
    try {
      await detectorApi.cancel(suiteId);
      setRunning(false);
      void loadHistory();
    } catch (e) {
      console.error("Failed to cancel detector:", e);
    }
  }, [suiteId, loadHistory]);

  const resetDetector = useCallback(() => {
    localStorage.removeItem("detector_suiteId");
    setSuiteId(null);
    setSuite(null);
    setError(null);
    setRunning(false);
  }, []);

  const clearHistory = useCallback(async () => {
    try {
      await detectorApi.clearHistory();
      setHistory([]);
    } catch (e) {
      console.error("Failed to clear detector history:", e);
    }
  }, []);

  const deleteHistoryEntry = useCallback(async (id: string) => {
    try {
      await detectorApi.deleteHistoryEntry(id);
      setHistory((prev) => prev.filter((e) => e.id !== id));
    } catch (e) {
      console.error("Failed to delete history entry:", e);
    }
  }, []);

  return {
    running,
    suiteId,
    suite,
    error,
    history,
    historyLoading,
    startDetector,
    cancelDetector,
    resetDetector,
    clearHistory,
    deleteHistoryEntry,
    loadHistory,
  };
}
