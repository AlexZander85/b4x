import { useCallback, useEffect, useRef, useState } from "react";
import { adblockApi } from "@api/adblock";
import { AdBlockConfigPatch, AdBlockStatus } from "@models/adblock";

const POLL_INTERVAL_MS = 1500;
const POLL_DEADLINE_MS = 60000;

interface RefreshBaseline {
  fetchCounters: number;
  modifiedKey: string;
}

const baselineOf = (s: AdBlockStatus | null): RefreshBaseline | null => {
  if (!s) return null;
  return {
    fetchCounters: s.stats.fetch_ok + s.stats.fetch_fail,
    modifiedKey: JSON.stringify(s.lists.map((l) => l.last_modified)),
  };
};

export function useAdBlock() {
  const [status, setStatus] = useState<AdBlockStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const statusRef = useRef<AdBlockStatus | null>(null);
  const pollTimer = useRef<number | null>(null);

  const applyStatus = useCallback((data: AdBlockStatus) => {
    statusRef.current = data;
    setStatus(data);
  }, []);

  const loadStatus = useCallback(async () => {
    try {
      applyStatus(await adblockApi.status());
    } finally {
      setLoading(false);
    }
  }, [applyStatus]);

  useEffect(() => {
    void loadStatus();
    return () => {
      if (pollTimer.current !== null) {
        window.clearTimeout(pollTimer.current);
        pollTimer.current = null;
      }
    };
  }, [loadStatus]);

  // Optimistic config update with rollback on failure.
  const updateConfig = useCallback(
    async (patch: AdBlockConfigPatch) => {
      const prev = statusRef.current;
      if (!prev) return;
      applyStatus({ ...prev, ...patch });
      try {
        applyStatus(await adblockApi.updateConfig(patch));
      } catch (err) {
        applyStatus(prev); // rollback
        throw err;
      }
    },
    [applyStatus],
  );

  const addList = useCallback(
    async (source: string) => {
      applyStatus(await adblockApi.addList(source));
    },
    [applyStatus],
  );

  const removeList = useCallback(
    async (source: string) => {
      applyStatus(await adblockApi.removeList(source));
    },
    [applyStatus],
  );

  // Optimistic per-list toggle with rollback on failure.
  const toggleList = useCallback(
    async (source: string, enabled: boolean) => {
      const prev = statusRef.current;
      if (!prev) return;
      applyStatus({
        ...prev,
        lists: prev.lists.map((l) =>
          l.source === source ? { ...l, enabled } : l,
        ),
      });
      try {
        applyStatus(await adblockApi.toggleList(source, enabled));
      } catch (err) {
        applyStatus(prev); // rollback
        throw err;
      }
    },
    [applyStatus],
  );

  // Force subscription re-download, then poll until fetch counters or any
  // list mtime changes (or the deadline expires).
  const refreshSubscriptions = useCallback(async () => {
    const base = baselineOf(statusRef.current);
    await adblockApi.refresh();
    setRefreshing(true);
    if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    const startedAt = Date.now();
    const tick = async () => {
      let done = false;
      try {
        const data = await adblockApi.status();
        applyStatus(data);
        const now = baselineOf(data);
        done =
          base === null ||
          now === null ||
          now.fetchCounters !== base.fetchCounters ||
          now.modifiedKey !== base.modifiedKey;
      } catch {
        // transient poll errors: keep trying until the deadline
      }
      if (done || Date.now() - startedAt >= POLL_DEADLINE_MS) {
        setRefreshing(false);
        return;
      }
      pollTimer.current = window.setTimeout(
        () => void tick(),
        POLL_INTERVAL_MS,
      );
    };
    pollTimer.current = window.setTimeout(() => void tick(), POLL_INTERVAL_MS);
  }, [applyStatus]);

  return {
    status,
    loading,
    refreshing,
    updateConfig,
    addList,
    removeList,
    toggleList,
    refreshSubscriptions,
    reload: loadStatus,
  };
}
