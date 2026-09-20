import { useCallback, useEffect, useRef, useState } from "react";
import { tunnelsApi } from "@api/tunnels";
import { TunnelKind } from "@models/config";
import { TunnelsOverview } from "@models/tunnels";

export function useTunnels(pollMs = 5000) {
  const [overview, setOverview] = useState<TunnelsOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [restarting, setRestarting] = useState<string | null>(null);
  // measuring: the kind being measured, or "__all__" for a measure-all run.
  const [measuring, setMeasuring] = useState<string | null>(null);
  const initRef = useRef(false);

  const loadOverview = useCallback(async () => {
    try {
      const data = await tunnelsApi.overview();
      setOverview(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load tunnels");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initRef.current) return;
    initRef.current = true;
    loadOverview().catch(() => {});
  }, [loadOverview]);

  useEffect(() => {
    const interval = setInterval(() => {
      loadOverview().catch(() => {});
    }, pollMs);
    return () => clearInterval(interval);
  }, [loadOverview, pollMs]);

  const restartTunnel = useCallback(
    async (kind: TunnelKind) => {
      try {
        setRestarting(kind);
        await tunnelsApi.restart(kind);
        await loadOverview();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Restart failed");
        throw err;
      } finally {
        setRestarting(null);
      }
    },
    [loadOverview],
  );

  // measureTunnels runs an on-demand health probe (all carriers, or one
  // kind) and refreshes the overview so the new scores surface (design §8).
  const measureTunnels = useCallback(
    async (kind?: TunnelKind) => {
      try {
        setMeasuring(kind ?? "__all__");
        await tunnelsApi.measure(kind);
        await loadOverview();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Measure failed");
        throw err;
      } finally {
        setMeasuring(null);
      }
    },
    [loadOverview],
  );

  return {
    overview,
    loading,
    error,
    restarting,
    measuring,
    reload: loadOverview,
    restartTunnel,
    measureTunnels,
  };
}
