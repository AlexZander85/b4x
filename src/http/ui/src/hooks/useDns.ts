import { useCallback, useEffect, useState } from "react";
import { dnsApi } from "@api/dns";
import {
  DNSAdaptivePolicy,
  DNSDiagnoseResponse,
  DNSMode,
  DNSProvider,
  DNSStatus,
} from "@models/dns";

const POLL_INTERVAL_MS = 5000;

export function useDns() {
  const [status, setStatus] = useState<DNSStatus | null>(null);
  const [policy, setPolicy] = useState<DNSAdaptivePolicy | null>(null);
  const [providers, setProviders] = useState<DNSProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [lastDiagnosis, setLastDiagnosis] =
    useState<DNSDiagnoseResponse | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, c, p] = await Promise.all([
        dnsApi.status(),
        dnsApi.config(),
        dnsApi.providers(),
      ]);
      setStatus(s);
      setPolicy(c.policy);
      setProviders(p);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const generation = status?.config_generation ?? 0;

  const updateConfig = useCallback(
    async (mode: DNSMode, next: DNSAdaptivePolicy | undefined) => {
      setBusy(true);
      try {
        await dnsApi.updateConfig(mode, next, generation);
        await refresh();
      } finally {
        setBusy(false);
      }
    },
    [generation, refresh],
  );

  const diagnose = useCallback(async () => {
    setBusy(true);
    try {
      const res = await dnsApi.diagnose(generation);
      setLastDiagnosis(res);
      await refresh();
      return res;
    } finally {
      setBusy(false);
    }
  }, [generation, refresh]);

  const rollback = useCallback(async () => {
    setBusy(true);
    try {
      const res = await dnsApi.rollback(generation);
      await refresh();
      return res;
    } finally {
      setBusy(false);
    }
  }, [generation, refresh]);

  const revalidate = useCallback(async () => {
    setBusy(true);
    try {
      const res = await dnsApi.revalidate(generation);
      await refresh();
      return res;
    } finally {
      setBusy(false);
    }
  }, [generation, refresh]);

  return {
    status,
    policy,
    providers,
    loading,
    busy,
    lastDiagnosis,
    refresh,
    updateConfig,
    diagnose,
    rollback,
    revalidate,
  };
}
