import {
  Alert, Box, CardContent, Chip, Divider, LinearProgress, Stack, Typography,
} from "@mui/material";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { B4Card } from "@common/B4Card";
import type {
  ClassifierHardeningStatus, GSOQueueRange, MetricSample, MetricsSnapshot,
  PassiveRSTDecisionStatus,
} from "@models/classifier";
import { fmtDate, SectionTitle, short } from "./shared";

interface Props {
  status?: ClassifierHardeningStatus;
  metrics?: MetricsSnapshot;
  loading?: boolean;
  error?: unknown;
}

const metricValue = (metrics: MetricSample[], name: string) =>
  metrics.filter((sample) => sample.name === name).reduce((sum, sample) => sum + sample.value, 0);

const number = (value?: number) => new Intl.NumberFormat().format(value ?? 0);
const bytes = (value?: number) => {
  const current = value ?? 0;
  if (current >= 1024 * 1024) return `${(current / (1024 * 1024)).toFixed(1)} MiB`;
  if (current >= 1024) return `${(current / 1024).toFixed(1)} KiB`;
  return `${current} B`;
};

function Stat({ label, value, hint }: Readonly<{ label: string; value: string; hint?: string }>) {
  return (
    <Box sx={{ p: 1.5, border: "1px solid", borderColor: "divider", borderRadius: 1.5, minWidth: 0 }}>
      <Typography variant="caption" color="text.secondary">{label}</Typography>
      <Typography variant="h6" fontWeight={750} sx={{ overflowWrap: "anywhere" }}>{value}</Typography>
      {hint && <Typography variant="caption" color="text.secondary">{hint}</Typography>}
    </Box>
  );
}

function QueueCard({ queue }: Readonly<{ queue: GSOQueueRange }>) {
  const end = queue.start + Math.max(queue.threads - 1, 0);
  return (
    <Box sx={{ p: 1.25, border: "1px solid", borderColor: "divider", borderRadius: 1.5 }}>
      <Stack direction="row" justifyContent="space-between" gap={1} alignItems="center">
        <Typography fontWeight={700}>{queue.role}</Typography>
        <Chip size="small" label={queue.enabled ? "enabled" : "reserved"} color={queue.enabled ? "success" : "default"} variant="outlined" />
      </Stack>
      <Typography fontFamily="monospace" variant="body2">{queue.start}–{end}</Typography>
      <Typography variant="caption" color="text.secondary">{queue.threads} worker(s)</Typography>
    </Box>
  );
}

function decisionSeverity(decision: PassiveRSTDecisionStatus) {
  if (decision.decision === "suppress") return "warning" as const;
  if (decision.decision === "fail-open") return "info" as const;
  return "success" as const;
}

export function HardeningPanel({ status, metrics, loading, error }: Readonly<Props>) {
  const { t } = useTranslation();
  const counters = metrics?.counters ?? [];
  const signalCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const decision of status?.passive_rst.recent_decisions ?? []) {
      for (const signal of decision.signals ?? []) {
        const key = `${signal.signal}:${signal.strength}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [status?.passive_rst.recent_decisions]);

  if (loading) return <LinearProgress />;

  return (
    <B4Card>
      <CardContent>
        <SectionTitle title={t("classifier.hardening.title")} description={t("classifier.hardening.description")} />
        {error && <Alert severity="error" sx={{ mb: 2 }}>{String(error)}</Alert>}
        {!status && !error && <Alert severity="warning">{t("classifier.hardening.unavailable")}</Alert>}
        {status && (
          <Stack gap={2}>
            {(status.gso.requested_mode === "full" || status.gso.execution_policy === "normalize-for-action") && (
              <Alert severity="warning">{t("classifier.hardening.fullWarning")}</Alert>
            )}
            {status.passive_rst.requested_mode === "aggressive" && (
              <Alert severity="warning">{t("classifier.hardening.aggressiveWarning")}</Alert>
            )}
            {(status.warnings ?? []).map((warning) => <Alert severity="warning" key={warning}>{warning}</Alert>)}

            <Stack direction="row" gap={1} flexWrap="wrap">
              <Chip label={`${t("classifier.hardening.apiVersion")}: ${status.api_version}`} variant="outlined" />
              <Chip label={`${t("classifier.hardening.generation")}: ${short(status.runtime_generation, 24)}`} variant="outlined" />
            </Stack>

            <Box>
              <Typography variant="h6" fontWeight={750}>{t("classifier.hardening.gsoTitle")}</Typography>
              <Stack direction="row" gap={1} flexWrap="wrap" sx={{ my: 1 }}>
                <Chip label={`${t("classifier.hardening.requestedMode")}: ${status.gso.requested_mode}`} color={status.gso.requested_mode === "full" ? "warning" : "default"} />
                <Chip label={`${t("classifier.hardening.executionPolicy")}: ${status.gso.execution_policy}`} variant="outlined" />
                <Chip
                  label={`${t("classifier.hardening.capability")}: ${status.gso.capability.level}`}
                  color={["classify-ready", "full-action-ready"].includes(status.gso.capability.level) ? "success" : "warning"}
                />
              </Stack>
              {status.gso.capability.reason && <Alert severity="info" sx={{ mb: 1.5 }}>{status.gso.capability.reason}</Alert>}
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 1.25 }}>
                <Stat label={t("classifier.hardening.maxGsoBytes")} value={bytes(status.gso.max_gso_bytes)} />
                <Stat label={t("classifier.hardening.workers")} value={number(status.gso.workers)} />
                <Stat label={t("classifier.hardening.activeTokens")} value={number(status.gso.active_tokens)} />
                <Stat label={t("classifier.hardening.tokenMisses")} value={number(status.gso.token_stats.misses)} />
                <Stat label={t("classifier.hardening.normalized")} value={number(metricValue(counters, "nfqueue_gso_normalized_total"))} />
                <Stat label={t("classifier.hardening.actionsSuppressed")} value={number(metricValue(counters, "nfqueue_gso_action_suppressed_total"))} />
              </Box>
            </Box>

            <Box>
              <Typography variant="subtitle1" fontWeight={700}>{t("classifier.hardening.topology")}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {status.gso.topology_source} · {status.gso.topology.normalizer_mechanism} · queue-bypass={String(status.gso.topology.queue_bypass)} · IPv4={String(status.gso.topology.families.ipv4)} · IPv6={String(status.gso.topology.families.ipv6)}
              </Typography>
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 1.25 }}>
                {[status.gso.topology.production, status.gso.topology.candidate, status.gso.topology.discovery, status.gso.topology.normalizer].map((queue) => <QueueCard key={queue.role} queue={queue} />)}
              </Box>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                {t("classifier.hardening.resourceEnvelope")}: {status.gso.topology.estimated_workers}/{status.gso.topology.max_workers} workers · {bytes(status.gso.topology.estimated_memory_bytes)}/{bytes(status.gso.topology.max_memory_bytes)}
              </Typography>
            </Box>

            <Box>
              <Typography variant="subtitle1" fontWeight={700}>{t("classifier.hardening.sniMetrics")}</Typography>
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))", gap: 1.25, mt: 1 }}>
                <Stat label="classifier_reassembled_sni_total" value={number(metricValue(counters, "classifier_reassembled_sni_total"))} />
                <Stat label="classifier_layout_parity_fail_total" value={number(metricValue(counters, "classifier_layout_parity_fail_total"))} />
                <Stat label="nfqueue_gso_packets_total" value={number(metricValue(counters, "nfqueue_gso_packets_total"))} />
                <Stat label="nfqueue_gso_truncated_total" value={number(metricValue(counters, "nfqueue_gso_truncated_total"))} />
              </Box>
            </Box>

            <Divider />
            <Box>
              <Typography variant="h6" fontWeight={750}>{t("classifier.hardening.rstTitle")}</Typography>
              <Stack direction="row" gap={1} flexWrap="wrap" sx={{ my: 1 }}>
                <Chip label={`${t("classifier.hardening.requestedMode")}: ${status.passive_rst.requested_mode}`} color={status.passive_rst.requested_mode === "aggressive" ? "warning" : "default"} />
                <Chip label={`${t("classifier.hardening.effectiveMode")}: ${status.passive_rst.effective_mode}`} variant="outlined" />
                <Chip label={`${t("classifier.hardening.visibility")}: ${status.passive_rst.visibility_complete}/${status.passive_rst.visibility_complete + status.passive_rst.visibility_incomplete}`} color={status.passive_rst.visibility_incomplete === 0 ? "success" : "warning"} />
              </Stack>
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(155px, 1fr))", gap: 1.25 }}>
                <Stat label={t("classifier.hardening.rstObserved")} value={number(status.passive_rst.stats.rst_observed)} />
                <Stat label={t("classifier.hardening.rstSuppressed")} value={number(status.passive_rst.stats.suppressed)} />
                <Stat label={t("classifier.hardening.failOpen")} value={number(status.passive_rst.stats.fail_open)} />
                <Stat label={t("classifier.hardening.budgetExhausted")} value={number(status.passive_rst.stats.budget_exhausted)} />
                <Stat label={t("classifier.hardening.rollbackCount")} value={number(metricValue(counters, "passive_rst_rollback_total"))} />
                <Stat label={t("classifier.hardening.reconnectRegression")} value={number(metricValue(counters, "passive_rst_reconnect_regression_total"))} />
              </Box>
            </Box>

            <Box>
              <Typography variant="subtitle1" fontWeight={700}>{t("classifier.hardening.signalBreakdown")}</Typography>
              <Stack direction="row" gap={1} flexWrap="wrap" sx={{ mt: 1 }}>
                {signalCounts.length === 0 && <Typography variant="body2" color="text.secondary">{t("classifier.hardening.empty")}</Typography>}
                {signalCounts.map(([signal, count]) => <Chip key={signal} label={`${signal} · ${count}`} variant="outlined" />)}
              </Stack>
            </Box>

            <Box>
              <Typography variant="subtitle1" fontWeight={700}>{t("classifier.hardening.recentDecisions")}</Typography>
              <Stack gap={1} sx={{ mt: 1 }}>
                {(status.passive_rst.recent_decisions ?? []).length === 0 && <Typography variant="body2" color="text.secondary">{t("classifier.hardening.empty")}</Typography>}
                {(status.passive_rst.recent_decisions ?? []).slice(0, 8).map((decision) => (
                  <Alert severity={decisionSeverity(decision)} key={`${decision.flow_id}-${decision.observed_at}`}>
                    <Typography variant="body2" fontWeight={700}>{decision.decision} · {decision.baseline_quality} · {fmtDate(decision.observed_at)}</Typography>
                    <Typography variant="caption" display="block">{short(decision.flow_id, 24)} · generation {decision.config_generation} · budget {decision.budget_remaining} · visibility={String(decision.visibility_complete)} · progress={String(decision.server_progress)}</Typography>
                    {decision.reason && <Typography variant="caption" display="block">{decision.reason}</Typography>}
                  </Alert>
                ))}
              </Stack>
            </Box>

            <Box>
              <Typography variant="subtitle1" fontWeight={700}>{t("classifier.hardening.recentRollbacks")}</Typography>
              <Stack gap={1} sx={{ mt: 1 }}>
                {(status.passive_rst.recent_rollbacks ?? []).length === 0 && <Typography variant="body2" color="text.secondary">{t("classifier.hardening.empty")}</Typography>}
                {(status.passive_rst.recent_rollbacks ?? []).slice(0, 8).map((rollback) => (
                  <Alert severity="warning" key={`${rollback.set_id}-${rollback.device_scope}-${rollback.triggered_at}`}>
                    <Typography variant="body2" fontWeight={700}>{rollback.from_mode} → {rollback.effective_mode} · {fmtDate(rollback.triggered_at)}</Typography>
                    <Typography variant="caption" display="block">{short(rollback.set_id)} · {short(rollback.device_scope)} · generation {rollback.config_generation} · {rollback.environment}</Typography>
                    <Typography variant="caption" display="block">{rollback.reason}</Typography>
                  </Alert>
                ))}
              </Stack>
            </Box>
          </Stack>
        )}
      </CardContent>
    </B4Card>
  );
}
