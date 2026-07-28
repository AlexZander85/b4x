import {
  Alert, Box, Button, CardContent, Divider, LinearProgress, MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { classifierApi } from "@api/classifier";
import { B4Card } from "@common/B4Card";
import { CheckCircleIcon, RestartIcon, SecurityIcon } from "@b4.icons";
import type { ClassifierConfigEnvelope, IssueBundle, RuntimePrepareRequest } from "@models/classifier";
import { EmptyState, SectionTitle, StatusChip, fmtDate, short } from "./shared";

export function RolloutPanel({
  config,
  bundle,
}: Readonly<{
  config?: ClassifierConfigEnvelope;
  bundle?: IssueBundle;
}>) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [setID, setSetID] = useState("");
  const [clientGroup, setClientGroup] = useState("ip:");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [candidateText, setCandidateText] = useState("");
  const [reason, setReason] = useState("operator requested");
  const rollout = config?.config.runtime.rollout;
  const transactional = Boolean(config?.config.flags.transactional_apply_enabled);
  const captureReady = Boolean(bundle?.queue.ready && bundle?.queue.processed_mark_verified);

  useEffect(() => {
    if (config && !candidateText) {
      setCandidateText(JSON.stringify({ classifier: config.config }, null, 2));
    }
  }, [config, candidateText]);

  const statusQuery = useQuery({
    queryKey: ["runtime-control-status"],
    queryFn: classifierApi.runtimeStatus,
    refetchInterval: 3000,
    retry: false,
  });
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["runtime-control-status"] });
  };
  const prepare = useMutation({
    mutationFn: async () => {
      const candidate = JSON.parse(candidateText) as RuntimePrepareRequest["candidate"];
      return classifierApi.runtimePrepare({
        candidate,
        canary: {
          client_group: clientGroup.trim(),
          set_id: setID.trim(),
          protocol,
          new_flow_percent: rollout?.canary_new_flow_percent ?? 10,
          duration_seconds: rollout?.canary_duration_seconds ?? 300,
          min_samples: rollout?.canary_min_samples ?? 20,
          max_failures: rollout?.canary_max_failures ?? 3,
          max_failure_rate: rollout?.canary_max_failure_rate ?? 0.1,
          stop_on_queue_drops: true,
          stop_on_capture_incomplete: true,
        },
      });
    },
    onSuccess: refresh,
  });
  const canary = useMutation({ mutationFn: classifierApi.runtimeCanary, onSuccess: refresh, onError: refresh });
  const promote = useMutation({ mutationFn: classifierApi.runtimePromote, onSuccess: refresh });
  const abort = useMutation({ mutationFn: () => classifierApi.runtimeAbort(reason), onSuccess: refresh });
  const rollback = useMutation({ mutationFn: () => classifierApi.runtimeRollback(reason), onSuccess: refresh });

  const status = statusQuery.data;
  const pending = status?.pending;
  const busy = prepare.isPending || canary.isPending || promote.isPending || abort.isPending || rollback.isPending;
  const candidateValid = useMemo(() => {
    try {
      const value = JSON.parse(candidateText) as Record<string, unknown>;
      return Boolean(value && typeof value === "object" && (value.classifier || value.sets));
    } catch {
      return false;
    }
  }, [candidateText]);
  const scopeValid = /^(ip|mac):.+/.test(clientGroup.trim());
  const canPrepare = transactional && captureReady && Boolean(status?.enabled) && !pending && candidateValid && scopeValid && setID.trim().length > 0;

  const error = prepare.error || canary.error || promote.error || abort.error || rollback.error || statusQuery.error;

  return (
    <Stack gap={2}>
      {statusQuery.isLoading && <LinearProgress />}
      {statusQuery.isError && <Alert severity="error">{t("classifier.rollout.runtimeMissing")}: {String(statusQuery.error)}</Alert>}
      {status && <Alert severity={status.enabled ? "success" : "warning"}>{status.enabled ? t("classifier.rollout.available") : t("classifier.rollout.disabled")}</Alert>}
      {error && <Alert severity="error">{String(error)}</Alert>}
      <B4Card>
        <CardContent>
          <SectionTitle title={t("classifier.rollout.title")} description={t("classifier.rollout.description")} />
          <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 2 }}>
            <Box><Typography variant="caption" color="text.secondary">Active generation</Typography><Typography fontFamily="monospace">{short(status?.active?.id ?? config?.runtime_generation, 26)}</Typography></Box>
            <Box><Typography variant="caption" color="text.secondary">Capture readiness</Typography><Box sx={{ mt: 0.5 }}><StatusChip ok={captureReady} label={captureReady ? "ready" : "blocked"} /></Box></Box>
            <Box><Typography variant="caption" color="text.secondary">Pending</Typography><Typography fontFamily="monospace">{pending ? short(pending.generation.id, 24) : "—"}</Typography></Box>
            <Box><Typography variant="caption" color="text.secondary">Last-good</Typography><Typography fontFamily="monospace">{short(status?.last_good?.generation_hash, 24)}</Typography></Box>
          </Box>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 180px 180px" }, gap: 1.5, mb: 2 }}>
            <TextField label={t("classifier.rollout.scopeValue")} value={clientGroup} onChange={(event) => setClientGroup(event.target.value)} helperText="ip:192.168.1.20 or mac:aa:bb:cc:dd:ee:ff" />
            <TextField label="Set ID" value={setID} onChange={(event) => setSetID(event.target.value)} />
            <TextField select label={t("classifier.rollout.protocol")} value={protocol} onChange={(event) => setProtocol(event.target.value as "tcp" | "udp")}>
              <MenuItem value="tcp">TCP</MenuItem><MenuItem value="udp">UDP / QUIC</MenuItem>
            </TextField>
          </Box>
          <TextField fullWidth multiline minRows={8} label={t("classifier.rollout.candidateJson")} value={candidateText} onChange={(event) => setCandidateText(event.target.value)} error={!candidateValid} sx={{ mb: 2 }} />
          <Stack direction={{ xs: "column", sm: "row" }} gap={1} flexWrap="wrap">
            <Button disabled={!canPrepare || busy} variant="outlined" onClick={() => prepare.mutate()}>{t("classifier.rollout.prepare")}</Button>
            <Button disabled={!pending || pending.canary_complete || busy} variant="contained" startIcon={<SecurityIcon />} onClick={() => canary.mutate()}>{t("classifier.rollout.canary")}</Button>
            <Button disabled={!pending?.canary_complete || !pending.canary?.passed || busy} color="success" startIcon={<CheckCircleIcon />} onClick={() => promote.mutate()}>{t("classifier.rollout.promote")}</Button>
            <Button disabled={!pending || busy} color="warning" onClick={() => abort.mutate()}>{t("classifier.rollout.abort")}</Button>
          </Stack>
          {pending && <Alert severity={pending.canary_complete ? (pending.canary?.passed ? "success" : "error") : "info"} sx={{ mt: 2 }}>
            {t("classifier.rollout.pending")}: {pending.generation.id} · {pending.canary_complete ? `${pending.canary?.samples ?? 0} samples / ${pending.canary?.failures ?? 0} failures` : "canary not run"}
          </Alert>}
          <Divider sx={{ my: 2 }} />
          <Stack direction={{ xs: "column", md: "row" }} gap={1}>
            <TextField fullWidth label={t("classifier.rollout.reason")} value={reason} onChange={(event) => setReason(event.target.value)} />
            <Button disabled={!status?.last_good || busy} color="error" startIcon={<RestartIcon />} onClick={() => rollback.mutate()}>{t("classifier.rollout.rollback")}</Button>
          </Stack>
        </CardContent>
      </B4Card>
      <B4Card>
        <CardContent>
          <SectionTitle title={t("classifier.rollout.history")} />
          {(status?.history ?? []).length === 0 ? <EmptyState text={t("classifier.rollout.noHistory")} /> : (
            <Stack gap={1}>{[...(status?.history ?? [])].reverse().map((entry, index) => (
              <Alert key={`${entry.at}-${index}`} severity={entry.success ? (entry.action === "rollback" ? "warning" : "success") : "error"}>
                {fmtDate(entry.at)} · {entry.action} · {short(entry.generation, 24)}{entry.reason ? ` · ${entry.reason}` : ""}
              </Alert>
            ))}</Stack>
          )}
        </CardContent>
      </B4Card>
    </Stack>
  );
}
