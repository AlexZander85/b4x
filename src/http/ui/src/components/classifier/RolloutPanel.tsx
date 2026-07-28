import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import { CheckCircleIcon, DownloadIcon, RestartIcon, SecurityIcon } from "@b4.icons";
import type { ClassifierConfigEnvelope, IssueBundle } from "@models/classifier";
import { EmptyState, SectionTitle, StatusChip, fmtDate, short } from "./shared";

export function RolloutPanel({
  config,
  bundle,
  onPrepare,
}: Readonly<{
  config?: ClassifierConfigEnvelope;
  bundle?: IssueBundle;
  onPrepare: () => void;
}>) {
  const { t } = useTranslation();
  const [prepared, setPrepared] = useState(false);
  const [scope, setScope] = useState("set");
  const [scopeValue, setScopeValue] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const rollout = config?.config.runtime.rollout;
  const transactional = Boolean(config?.config.flags.transactional_apply_enabled);
  const ready = Boolean(bundle?.queue.ready && bundle?.queue.processed_mark_verified);
  const runtimeControlAvailable = false;
  const canControl =
    transactional &&
    ready &&
    runtimeControlAvailable &&
    scopeValue.trim().length > 0;

  return (
    <Stack gap={2}>
      <Alert severity="warning">{t("classifier.rollout.unavailable")}</Alert>
      <B4Card>
        <CardContent>
          <SectionTitle title={t("classifier.rollout.title")} description={t("classifier.rollout.description")} />
          <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 2 }}>
            <Box><Typography variant="caption" color="text.secondary">Active generation</Typography><Typography fontFamily="monospace">{short(config?.runtime_generation, 26)}</Typography></Box>
            <Box><Typography variant="caption" color="text.secondary">Readiness</Typography><Box sx={{ mt: 0.5 }}><StatusChip ok={ready} label={ready ? "ready" : "blocked"} /></Box></Box>
            <Box><Typography variant="caption" color="text.secondary">Canary</Typography><Typography>{rollout?.canary_new_flow_percent ?? "—"}% · {rollout?.canary_duration_seconds ?? "—"}s · min {rollout?.canary_min_samples ?? "—"}</Typography></Box>
            <Box><Typography variant="caption" color="text.secondary">Cooldown</Typography><Typography>{rollout?.cooldown_seconds ?? "—"}s</Typography></Box>
          </Box>
          <Divider sx={{ my: 2 }} />
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "180px 1fr 160px" },
              gap: 1.5,
              mb: 2,
            }}
          >
            <TextField
              select
              label={t("classifier.rollout.scope")}
              value={scope}
              onChange={(event) => setScope(event.target.value)}
            >
              <MenuItem value="set">Set</MenuItem>
              <MenuItem value="group">Group</MenuItem>
              <MenuItem value="client">Client</MenuItem>
            </TextField>
            <TextField
              label={t("classifier.rollout.scopeValue")}
              value={scopeValue}
              onChange={(event) => setScopeValue(event.target.value)}
              placeholder="SetID / group / redacted client ID"
            />
            <TextField
              select
              label={t("classifier.rollout.protocol")}
              value={protocol}
              onChange={(event) => setProtocol(event.target.value)}
            >
              <MenuItem value="tcp">TCP</MenuItem>
              <MenuItem value="udp">UDP / QUIC</MenuItem>
              <MenuItem value="all">All</MenuItem>
            </TextField>
          </Box>
          <Stack direction={{ xs: "column", sm: "row" }} gap={1} flexWrap="wrap">
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={() => { onPrepare(); setPrepared(true); }}
            >
              {t("classifier.rollout.prepare")}
            </Button>
            <Tooltip title={!prepared ? t("classifier.rollout.prepareFirst") : t("classifier.rollout.runtimeMissing")}>
              <span><Button disabled={!canControl} variant="contained" startIcon={<SecurityIcon />}>{t("classifier.rollout.canary")}</Button></span>
            </Tooltip>
            <Tooltip title={t("classifier.rollout.runtimeMissing")}><span><Button disabled={!canControl} color="success" startIcon={<CheckCircleIcon />}>{t("classifier.rollout.promote")}</Button></span></Tooltip>
            <Tooltip title={t("classifier.rollout.runtimeMissing")}><span><Button disabled={!canControl} color="error" startIcon={<RestartIcon />}>{t("classifier.rollout.rollback")}</Button></span></Tooltip>
          </Stack>
          {prepared && <Alert severity="success" sx={{ mt: 2 }}>{t("classifier.rollout.prepared")}</Alert>}
        </CardContent>
      </B4Card>
      <B4Card>
        <CardContent>
          <SectionTitle title={t("classifier.rollout.history")} />
          <Alert severity="info" sx={{ mb: 2 }}>{t("classifier.rollout.lastGoodUnavailable")}</Alert>
          {(bundle?.trace ?? []).filter((event) => event.kind.includes("promote") || event.kind.includes("rollback")).length === 0 ? (
            <EmptyState text={t("classifier.rollout.noHistory")} />
          ) : (
            <Stack gap={1}>{(bundle?.trace ?? []).filter((event) => event.kind.includes("promote") || event.kind.includes("rollback")).map((event, index) => (
              <Alert key={`${event.timestamp}-${index}`} severity={event.kind.includes("rollback") ? "warning" : "success"}>{fmtDate(event.timestamp)} · {event.kind} · {JSON.stringify(event.fields ?? {})}</Alert>
            ))}</Stack>
          )}
        </CardContent>
      </B4Card>
    </Stack>
  );
}

