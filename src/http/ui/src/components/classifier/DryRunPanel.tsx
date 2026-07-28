import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import type { ClassifierConfigEnvelope } from "@models/classifier";
import { evaluateStrategyDryRun } from "@models/classifier";
import { SectionTitle, STRATEGIES, STRATEGY_CONFIG_KEYS } from "./shared";

export function DryRunPanel({ config }: Readonly<{ config?: ClassifierConfigEnvelope }>) {
  const { t } = useTranslation();
  const [setId, setSetId] = useState("");
  const [strategy, setStrategy] = useState(STRATEGIES[0]);
  const [confidence, setConfidence] = useState(80);
  const [ech, setECH] = useState(false);
  const [clearHost, setClearHost] = useState(true);
  const [amplification, setAmplification] = useState(2);
  const thresholds = config?.config.runtime.confidence ?? {
    classify: 50,
    mutate: 70,
    destructive: 90,
    proxy_fallback: 30,
  };
  const result = evaluateStrategyDryRun({
    setId,
    strategy,
    confidence,
    ech,
    clearHost,
    amplification,
    maxAmplification: config?.config.runtime.actions.max_amplification ?? 4,
    thresholds,
  });
  const enabled =
    config?.config.runtime.strategies?.[STRATEGY_CONFIG_KEYS[strategy]] ?? false;

  return (
    <Stack gap={2}>
      <Alert severity="info">{t("classifier.dryRun.noPackets")}</Alert>
      <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.dryRun.title")}
            description={t("classifier.dryRun.description")}
          />
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 3 }}>
            <Stack gap={2}>
              <TextField
                label={t("classifier.dryRun.setId")}
                value={setId}
                onChange={(event) => setSetId(event.target.value)}
                placeholder="SetID / strategy scope"
              />
              <TextField
                select
                label={t("classifier.dryRun.strategy")}
                value={strategy}
                onChange={(event) => setStrategy(event.target.value)}
              >
                {STRATEGIES.map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}
              </TextField>
              <Box>
                <Typography gutterBottom>{t("classifier.dryRun.confidence")}: {confidence}</Typography>
                <Slider min={0} max={100} value={confidence} onChange={(_, value) => setConfidence(value as number)} />
              </Box>
              <Box>
                <Typography gutterBottom>{t("classifier.dryRun.amplification")}: {amplification.toFixed(1)}×</Typography>
                <Slider min={1} max={8} step={0.5} value={amplification} onChange={(_, value) => setAmplification(value as number)} />
              </Box>
              <FormControlLabel control={<Switch checked={clearHost} onChange={(event) => setClearHost(event.target.checked)} />} label={t("classifier.dryRun.clearHost")} />
              <FormControlLabel control={<Switch checked={ech} onChange={(event) => setECH(event.target.checked)} />} label="ECH present" />
            </Stack>
            <Stack gap={2}>
              <Alert severity={result.allowed ? (result.level === "warning" ? "warning" : "success") : "error"}>
                <Typography fontWeight={700}>{result.allowed ? t("classifier.dryRun.allowed") : t("classifier.dryRun.blocked")}</Typography>
                <Typography variant="body2">required confidence: {result.requiredConfidence}</Typography>
              </Alert>
              {!enabled && (
                <Alert severity="warning">{t("classifier.dryRun.disabledStrategy")}</Alert>
              )}
              <Stack gap={1}>
                {result.reasons.map((reason) => (
                  <Typography key={reason} variant="body2">• {reason}</Typography>
                ))}
              </Stack>
              <Divider />
              <Typography variant="caption" color="text.secondary">
                max writes: {config?.config.runtime.actions.max_writes_per_hello ?? "—"} · max fake bytes: {config?.config.runtime.actions.max_fake_bytes ?? "—"} · configured amplification cap: {config?.config.runtime.actions.max_amplification ?? "—"}×
              </Typography>
            </Stack>
          </Box>
        </CardContent>
      </B4Card>
    </Stack>
  );
}

