import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, MenuItem,
  Stack, Switch, TextField, Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { classifierApi } from "@api/classifier";
import { B4Card } from "@common/B4Card";
import { DownloadIcon, RefreshIcon, WarningIcon } from "@b4.icons";
import { SectionTitle, StatusChip, short } from "./shared";

function activeGeneration(status: Awaited<ReturnType<typeof classifierApi.ppeStatus>> | undefined) {
  return status?.desired?.generation ?? "none";
}

export function PPEPanel({ advanced }: Readonly<{ advanced: boolean }>) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [endpoint, setEndpoint] = useState("");
  const [family, setFamily] = useState<"ipv4" | "ipv6">("ipv4");
  const [tcpPort, setTCPPort] = useState(49152);
  const [quicPort, setQUICPort] = useState(49153);
  const [requireQUIC, setRequireQUIC] = useState(true);

  const statusQuery = useQuery({
    queryKey: ["ppe-product-status"],
    queryFn: classifierApi.ppeStatus,
    refetchInterval: 5000,
  });
  const status = statusQuery.data;
  const enabled = status?.effective === "per-flow-exclusion";
  const canMutate = Boolean(status?.capabilities.supported);
  const generation = activeGeneration(status);

  const refresh = async () => {
    await statusQuery.refetch();
    await queryClient.invalidateQueries({ queryKey: ["classifier-issue-bundle"] });
  };

  const policyMutation = useMutation({
    mutationFn: async (next: boolean) => next
      ? classifierApi.ppeApply(generation)
      : classifierApi.ppeRollback(generation),
    onSuccess: refresh,
  });
  const selfTestMutation = useMutation({
    mutationFn: () => classifierApi.ppeSelfTest({
      expected_generation: generation,
      controlled_endpoint: endpoint || undefined,
      family,
      tcp_source_port: tcpPort,
      quic_source_port: requireQUIC ? quicPort : undefined,
      require_quic: requireQUIC,
      timeout_ms: 5000,
    }),
    onSuccess: refresh,
  });

  const error = policyMutation.error || selfTestMutation.error || statusQuery.error;
  const blockedFeatures = useMemo(() => (
    Object.entries(status?.features ?? {}) as Array<[string, { allowed: boolean }]>
  ).filter(([, decision]) => !decision.allowed)
    .map(([feature]) => feature), [status?.features]);

  const downloadBundle = async () => {
    const blob = await classifierApi.ppeIssueBundle();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "b4-ppe-issue-bundle.json";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <B4Card>
      <CardContent>
        <SectionTitle
          title={t("ppe.title")}
          description={t("ppe.description")}
        />

        <Alert severity="info" sx={{ mb: 2 }}>
          {t("ppe.beginnerSafety")}
        </Alert>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{String(error)}</Alert>}
        {!canMutate && (
          <Alert severity="warning" icon={<WarningIcon />} sx={{ mb: 2 }}>
            {t("ppe.unsupported")}
          </Alert>
        )}

        <Stack direction={{ xs: "column", md: "row" }} gap={2} justifyContent="space-between">
          <Box>
            <FormControlLabel
              control={(
                <Switch
                  checked={enabled}
                  disabled={!canMutate || policyMutation.isPending}
                  onChange={(_, checked) => policyMutation.mutate(checked)}
                />
              )}
              label={t("ppe.toggle")}
            />
            <Typography variant="body2" color="text.secondary">
              {enabled ? t("ppe.modeExclude") : t("ppe.modeMonitor")}
            </Typography>
          </Box>
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center">
            <StatusChip ok={Boolean(status?.rules_present)} label={status?.rules_present ? t("ppe.rulesPresent") : t("ppe.rulesMissing")} />
            <Chip size="small" label={`${t("ppe.visibility")}: ${status?.visibility.mode ?? "unknown"}`} color={status?.visibility.mode === "complete" ? "success" : "warning"} />
            <Button startIcon={<RefreshIcon />} onClick={() => void refresh()}>{t("ppe.refresh")}</Button>
            <Button startIcon={<DownloadIcon />} onClick={() => void downloadBundle()}>{t("ppe.bundle")}</Button>
          </Stack>
        </Stack>

        <Divider sx={{ my: 2 }} />
        <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 1.5 }}>
          <Box>
            <Typography variant="caption" color="text.secondary">{t("ppe.generation")}</Typography>
            <Typography fontFamily="monospace">{short(status?.desired?.generation, 24)}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">{t("ppe.scope")}</Typography>
            <Typography>{status?.desired?.source_scope ?? "—"}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">{t("ppe.tcpPorts")}</Typography>
            <Typography>{status?.desired?.effective_tcp_ports?.join(", ") || "—"}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">{t("ppe.udpPorts")}</Typography>
            <Typography>{status?.desired?.effective_udp_ports?.join(", ") || "—"}</Typography>
          </Box>
        </Box>

        {status?.visibility.reason && (
          <Alert severity={status.visibility.mode === "complete" ? "success" : "warning"} sx={{ mt: 2 }}>
            {status.visibility.reason}
          </Alert>
        )}
        {blockedFeatures.length > 0 && (
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
            {t("ppe.blockedFeatures")}: {blockedFeatures.join(", ")}
          </Typography>
        )}

        {advanced && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle1" fontWeight={700}>{t("ppe.advancedTitle")}</Typography>
            <Alert severity="warning" sx={{ my: 1.5 }}>{t("ppe.noGlobalClaim")}</Alert>
            <Stack direction={{ xs: "column", lg: "row" }} gap={1.5} alignItems={{ lg: "center" }}>
              <TextField
                label={t("ppe.endpoint")}
                value={endpoint}
                onChange={(event) => setEndpoint(event.target.value)}
                placeholder="https://controlled.example/health"
                fullWidth
              />
              <TextField select label={t("ppe.family")} value={family} onChange={(event) => setFamily(event.target.value as "ipv4" | "ipv6")} sx={{ minWidth: 120 }}>
                <MenuItem value="ipv4">IPv4</MenuItem>
                <MenuItem value="ipv6">IPv6</MenuItem>
              </TextField>
              <TextField label={t("ppe.tcpSourcePort")} type="number" value={tcpPort} onChange={(event) => setTCPPort(Number(event.target.value))} sx={{ minWidth: 150 }} />
              <TextField disabled={!requireQUIC} label={t("ppe.quicSourcePort")} type="number" value={quicPort} onChange={(event) => setQUICPort(Number(event.target.value))} sx={{ minWidth: 160 }} />
            </Stack>
            <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }} sx={{ mt: 1.5 }}>
              <FormControlLabel control={<Switch checked={requireQUIC} onChange={(_, checked) => setRequireQUIC(checked)} />} label={t("ppe.requireQuic")} />
              <Button
                variant="outlined"
                disabled={!enabled || selfTestMutation.isPending || tcpPort < 1 || tcpPort > 65535}
                onClick={() => selfTestMutation.mutate()}
              >
                {t("ppe.runSelfTest")}
              </Button>
              {status?.last_self_test && (
                <Chip
                  label={`${status.last_self_test.run_id}: ${status.last_self_test.verdict}`}
                  color={status.last_self_test.production_ready ? "success" : "warning"}
                />
              )}
            </Stack>
          </>
        )}
      </CardContent>
    </B4Card>
  );
}
