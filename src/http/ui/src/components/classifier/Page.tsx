import {
  Alert, Box, Button, Container, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, LinearProgress, Stack, Switch, Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { classifierApi } from "@api/classifier";
import { B4Card } from "@common/B4Card";
import { DownloadIcon, FingerprintIcon, RefreshIcon } from "@b4.icons";
import { colors } from "@design";
import { ClientHelloPanel } from "./ClientHelloPanel";
import { DiscoveryPanel } from "./DiscoveryPanel";
import { DryRunPanel } from "./DryRunPanel";
import { FailureInboxPanel } from "./FailureInboxPanel";
import { FlowsPanel } from "./FlowsPanel";
import { HardeningPanel } from "./HardeningPanel";
import { OverviewPanel } from "./OverviewPanel";
import { PPEPanel } from "./PPEPanel";
import { RolloutPanel } from "./RolloutPanel";

export function ClassifierPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState(0);
  const [advanced, setAdvanced] = useState(false);
  const [privacyDialog, setPrivacyDialog] = useState(false);
  const [rawConfirmed, setRawConfirmed] = useState(false);

  const configQuery = useQuery({ queryKey: ["classifier-v23-config"], queryFn: classifierApi.config });
  const isolationQuery = useQuery({ queryKey: ["classifier-v23-isolation"], queryFn: classifierApi.isolation, refetchInterval: 5000 });
  const hardeningQuery = useQuery({
    queryKey: ["classifier-hardening-v1"], queryFn: classifierApi.hardening, enabled: advanced,
    refetchInterval: advanced ? 5000 : false,
  });
  const bundleQuery = useQuery({ queryKey: ["classifier-issue-bundle"], queryFn: classifierApi.issueBundle, refetchInterval: 5000 });
  const failuresQuery = useQuery({ queryKey: ["classifier-failures"], queryFn: classifierApi.failures, refetchInterval: 5000 });
  const profilesQuery = useQuery({ queryKey: ["classifier-clienthello"], queryFn: classifierApi.clientHelloProfiles, refetchInterval: 10000 });
  const discoveryCurrentQuery = useQuery({ queryKey: ["classifier-discovery-current"], queryFn: classifierApi.discoveryCurrent, refetchInterval: 5000 });
  const discoveryHistoryQuery = useQuery({ queryKey: ["classifier-discovery-history"], queryFn: classifierApi.discoveryHistory });

  const isLoading = configQuery.isLoading || bundleQuery.isLoading || isolationQuery.isLoading;
  const error = configQuery.error || bundleQuery.error || isolationQuery.error;
  const tabs = [
    t("classifier.tabs.overview"),
    t("classifier.tabs.flows"),
    t("classifier.tabs.dryRun"),
    t("classifier.tabs.discovery"),
    t("classifier.tabs.inbox"),
    t("classifier.tabs.lab"),
    t("classifier.tabs.rollout"),
  ];

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  const exportConfig = async (includeRaw = false) => {
    const blob = await classifierApi.exportConfig(includeRaw, includeRaw);
    downloadBlob(blob, includeRaw ? "b4-classifier-v23-confirmed.json" : "b4-classifier-v23.json");
  };
  const exportIssueBundle = async () => {
    const response = await fetch("/api/diagnostics/issue-bundle");
    if (!response.ok) throw new Error(`Issue bundle export failed (${response.status})`);
    downloadBlob(await response.blob(), "b4-classifier-issue-bundle.json");
  };
  const refetchAll = () => {
    void Promise.all([
      configQuery.refetch(), isolationQuery.refetch(), bundleQuery.refetch(), failuresQuery.refetch(), profilesQuery.refetch(),
      ...(advanced ? [hardeningQuery.refetch()] : []),
      discoveryCurrentQuery.refetch(), discoveryHistoryQuery.refetch(),
    ]);
  };

  return (
    <Container maxWidth={false} sx={{ py: 3, overflow: "auto" }}>
      <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" alignItems={{ xs: "stretch", md: "center" }} gap={2} sx={{ mb: 2 }}>
        <Box>
          <Stack direction="row" alignItems="center" gap={1}>
            <FingerprintIcon color="primary" />
            <Typography variant="h5" fontWeight={800}>{t("classifier.title")}</Typography>
          </Stack>
          <Typography color="text.secondary">{t("classifier.description")}</Typography>
        </Box>
        <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
          <FormControlLabel control={<Switch checked={advanced} onChange={(event) => setAdvanced(event.target.checked)} />} label={t("classifier.advanced")} />
          <Button startIcon={<RefreshIcon />} onClick={refetchAll}>{t("classifier.refresh")}</Button>
          <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => void exportConfig(false)}>{t("classifier.safeExport")}</Button>
        </Stack>
      </Stack>

      <Alert severity="info" sx={{ mb: 2 }}>{t("classifier.safetyBanner")}</Alert>
      {isLoading && <LinearProgress sx={{ mb: 2 }} />}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{String(error)}</Alert>}

      <B4Card sx={{ mb: 2 }}>
        <Box sx={{ borderBottom: `1px solid ${colors.border.default}`, overflowX: "auto" }}>
          <Stack direction="row" sx={{ minWidth: 760 }}>
            {tabs.map((label, index) => (
              <Button
                key={label}
                onClick={() => setTab(index)}
                sx={{ borderRadius: 0, px: 2, py: 1.5, borderBottom: tab === index ? `2px solid ${colors.secondary}` : "2px solid transparent", color: tab === index ? colors.secondary : colors.text.secondary }}
              >{label}</Button>
            ))}
          </Stack>
        </Box>
      </B4Card>

      {tab === 0 && (
        <Stack gap={2}>
          <PPEPanel advanced={advanced} />
          {advanced && (
            <HardeningPanel
              status={hardeningQuery.data}
              metrics={bundleQuery.data?.metrics}
              loading={hardeningQuery.isLoading}
              error={hardeningQuery.error}
            />
          )}
          <OverviewPanel config={configQuery.data} isolation={isolationQuery.data} bundle={bundleQuery.data} advanced={advanced} />
        </Stack>
      )}
      {tab === 1 && <FlowsPanel bundle={bundleQuery.data} />}
      {tab === 2 && <DryRunPanel config={configQuery.data} />}
      {tab === 3 && <DiscoveryPanel current={discoveryCurrentQuery.data} history={discoveryHistoryQuery.data} bundle={bundleQuery.data} />}
      {tab === 4 && <FailureInboxPanel candidates={failuresQuery.data?.candidates ?? []} onExport={() => void exportIssueBundle()} />}
      {tab === 5 && <ClientHelloPanel profiles={profilesQuery.data?.profiles ?? []} advanced={advanced} onRawExport={() => setPrivacyDialog(true)} />}
      {tab === 6 && <RolloutPanel config={configQuery.data} bundle={bundleQuery.data} />}

      <Dialog open={privacyDialog} onClose={() => setPrivacyDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("classifier.privacy.title")}</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>{t("classifier.privacy.warning")}</Alert>
          <FormControlLabel control={<Switch checked={rawConfirmed} onChange={(event) => setRawConfirmed(event.target.checked)} />} label={t("classifier.privacy.confirm")} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPrivacyDialog(false)}>{t("classifier.cancel")}</Button>
          <Button disabled={!rawConfirmed} color="warning" variant="contained" onClick={() => { void exportConfig(true); setPrivacyDialog(false); setRawConfirmed(false); }}>{t("classifier.privacy.export")}</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}
