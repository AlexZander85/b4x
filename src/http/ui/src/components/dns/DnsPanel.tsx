import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Box,
  Button,
  CircularProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { DnsIcon, RefreshIcon } from "@b4.icons";
import { colors } from "@design";
import {
  B4Accordion,
  B4Badge,
  B4NumberField,
  B4Section,
  B4Select,
  B4Switch,
  B4TextField,
} from "@b4.elements";
import { useDns } from "@hooks/useDns";
import { useSnackbar } from "@context/SnackbarProvider";
import { DNSAdaptivePolicy, DNSMode, DNSStatus } from "@models/dns";

const MODES: DNSMode[] = ["current", "manual", "adaptive", "diagnostic"];

// §20: beginner UI must not show a green Healthy when the profile is
// missing/stale, fallbacks are absent or rollback is impossible.
function honestVerdict(status: DNSStatus): {
  key: "healthy" | "degraded" | "unavailable";
  ok: boolean;
} {
  const healthy =
    status.verdict === "healthy" &&
    !!status.profile_id &&
    (status.fallbacks?.length ?? 0) > 0;
  if (healthy) return { key: "healthy", ok: true };
  if (status.primary) return { key: "degraded", ok: false };
  return { key: "unavailable", ok: false };
}

function StatusBadge({ status }: Readonly<{ status: DNSStatus }>) {
  const { t } = useTranslation();
  const v = honestVerdict(status);
  const color = v.ok ? "primary" : v.key === "degraded" ? "secondary" : "default";
  return (
    <B4Badge
      label={t(`dns.verdict.${v.key}`)}
      color={color}
      variant={v.ok ? "filled" : "outlined"}
    />
  );
}

function ReasonList({ status }: Readonly<{ status: DNSStatus }>) {
  const { t } = useTranslation();
  const d = status.diagnosis;
  if (!d) return null;
  const reasons: string[] = [];
  if (d.udp_injection_suspected) reasons.push(t("dns.reason.udpInjection"));
  if (d.poisoning_detected) reasons.push(t("dns.reason.poisoning"));
  if (d.port53_blocked) reasons.push(t("dns.reason.port53Blocked"));
  if (reasons.length === 0) reasons.push(t("dns.reason.controlsPassed"));
  return (
    <Box>
      <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
        {t("dns.reasonTitle")}
      </Typography>
      {reasons.map((r) => (
        <Typography key={r} variant="body2" color="text.secondary">
          {"\u2022"} {r}
        </Typography>
      ))}
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
        {t("dns.confidence", { value: Math.round(d.confidence * 100) })}
      </Typography>
    </Box>
  );
}

function PolicyForm({
  policy,
  disabled,
  onSave,
}: Readonly<{
  policy: DNSAdaptivePolicy;
  disabled: boolean;
  onSave: (next: DNSAdaptivePolicy) => void;
}>) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<DNSAdaptivePolicy>(policy);
  const set = <K extends keyof DNSAdaptivePolicy>(
    key: K,
    value: DNSAdaptivePolicy[K],
  ) => setDraft((d) => ({ ...d, [key]: value }));

  const boolKeys = [
    "enabled",
    "allow_native_classic",
    "allow_native_encrypted",
    "allow_managed_dnscrypt_backend",
    "allow_anonymized_dnscrypt",
    "allow_odoh",
    "allow_pqdnscrypt",
    "require_dnssec_capable",
    "require_nolog_claim",
    "require_nofilter_claim",
  ] as const;

  const numKeys = [
    { key: "max_quick_candidates" as const, min: 1, max: 64 },
    { key: "max_deep_candidates" as const, min: 1, max: 128 },
    { key: "max_parallel_probes" as const, min: 1, max: 8 },
  ];

  const durKeys = [
    "cooldown",
    "failed_search_cooldown",
    "recovery_hysteresis",
    "profile_ttl",
  ] as const;

  return (
    <Stack spacing={2}>
      <Stack direction="row" flexWrap="wrap" gap={1}>
        {boolKeys.map((k) => (
          <Box key={k} sx={{ minWidth: 260, flex: "1 1 30%" }}>
            <B4Switch
              label={t(`dns.policy.${k}`)}
              checked={draft[k]}
              disabled={disabled}
              onChange={(v) => set(k, v)}
            />
          </Box>
        ))}
      </Stack>
      <B4Select
        label={t("dns.policy.preference")}
        value={draft.preference}
        disabled={disabled}
        onChange={(e) =>
          set("preference", e.target.value as DNSAdaptivePolicy["preference"])
        }
        options={[
          { value: "lowest-latency", label: t("dns.pref.lowestLatency") },
          { value: "balanced", label: t("dns.pref.balanced") },
          { value: "privacy", label: t("dns.pref.privacy") },
          { value: "minimum-dependency", label: t("dns.pref.minDependency") },
        ]}
      />
      <Stack direction="row" flexWrap="wrap" gap={2}>
        {numKeys.map(({ key, min, max }) => (
          <B4NumberField
            key={key}
            label={t(`dns.policy.${key}`)}
            value={draft[key]}
            min={min}
            max={max}
            disabled={disabled}
            onChange={(n) => set(key, n)}
          />
        ))}
        {durKeys.map((k) => (
          <B4TextField
            key={k}
            label={t(`dns.policy.${k}`)}
            value={draft[k]}
            disabled={disabled}
            onChange={(e) => set(k, e.target.value)}
          />
        ))}
      </Stack>
      <Box>
        <Button
          variant="contained"
          disabled={disabled}
          onClick={() => onSave(draft)}
        >
          {t("dns.applyPolicy")}
        </Button>
      </Box>
    </Stack>
  );
}

export function DnsPanel() {
  const { t } = useTranslation();
  const { showError, showSuccess } = useSnackbar();
  const {
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
  } = useDns();

  const onError = (err: unknown) =>
    showError(err instanceof Error ? err.message : String(err));

  if (loading || !status) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  return (
    <Stack spacing={3}>
      <B4Section
        title={t("dns.title")}
        description={t("dns.description")}
        icon={<DnsIcon />}
        action={
          <Button
            size="small"
            startIcon={<RefreshIcon />}
            onClick={() => void refresh()}
            disabled={busy}
          >
            {t("dns.refresh")}
          </Button>
        }
      >
        <Stack spacing={2}>
          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
            <B4Select
              label={t("dns.mode")}
              value={status.mode}
              disabled={busy}
              onChange={(e) =>
                updateConfig(e.target.value as DNSMode, policy ?? undefined).catch(
                  onError,
                )
              }
              options={MODES.map((m) => ({
                value: m,
                label: t(`dns.modes.${m}`),
              }))}
            />
            <StatusBadge status={status} />
            {status.rollback_ready && (
              <B4Badge
                label={t("dns.rollbackReady")}
                color="primary"
                variant="outlined"
              />
            )}
          </Stack>

          {status.primary && (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{t("dns.table.role")}</TableCell>
                    <TableCell>{t("dns.table.family")}</TableCell>
                    <TableCell>{t("dns.table.health")}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>{t("dns.table.primary")}</TableCell>
                    <TableCell>{status.primary.family}</TableCell>
                    <TableCell>{status.primary.health}</TableCell>
                  </TableRow>
                  {(status.fallbacks ?? []).map((fb, i) => (
                    <TableRow key={`${fb.family}-${i}`}>
                      <TableCell>
                        {t("dns.table.fallback", { index: i + 1 })}
                      </TableCell>
                      <TableCell>{fb.family}</TableCell>
                      <TableCell>{fb.health}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          <ReasonList status={status} />

          {lastDiagnosis && (
            <Box
              sx={{
                p: 1.5,
                border: `1px solid ${colors.border.default}`,
                borderRadius: 1,
              }}
            >
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                {t("dns.lastDiagnosis")}
              </Typography>
              {lastDiagnosis.result.explanation.map((line) => (
                <Typography key={line} variant="body2" color="text.secondary">
                  {"\u2022"} {line}
                </Typography>
              ))}
            </Box>
          )}

          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Button
              variant="outlined"
              disabled={busy}
              onClick={() =>
                diagnose()
                  .then(() => showSuccess(t("dns.diagnoseDone")))
                  .catch(onError)
              }
            >
              {t("dns.actions.diagnose")}
            </Button>
            <Button
              variant="outlined"
              disabled={busy}
              onClick={() =>
                revalidate()
                  .then((r) =>
                    r.revalidated
                      ? showSuccess(t("dns.revalidateOk"))
                      : showError(r.reason ?? t("dns.revalidateFail")),
                  )
                  .catch(onError)
              }
            >
              {t("dns.actions.revalidate")}
            </Button>
            <Button
              variant="outlined"
              color="error"
              disabled={busy || !status.rollback_ready}
              onClick={() =>
                rollback()
                  .then((r) =>
                    r.rolled_back
                      ? showSuccess(t("dns.rollbackDone"))
                      : showError(r.reason ?? t("dns.rollbackFail")),
                  )
                  .catch(onError)
              }
            >
              {t("dns.actions.rollback")}
            </Button>
          </Stack>
        </Stack>
      </B4Section>

      {policy && (
        <B4Section title={t("dns.advancedTitle")} icon={<DnsIcon />}>
          <B4Accordion title={t("dns.advancedAccordion")}>
            <PolicyForm
              policy={policy}
              disabled={busy}
              onSave={(next) =>
                updateConfig(status.mode, next)
                  .then(() => showSuccess(t("dns.policySaved")))
                  .catch(onError)
              }
            />
          </B4Accordion>
        </B4Section>
      )}

      {providers.length > 0 && (
        <B4Section title={t("dns.providersTitle")} icon={<DnsIcon />}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{t("dns.table.family")}</TableCell>
                  <TableCell>{t("dns.table.state")}</TableCell>
                  <TableCell>{t("dns.table.reason")}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {providers.map((p) => (
                  <TableRow key={p.hash}>
                    <TableCell>{p.family}</TableCell>
                    <TableCell>{p.state}</TableCell>
                    <TableCell>{p.reason ?? "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </B4Section>
      )}
    </Stack>
  );
}
