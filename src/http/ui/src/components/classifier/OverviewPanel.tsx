import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import { WarningIcon } from "@b4.icons";
import type { ClassifierConfigEnvelope, ClassifierIsolationStatus, IssueBundle } from "@models/classifier";
import { EmptyState, SectionTitle, StatusChip, short } from "./shared";

export function OverviewPanel({
  config,
  isolation,
  bundle,
  advanced,
}: Readonly<{
  config?: ClassifierConfigEnvelope;
  isolation?: ClassifierIsolationStatus;
  bundle?: IssueBundle;
  advanced: boolean;
}>) {
  const { t } = useTranslation();
  const flags = config?.config.flags;
  const evidence = bundle?.evidence ?? [];
  const queue = bundle?.queue;
  const captureCounters = (bundle?.metrics.counters ?? []).filter((sample) =>
    sample.name.startsWith("capture_"),
  );

  return (
    <Stack gap={2}>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 2,
        }}
      >
        <B4Card>
          <CardContent>
            <Typography color="text.secondary" variant="caption">
              {t("classifier.generation")}
            </Typography>
            <Typography fontFamily="monospace" fontWeight={700} sx={{ mt: 1 }}>
              {short(config?.runtime_generation, 26)}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              API {config?.api_version ?? "—"} · schema {config?.schema_version ?? "—"}
            </Typography>
          </CardContent>
        </B4Card>
        <B4Card>
          <CardContent>
            <Typography color="text.secondary" variant="caption">
              {t("classifier.capture.title")}
            </Typography>
            <Stack direction="row" gap={1} alignItems="center" sx={{ mt: 1 }}>
              <StatusChip ok={Boolean(queue?.ready)} label={queue?.status ?? "unknown"} />
              <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.isolation.title")}
            description={t("classifier.isolation.description")}
          />
          {isolation?.warnings?.length ? (
            <Alert severity="warning" sx={{ mb: 2 }}>
              {t("classifier.isolation.unsafeLegacy", { count: isolation.warnings.length })}
            </Alert>
          ) : null}
          <Stack direction={{ xs: "column", md: "row" }} gap={1} sx={{ mb: 2 }}>
            <StatusChip
              ok={isolation?.negative_control.status === "passed"}
              label={t(`classifier.isolation.negative.${isolation?.negative_control.status ?? "not_run"}`)}
            />
            <Chip
              size="small"
              label={`${t("classifier.isolation.unrelatedActions")}: ${isolation?.negative_control.unrelated_control_action_total ?? 0}`}
              color={(isolation?.negative_control.unrelated_control_action_total ?? 0) === 0 ? "success" : "error"}
            />
            <Chip size="small" variant="outlined" label={isolation?.raw_hostnames ? "raw hostnames" : t("classifier.isolation.redacted")} />
          </Stack>
          {(isolation?.sets.length ?? 0) === 0 ? (
            <EmptyState text={t("classifier.isolation.empty")} />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{t("classifier.evidence.set")}</TableCell>
                    <TableCell>{t("classifier.isolation.configured")}</TableCell>
                    <TableCell>{t("classifier.isolation.effective")}</TableCell>
                    <TableCell>{t("classifier.isolation.state")}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {isolation?.sets.slice(0, advanced ? 100 : 12).map((item) => (
                    <TableRow key={item.set_id}>
                      <TableCell sx={{ fontFamily: "monospace" }}>{short(item.set_id, 28)}</TableCell>
                      <TableCell>{item.configured_policy}</TableCell>
                      <TableCell><Chip size="small" label={item.effective_policy} /></TableCell>
                      <TableCell>
                        {item.unsafe_legacy ? (
                          <Chip size="small" color="error" label={item.reason_code || "unsafe legacy"} />
                        ) : item.migration_required ? (
                          <Chip size="small" color="warning" label={`→ ${item.migration_target}`} />
                        ) : (
                          <Chip size="small" color="success" label={t("classifier.isolation.scoped")} />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          {advanced && (isolation?.recent_events?.length ?? 0) > 0 && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>{t("classifier.isolation.recentEvents")}</Typography>
              <Stack gap={0.5}>
                {isolation?.recent_events?.slice(-8).reverse().map((event, index) => (
                  <Typography key={`${event.timestamp}-${index}`} variant="caption" fontFamily="monospace">
                    {event.kind} · {event.fields?.disposition ?? event.fields?.result ?? event.fields?.reason ?? "—"}
                  </Typography>
                ))}
              </Stack>
            </>
          )}
        </CardContent>
      </B4Card>

      {queue?.offload_suspected && (
                <Chip size="small" color="error" label="offload suspected" />
              )}
            </Stack>
            <Typography variant="caption" color="text.secondary">
              drops: {queue?.queue_drops ?? 0} / userspace: {queue?.user_drops ?? 0}
            </Typography>
          </CardContent>
        </B4Card>
        <B4Card>
          <CardContent>
            <Typography color="text.secondary" variant="caption">
              {t("classifier.domainMode")}
            </Typography>
            <Typography fontWeight={700} sx={{ mt: 1 }}>
              {config?.config.domain_only_mode ?? "—"}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              reassembly: {flags?.tcp_reassembly_mode ?? "—"} · hold: {flags?.tcp_hold_replay_mode ?? "—"}
            </Typography>
          </CardContent>
        </B4Card>
        <B4Card>
          <CardContent>
            <Typography color="text.secondary" variant="caption">
              {t("classifier.evidence.title")}
            </Typography>
            <Typography fontWeight={700} sx={{ mt: 1 }}>
              {evidence.length}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              fresh: {evidence.filter((item) => item.fresh).length} · ECH: {evidence.filter((item) => item.ech).length}
            </Typography>
          </CardContent>
        </B4Card>
      </Box>

      {queue?.offload_suspected && (
        <Alert severity="error" icon={<WarningIcon />}>
          {t("classifier.capture.offloadWarning")}
        </Alert>
      )}
      {!queue?.ready && (
        <Alert severity="warning">{t("classifier.capture.notReady")}</Alert>
      )}

      <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.evidence.title")}
            description={t("classifier.evidence.description")}
          />
          {evidence.length === 0 ? (
            <EmptyState text={t("classifier.evidence.empty")} />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{t("classifier.evidence.source")}</TableCell>
                    <TableCell>{t("classifier.evidence.set")}</TableCell>
                    <TableCell>{t("classifier.evidence.domain")}</TableCell>
                    <TableCell align="right">{t("classifier.evidence.confidence")}</TableCell>
                    <TableCell>{t("classifier.evidence.state")}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {evidence.slice(0, advanced ? 100 : 12).map((item, index) => (
                    <TableRow key={`${item.source}-${index}`}>
                      <TableCell>{item.source}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{short(item.set_id)}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{short(item.domain_id)}</TableCell>
                      <TableCell align="right">{item.confidence}</TableCell>
                      <TableCell>
                        <Stack direction="row" gap={0.5}>
                          <Chip size="small" label={item.fresh ? "fresh" : "stale"} color={item.fresh ? "success" : "default"} />
                          {item.ech && <Chip size="small" label="ECH" />}
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </B4Card>

      <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.capture.counters")}
            description={t("classifier.capture.countersDescription")}
          />
          {captureCounters.length === 0 ? (
            <EmptyState text={t("classifier.capture.noCounters")} />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Metric</TableCell>
                    <TableCell>Labels</TableCell>
                    <TableCell align="right">Value</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {captureCounters.map((sample, index) => (
                    <TableRow key={`${sample.name}-${index}`}>
                      <TableCell sx={{ fontFamily: "monospace" }}>{sample.name}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>
                        {Object.entries(sample.labels ?? {})
                          .map(([key, value]) => `${key}=${value}`)
                          .join(", ") || "—"}
                      </TableCell>
                      <TableCell align="right">{sample.value}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </B4Card>

      {advanced && flags && (
        <B4Card>
          <CardContent>
            <SectionTitle title={t("classifier.flags")} />
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {Object.entries(flags).map(([name, value]) => (
                <Chip
                  key={name}
                  label={`${name}: ${String(value)}`}
                  color={value === true ? "success" : "default"}
                  variant="outlined"
                />
              ))}
            </Box>
          </CardContent>
        </B4Card>
      )}
    </Stack>
  );
}

