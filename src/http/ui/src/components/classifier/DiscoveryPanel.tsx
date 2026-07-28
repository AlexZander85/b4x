import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { classifierApi } from "@api/classifier";
import { B4Card } from "@common/B4Card";
import { DiscoveryIcon } from "@b4.icons";
import type { IssueBundle } from "@models/classifier";
import { EmptyState, SectionTitle, fmtDate } from "./shared";

export function DiscoveryPanel({
  current,
  history,
  bundle,
}: Readonly<{
  current?: Awaited<ReturnType<typeof classifierApi.discoveryCurrent>>;
  history?: Awaited<ReturnType<typeof classifierApi.discoveryHistory>>;
  bundle?: IssueBundle;
}>) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const results = current?.domain_discovery_results
    ? Object.values(current.domain_discovery_results)
    : [];

  return (
    <Stack gap={2}>
      <Alert severity="warning">{t("classifier.discovery.manualOnly")}</Alert>
      <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.discovery.title")}
            description={t("classifier.discovery.description")}
            action={<Button startIcon={<DiscoveryIcon />} onClick={() => navigate("/discovery")}>{t("classifier.discovery.open")}</Button>}
          />
          {!current ? (
            <EmptyState text={t("classifier.discovery.noCurrent")} />
          ) : (
            <Stack gap={2}>
              <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                <Chip label={current.status} color={current.status === "complete" ? "success" : "primary"} />
                {current.current_phase && <Chip label={current.current_phase} variant="outlined" />}
                {current.current_domain && <Typography variant="body2">{current.current_domain}</Typography>}
              </Stack>
              <LinearProgress variant="determinate" value={current.total_checks ? (current.completed_checks / current.total_checks) * 100 : 0} />
              {results.map((result) => (
                <Alert key={result.domain} severity={result.best_success ? "success" : "error"}>
                  <strong>{result.domain}</strong>: {result.best_preset || "baseline-none"} · {Math.round(result.best_speed || 0)} B/s · improvement {Math.round(result.improvement || 0)}%
                </Alert>
              ))}
            </Stack>
          )}
        </CardContent>
      </B4Card>

      <B4Card>
        <CardContent>
          <SectionTitle title={t("classifier.discovery.causalVerdicts")} />
          {(bundle?.probe_outcomes ?? []).length === 0 ? (
            <EmptyState text={t("classifier.discovery.noVerdicts")} />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead><TableRow><TableCell>Profile</TableCell><TableCell>Verdict</TableCell><TableCell>Failure stage</TableCell><TableCell align="right">Body</TableCell><TableCell align="right">Throughput</TableCell></TableRow></TableHead>
                <TableBody>
                  {(bundle?.probe_outcomes ?? []).map((outcome, index) => (
                    <TableRow key={`${outcome.target_profile}-${index}`}>
                      <TableCell>{outcome.target_profile ?? "—"}</TableCell>
                      <TableCell><Chip size="small" label={outcome.verdict} /></TableCell>
                      <TableCell>{outcome.failure_stage ?? "—"}{outcome.failure_offset ? ` @ ${outcome.failure_offset}` : ""}</TableCell>
                      <TableCell align="right">{outcome.body_bytes}</TableCell>
                      <TableCell align="right">{outcome.throughput_bps}</TableCell>
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
          <SectionTitle title={t("classifier.discovery.history")} />
          {!history?.length ? <EmptyState text={t("classifier.discovery.noHistory")} /> : (
            <TableContainer>
              <Table size="small">
                <TableHead><TableRow><TableCell>Domain</TableCell><TableCell>Status</TableCell><TableCell>Winner</TableCell><TableCell>Baseline</TableCell><TableCell>Ended</TableCell></TableRow></TableHead>
                <TableBody>{history.slice(0, 50).map((entry) => (
                  <TableRow key={`${entry.domain}-${entry.end_time}`}>
                    <TableCell>{entry.domain}</TableCell><TableCell>{entry.status}</TableCell><TableCell>{entry.best_preset || "—"}</TableCell><TableCell>{Math.round(entry.baseline_speed || 0)} B/s</TableCell><TableCell>{fmtDate(entry.end_time)}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </B4Card>
    </Stack>
  );
}

