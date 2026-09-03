import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import type { IssueBundle } from "@models/classifier";
import { deriveFlowDiagnostics } from "@models/classifier";
import { EmptyState, SectionTitle, fmtDate, short } from "./shared";

export function FlowsPanel({ bundle }: Readonly<{ bundle?: IssueBundle }>) {
  const { t } = useTranslation();
  const flows = useMemo(
    () => deriveFlowDiagnostics(bundle?.trace ?? []),
    [bundle?.trace],
  );
  const actionCounters = (bundle?.metrics.counters ?? []).filter((sample) =>
    sample.name.startsWith("tcp_action_") || sample.name === "tcp_action_token_reuse_total",
  );

  return (
    <Stack gap={2}>
      <Alert severity="info">{t("classifier.flows.actionVisibility")}</Alert>
      <B4Card>
      <CardContent>
        <SectionTitle
          title={t("classifier.flows.title")}
          description={t("classifier.flows.description")}
        />
        {flows.length === 0 ? (
          <EmptyState text={t("classifier.flows.empty")} />
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Flow</TableCell>
                  <TableCell>Client</TableCell>
                  <TableCell>FSM phase</TableCell>
                  <TableCell>Evidence</TableCell>
                  <TableCell>Reassembly</TableCell>
                  <TableCell>Last event</TableCell>
                  <TableCell>Updated</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {flows.slice(0, 128).map((flow) => (
                  <TableRow key={flow.id} hover>
                    <TableCell sx={{ fontFamily: "monospace" }}>{short(flow.id)}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{short(flow.clientId)}</TableCell>
                    <TableCell><Chip size="small" label={flow.phase} /></TableCell>
                    <TableCell>
                      {flow.source ?? "—"}
                      {flow.confidence !== undefined && ` · ${flow.confidence}`}
                      {flow.setId && ` · ${short(flow.setId, 10)}`}
                    </TableCell>
                    <TableCell>{flow.reassembly}</TableCell>
                    <TableCell>{flow.lastKind}</TableCell>
                    <TableCell>{fmtDate(flow.lastSeen)}</TableCell>
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
          <SectionTitle title={t("classifier.flows.actionCounters")} />
          {actionCounters.length === 0 ? (
            <EmptyState text={t("classifier.flows.noActionCounters")} />
          ) : (
            <Stack gap={1}>
              {actionCounters.map((sample, index) => (
                <Alert key={`${sample.name}-${index}`} severity="info">
                  <strong>{sample.name}</strong> · {Object.entries(sample.labels ?? {}).map(([key, value]) => `${key}=${value}`).join(", ") || "unlabelled"} · {sample.value}
                </Alert>
              ))}
            </Stack>
          )}
        </CardContent>
      </B4Card>
    </Stack>
  );
}

