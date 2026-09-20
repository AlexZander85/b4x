import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { useTranslation } from "react-i18next";
import { TunnelCard as TunnelCardModel, TunnelHealth } from "@models/tunnels";
import { TunnelKind } from "@models/config";

interface TunnelHealthDashboardProps {
  cards: TunnelCardModel[];
  // The kind currently being measured, or "__all__" for a measure-all run.
  measuring: string | null;
  onMeasure: (kind?: TunnelKind) => void;
}

const VERDICT_COLOR: Record<
  string,
  "success" | "warning" | "error" | "default"
> = {
  healthy: "success",
  degraded: "warning",
  poor: "error",
  unavailable: "default",
};

function fmtTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getFullYear() <= 1) return "—";
  return d.toLocaleTimeString();
}

// TunnelHealthDashboard is the on-demand health/benchmark surface
// (TUNNELS_PANEL_DESIGN.md §8): availability/latency/throughput/loss and a
// score per tunnel, refreshed only when the operator asks. It is a
// RECOMMENDATION surface — it never changes which tunnel routes traffic.
export function TunnelHealthDashboard({
  cards,
  measuring,
  onMeasure,
}: TunnelHealthDashboardProps) {
  const { t } = useTranslation();

  let bestKind: string | null = null;
  let bestScore = -1;
  for (const c of cards) {
    if (c.health?.available && c.health.score > bestScore) {
      bestScore = c.health.score;
      bestKind = c.kind;
    }
  }
  const anyHealth = cards.some((c) => c.health);
  const busy = measuring !== null;

  return (
    <Box>
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        sx={{ mb: 1 }}
      >
        <Typography variant="body2" color="text.secondary">
          {t("tunnels.health.description")}
        </Typography>
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          startIcon={
            measuring === "__all__" ? <CircularProgress size={14} /> : undefined
          }
          onClick={() => onMeasure()}
        >
          {measuring === "__all__"
            ? t("tunnels.health.measuring")
            : t("tunnels.health.measureAll")}
        </Button>
      </Stack>

      <Box sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>{t("tunnels.health.colTunnel")}</TableCell>
              <TableCell>{t("tunnels.health.colVerdict")}</TableCell>
              <TableCell align="right">
                {t("tunnels.health.colScore")}
              </TableCell>
              <TableCell align="right">{t("tunnels.health.colRtt")}</TableCell>
              <TableCell align="right">
                {t("tunnels.health.colTtfb")}
              </TableCell>
              <TableCell align="right">
                {t("tunnels.health.colThroughput")}
              </TableCell>
              <TableCell align="right">
                {t("tunnels.health.colLoss")}
              </TableCell>
              <TableCell>{t("tunnels.health.colMeasured")}</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {cards.length === 0 && (
              <TableRow>
                <TableCell colSpan={9}>
                  <Typography variant="caption" color="text.secondary">
                    {t("tunnels.health.empty")}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
            {cards.map((c) => {
              const h: TunnelHealth | undefined = c.health;
              const rowBusy = measuring === c.kind;
              return (
                <TableRow key={c.kind} hover>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Typography sx={{ fontWeight: 600 }}>
                        {t(`tunnels.kind.${c.kind}`)}
                      </Typography>
                      {bestKind === c.kind && (
                        <Chip
                          size="small"
                          color="primary"
                          label={t("tunnels.health.best")}
                        />
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    {h ? (
                      <Chip
                        size="small"
                        variant="outlined"
                        color={VERDICT_COLOR[h.verdict] ?? "default"}
                        label={t(`tunnels.health.verdict.${h.verdict}`, {
                          defaultValue: h.verdict,
                        })}
                      />
                    ) : (
                      <Typography variant="caption" color="text.secondary">
                        {t("tunnels.health.never")}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    {h ? h.score.toFixed(1) : "—"}
                  </TableCell>
                  <TableCell align="right">
                    {h?.rtt_ms != null ? `${h.rtt_ms} ms` : "—"}
                  </TableCell>
                  <TableCell align="right">
                    {h?.ttfb_ms != null ? `${h.ttfb_ms} ms` : "—"}
                  </TableCell>
                  <TableCell align="right">
                    {h?.throughput_mbps != null
                      ? `${h.throughput_mbps.toFixed(2)} Mbps`
                      : "—"}
                  </TableCell>
                  <TableCell align="right">
                    {h?.loss_pct != null ? `${h.loss_pct.toFixed(0)}%` : "—"}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">
                      {fmtTime(h?.measured_at)}
                    </Typography>
                    {h?.error && (
                      <Typography
                        variant="caption"
                        color="error"
                        sx={{ display: "block" }}
                        title={h.error}
                      >
                        {h.error}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Button
                      size="small"
                      variant="outlined"
                      disabled={busy}
                      startIcon={
                        rowBusy ? <CircularProgress size={14} /> : undefined
                      }
                      onClick={() => onMeasure(c.kind)}
                    >
                      {rowBusy
                        ? t("tunnels.health.measuring")
                        : t("tunnels.health.measure")}
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Box>

      {!anyHealth && (
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: "block", mt: 1 }}
        >
          {t("tunnels.health.hint")}
        </Typography>
      )}
    </Box>
  );
}
