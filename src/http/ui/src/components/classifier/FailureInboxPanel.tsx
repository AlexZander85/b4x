import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import { CompareIcon, DownloadIcon } from "@b4.icons";
import { colors } from "@design";
import type { FailureCandidate } from "@models/classifier";
import { EmptyState, SectionTitle, fmtDate, short } from "./shared";

export function FailureInboxPanel({
  candidates,
  onExport,
}: Readonly<{ candidates: FailureCandidate[]; onExport: () => void }>) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <B4Card>
      <CardContent>
        <SectionTitle title={t("classifier.inbox.title")} description={t("classifier.inbox.description")} />
        {candidates.length === 0 ? <EmptyState text={t("classifier.inbox.empty")} /> : (
          <Stack gap={2}>
            {candidates.map((candidate) => (
              <Box key={candidate.id} sx={{ border: `1px solid ${colors.border.default}`, borderRadius: 2, p: 2 }}>
                <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" gap={2}>
                  <Box>
                    <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                      <Typography fontFamily="monospace" fontWeight={700}>{short(candidate.id, 22)}</Typography>
                      <Chip size="small" label={candidate.conntrack_state || "unknown"} />
                      <Chip size="small" color="warning" label={`${candidate.flow_retries} retries`} />
                    </Stack>
                    <Typography variant="body2" sx={{ mt: 1 }}>{candidate.destination_ip}:{candidate.destination_port} · L4 {candidate.protocol}</Typography>
                    <Typography variant="caption" color="text.secondary">{candidate.signals.join(", ")}</Typography>
                    {(candidate.reasons ?? []).map((reason) => <Typography variant="body2" key={reason}>• {reason}</Typography>)}
                  </Box>
                  <Stack direction="row" gap={1} alignItems="flex-start" flexWrap="wrap">
                    <Button size="small" onClick={() => navigate("/logs")}>Trace</Button>
                    <Button size="small" onClick={() => navigate("/discovery")}>Discovery</Button>
                    <Button size="small" startIcon={<DownloadIcon />} onClick={onExport}>Issue bundle</Button>
                  </Stack>
                </Stack>
                <Divider sx={{ my: 1.5 }} />
                <Typography variant="caption">Suggested: {candidate.suggested_action} · Available: {candidate.available_actions.join(", ")}</Typography>
              </Box>
            ))}
          </Stack>
        )}
      </CardContent>
    </B4Card>
  );
}

