import {
  Alert, Box, Button, CardContent, Chip, Divider, FormControlLabel, LinearProgress, MenuItem, Select, Slider, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { B4Card } from "@common/B4Card";
import { CompareIcon, DownloadIcon } from "@b4.icons";
import { colors } from "@design";
import type { ClientHelloProfile } from "@models/classifier";
import { EmptyState, SectionTitle, StatusChip, fmtDate, short } from "./shared";

function ProfileSummary({ profile }: Readonly<{ profile?: ClientHelloProfile }>) {
  if (!profile) return <EmptyState text="Select a profile" />;
  const compiled = profile.compiled_size || profile.raw_size;
  const mtuSafe = compiled <= 1460;
  return (
    <Stack gap={1.2}>
      <Typography fontFamily="monospace" fontWeight={700}>{short(profile.id, 28)}</Typography>
      <Stack direction="row" gap={1} flexWrap="wrap">
        <StatusChip ok={profile.privacy_safe} label={profile.privacy_safe ? "privacy-safe" : "private"} />
        <StatusChip ok={mtuSafe} label={mtuSafe ? "MTU-safe" : "MTU-risk"} />
        <Chip size="small" label={profile.ip_family} />
      </Stack>
      <Typography variant="body2">Source: {profile.source_app || "—"} · domain: {profile.observed_domain || "redacted"}</Typography>
      <Typography variant="body2">TLS: 0x{profile.tls_version.toString(16)} · ALPN: {profile.alpn?.join(", ") || "—"}</Typography>
      <Typography variant="body2">raw {profile.raw_size} B → compiled {compiled} B</Typography>
      <Typography variant="caption" fontFamily="monospace">SHA-256: {short(profile.sha256, 34)}</Typography>
      <Typography variant="caption" color="text.secondary">Captured {fmtDate(profile.completed_at)}</Typography>
    </Stack>
  );
}

export function ClientHelloPanel({
  profiles,
  advanced,
  onRawExport,
}: Readonly<{
  profiles: ClientHelloProfile[];
  advanced: boolean;
  onRawExport: () => void;
}>) {
  const { t } = useTranslation();
  const [leftId, setLeftId] = useState("");
  const [rightId, setRightId] = useState("");
  const left = profiles.find((profile) => profile.id === leftId) ?? profiles[0];
  const right = profiles.find((profile) => profile.id === rightId) ?? profiles[1];

  return (
    <Stack gap={2}>
      <Alert severity="info">{t("classifier.lab.privacy")}</Alert>
      <B4Card>
        <CardContent>
          <SectionTitle
            title={t("classifier.lab.title")}
            description={t("classifier.lab.description")}
            action={advanced ? <Button color="warning" startIcon={<DownloadIcon />} onClick={onRawExport}>{t("classifier.lab.rawExport")}</Button> : undefined}
          />
          {profiles.length === 0 ? <EmptyState text={t("classifier.lab.empty")} /> : (
            <>
              <Stack direction={{ xs: "column", md: "row" }} gap={2} sx={{ mb: 2 }}>
                <Select fullWidth displayEmpty value={left?.id ?? ""} onChange={(event) => setLeftId(event.target.value)}>
                  {profiles.map((profile) => <MenuItem value={profile.id} key={profile.id}>{profile.source_app || profile.id} · {profile.raw_size} B</MenuItem>)}
                </Select>
                <CompareIcon sx={{ alignSelf: "center" }} />
                <Select fullWidth displayEmpty value={right?.id ?? ""} onChange={(event) => setRightId(event.target.value)}>
                  {profiles.map((profile) => <MenuItem value={profile.id} key={profile.id}>{profile.source_app || profile.id} · {profile.raw_size} B</MenuItem>)}
                </Select>
              </Stack>
              <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
                <Box sx={{ border: `1px solid ${colors.border.default}`, p: 2, borderRadius: 2 }}><ProfileSummary profile={left} /></Box>
                <Box sx={{ border: `1px solid ${colors.border.default}`, p: 2, borderRadius: 2 }}><ProfileSummary profile={right} /></Box>
              </Box>
            </>
          )}
        </CardContent>
      </B4Card>
    </Stack>
  );
}

