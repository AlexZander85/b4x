import { Box, Stack, Typography } from "@mui/material";
import { colors } from "@design";
import { B4Badge } from "@b4.elements";
import type { TCPTargetResult } from "@models/detector";
import { ResultCard } from "../ResultCard";
import { StatusChip } from "../StatusChip";
import { useTranslation } from "react-i18next";

function KVRow({
  label,
  value,
  mono,
}: Readonly<{
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}>) {
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Typography
        variant="caption"
        sx={{
          color: colors.text.secondary,
          minWidth: 80,
          textTransform: "uppercase",
          letterSpacing: "0.5px",
        }}
      >
        {label}
      </Typography>
      {typeof value === "string" || typeof value === "number" ? (
        <Typography
          variant="body2"
          sx={{
            color: colors.text.primary,
            fontFamily: mono ? "monospace" : "inherit",
            fontSize: mono ? "0.8rem" : undefined,
          }}
        >
          {value}
        </Typography>
      ) : (
        value
      )}
    </Stack>
  );
}

export function TCPResults({
  targets,
}: Readonly<{ targets: TCPTargetResult[] }>) {
  const { t } = useTranslation();

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      {targets.map((tr, index) => {
        const status =
          tr.status === "OK"
            ? "ok"
            : tr.status === "DETECTED"
              ? "error"
              : "warning";

        return (
          <Box key={tr.target.id} sx={{ flex: "1 1 300px", minWidth: 0 }}>
            <ResultCard
              index={index}
              status={status}
              title={`${tr.target.provider} (AS${tr.target.asn})`}
              subtitle={`${tr.target.ip}:${tr.target.port}`}
              badge={
                <Stack direction="row" alignItems="center" spacing={0.5}>
                  <B4Badge
                    label={tr.alive ? t("detector.results.alive") : t("detector.results.dead")}
                    size="small"
                    color={tr.alive ? "primary" : "error"}
                  />
                  <StatusChip status={tr.status} />
                </Stack>
              }
              expandedContent={
                <Stack spacing={1} sx={{ py: 0.5 }}>
                  <KVRow
                    label={t("detector.labels.endpoint")}
                    value={`${tr.target.ip}:${tr.target.port}`}
                    mono
                  />
                  <KVRow label={t("detector.labels.asn")} value={`AS${tr.target.asn}`} mono />
                  <KVRow
                    label={t("detector.results.alive")}
                    value={
                      <B4Badge
                        label={tr.alive ? t("core.yes") : t("core.no")}
                        size="small"
                        color={tr.alive ? "primary" : "error"}
                      />
                    }
                  />
                  {tr.drop_at_kb != null && (
                    <KVRow label={t("detector.labels.dropAt")} value={`${tr.drop_at_kb} KB`} mono />
                  )}
                  {tr.rtt_ms != null && (
                    <KVRow label={t("detector.labels.rtt")} value={`${tr.rtt_ms} ms`} mono />
                  )}
                  {tr.target.sni && (
                    <KVRow label={t("detector.labels.sni")} value={tr.target.sni} mono />
                  )}
                  {tr.detail && (
                    <KVRow
                      label={t("detector.labels.detail")}
                      value={
                        <Typography
                          variant="caption"
                          sx={{ color: colors.text.secondary }}
                        >
                          {tr.detail}
                        </Typography>
                      }
                    />
                  )}
                </Stack>
              }
            />
          </Box>
        );
      })}
    </Box>
  );
}
