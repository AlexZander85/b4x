import { Box, Stack, Typography } from "@mui/material";
import { colors } from "@design";
import type { SNIASNResult } from "@models/detector";
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

export function SNIResults({
  results,
}: Readonly<{ results: SNIASNResult[] }>) {
  const { t } = useTranslation();

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      {results.map((r, index) => {
        const status =
          r.status === "FOUND"
            ? "ok"
            : r.status === "NOT_BLOCKED"
              ? "warning"
              : "error";

        return (
          <Box key={r.asn} sx={{ flex: "1 1 300px", minWidth: 0 }}>
            <ResultCard
              index={index}
              status={status}
              title={`${r.provider} (AS${r.asn})`}
              subtitle={`IP: ${r.ip}`}
              badge={<StatusChip status={r.status} />}
              expandedContent={
                <Stack spacing={1} sx={{ py: 0.5 }}>
                  <KVRow label={t("detector.labels.asn")} value={`AS${r.asn}`} mono />
                  <KVRow label={t("detector.labels.provider")} value={r.provider} />
                  <KVRow label={t("core.devices.ip")} value={r.ip} mono />
                  <KVRow
                    label={t("detector.labels.status")}
                    value={<StatusChip status={r.status} />}
                  />
                  {r.found_sni ? (
                    <KVRow
                      label={t("detector.labels.foundSni")}
                      value={
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            color: "#4caf50",
                            fontWeight: 600,
                          }}
                        >
                          {r.found_sni}
                        </Typography>
                      }
                    />
                  ) : (
                    <KVRow
                      label={t("detector.labels.foundSni")}
                      value={
                        <Typography
                          variant="caption"
                          sx={{ color: colors.text.secondary }}
                        >
                          -
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
