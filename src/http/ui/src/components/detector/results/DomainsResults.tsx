import { Box, Stack, Typography } from "@mui/material";
import { colors } from "@design";
import type { DomainCheckResult } from "@models/detector";
import { ResultCard } from "../ResultCard";
import { StatusChip } from "../StatusChip";
import { useTranslation } from "react-i18next";

function ProbeRow({
  label,
  status,
  detail,
  latency,
}: Readonly<{
  label: string;
  status?: string;
  detail?: string;
  latency?: number;
}>) {
  if (!status) return null;
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Typography
        variant="caption"
        sx={{
          color: colors.text.secondary,
          minWidth: 60,
          textTransform: "uppercase",
          letterSpacing: "0.5px",
        }}
      >
        {label}
      </Typography>
      <StatusChip status={status} />
      {latency != null && latency > 0 && (
        <Typography
          variant="caption"
          sx={{ color: colors.text.secondary, fontFamily: "monospace" }}
        >
          {latency}ms
        </Typography>
      )}
      {detail && (
        <Typography
          variant="caption"
          sx={{
            color: colors.text.secondary,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: 200,
          }}
        >
          {detail}
        </Typography>
      )}
    </Stack>
  );
}

export function DomainsResults({
  domains,
}: Readonly<{ domains: DomainCheckResult[] }>) {
  const { t } = useTranslation();

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      {domains.map((d, index) => {
        const status =
          d.overall === "OK"
            ? "ok"
            : d.overall === "TIMEOUT" || d.overall === "ERROR"
              ? "warning"
              : "error";

        return (
          <Box key={d.domain} sx={{ flex: "1 1 280px", minWidth: 0 }}>
            <ResultCard
              index={index}
              status={status}
              title={d.domain}
              subtitle={d.ip ? `IP: ${d.ip}` : undefined}
              badge={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  {d.is_fake_ip && (
                    <Typography
                      variant="caption"
                      sx={{ color: "#f44336", fontWeight: 600 }}
                    >
                      {t("detector.results.fakeIp")}
                    </Typography>
                  )}
                  <StatusChip status={d.overall} />
                </Box>
              }
              expandedContent={
                <Stack spacing={1} sx={{ py: 0.5 }}>
                  {d.ip && (
                    <Stack direction="row" spacing={2} alignItems="center">
                      <Typography
                        variant="caption"
                        sx={{
                          color: colors.text.secondary,
                          minWidth: 60,
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                        }}
                      >
                        {t("core.devices.ip")}
                      </Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          color: colors.text.primary,
                          fontFamily: "monospace",
                          fontSize: "0.8rem",
                        }}
                      >
                        {d.ip}
                      </Typography>
                    </Stack>
                  )}
                  <ProbeRow
                    label={t("detector.labels.tls13")}
                    status={d.tls13?.status}
                    detail={d.tls13?.detail}
                    latency={d.tls13?.latency_ms}
                  />
                  <ProbeRow
                    label={t("detector.labels.tls12")}
                    status={d.tls12?.status}
                    detail={d.tls12?.detail}
                    latency={d.tls12?.latency_ms}
                  />
                  <ProbeRow
                    label={t("detector.labels.http")}
                    status={d.http?.status}
                    detail={d.http?.detail}
                  />
                </Stack>
              }
            />
          </Box>
        );
      })}
    </Box>
  );
}
