import { Box, Chip, Stack, Typography } from "@mui/material";
import type { ReactNode } from "react";

export const STRATEGIES = [
  "marker_multi_split",
  "marker_multi_disorder",
  "host_fake_split",
  "fake_payload_catalog",
  "fake_d_split",
  "fake_d_disorder",
  "tls_record_split",
  "controlled_rst",
];
export const STRATEGY_CONFIG_KEYS: Record<string, string> = {
  marker_multi_split: "marker_multisplit",
  marker_multi_disorder: "marker_multidisorder",
  host_fake_split: "hostfakesplit",
  fake_payload_catalog: "fake_payload_catalog",
  fake_d_split: "fakedsplit",
  fake_d_disorder: "fakeddisorder",
  tls_record_split: "tls_record_split",
  controlled_rst: "controlled_rst",
};


export const fmtDate = (value?: string) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
};

export const short = (value?: string, size = 18) => {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
};

export function StatusChip({ ok, label }: Readonly<{ ok: boolean; label: string }>) {
  return (
    <Chip
      size="small"
      label={label}
      color={ok ? "success" : "warning"}
      variant={ok ? "filled" : "outlined"}
    />
  );
}

export function SectionTitle({
  title,
  description,
  action,
}: Readonly<{
  title: string;
  description?: string;
  action?: ReactNode;
}>) {
  return (
    <Stack
      direction={{ xs: "column", sm: "row" }}
      justifyContent="space-between"
      alignItems={{ xs: "stretch", sm: "center" }}
      gap={1}
      sx={{ mb: 2 }}
    >
      <Box>
        <Typography variant="h6" fontWeight={700}>
          {title}
        </Typography>
        {description && (
          <Typography variant="body2" color="text.secondary">
            {description}
          </Typography>
        )}
      </Box>
      {action}
    </Stack>
  );
}

export function EmptyState({ text }: Readonly<{ text: string }>) {
  return (
    <Box sx={{ py: 5, textAlign: "center", color: "text.secondary" }}>
      <Typography variant="body2">{text}</Typography>
    </Box>
  );
}

