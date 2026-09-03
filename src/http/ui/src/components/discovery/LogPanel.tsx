import { useEffect, useRef, useState } from "react";
import {
  Box,
  Typography,
  Stack,
  Button,
} from "@mui/material";
import {
  ClearIcon,
  LogsIcon,
  CloseIcon,
} from "@b4.icons";
import { colors } from "@design";
import { useDiscoveryLogs } from "@b4.discovery";
import { B4Dialog } from "@common/B4Dialog";
import { useTranslation } from "react-i18next";

interface DiscoveryLogPanelProps {
  running: boolean;
}

export const DiscoveryLogPanel = ({ running }: DiscoveryLogPanelProps) => {
  const { t } = useTranslation();
  const { logs, connected, clearLogs } = useDiscoveryLogs();
  const [modalOpen, setModalOpen] = useState(false);
  const modalScrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (modalScrollRef.current && modalOpen) {
      modalScrollRef.current.scrollTop = modalScrollRef.current.scrollHeight;
    }
  }, [logs, modalOpen]);

  if (!running && logs.length === 0) return null;

  return (
    <>
      <Stack direction="row" alignItems="center" spacing={1.5}>
        <Button
          variant="outlined"
          size="small"
          startIcon={<LogsIcon />}
          onClick={() => setModalOpen(true)}
          sx={{ textTransform: "none" }}
        >
          {t("discovery.logs.title")}
        </Button>
        <Box
          sx={{
            width: 10,
            height: 10,
            borderRadius: "50%",
            bgcolor: connected ? colors.secondary : colors.text.disabled,
          }}
        />
        {logs.length > 0 && (
          <Typography variant="caption" sx={{ color: colors.text.secondary }}>
            {logs[logs.length - 1]}
          </Typography>
        )}
      </Stack>

      <B4Dialog
        title={t("discovery.logs.title")}
        icon={<LogsIcon />}
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        fullWidth
        maxWidth="xl"
        actions={
          <>
            <Button
              onClick={clearLogs}
              startIcon={<ClearIcon />}
              size="small"
            >
              {t("discovery.logs.clear")}
            </Button>
            <Box sx={{ flex: 1 }} />
            <Button
              onClick={() => setModalOpen(false)}
              variant="contained"
              startIcon={<CloseIcon />}
            >
              {t("core.close")}
            </Button>
          </>
        }
      >
        <div
          ref={modalScrollRef}
          style={{
            height: "60vh",
            overflowY: "auto",
            backgroundColor: colors.background.dark,
            fontFamily: "monospace",
            fontSize: 12,
            padding: 16,
          }}
        >
          {logs.length === 0 ? (
            <Typography
              sx={{ color: colors.text.disabled, fontStyle: "italic" }}
            >
              {t("discovery.logs.waiting")}
            </Typography>
          ) : (
            logs.map((line, i) => (
              <div
                key={i}
                style={{
                  color: getLogColor(line),
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  lineHeight: 1.6,
                }}
              >
                {line}
              </div>
            ))
          )}
        </div>
      </B4Dialog>
    </>
  );
};

function getLogColor(line: string): string {
  const lower = line.toLowerCase();
  if (lower.includes("success") || line.includes("✓") || lower.includes("best"))
    return colors.secondary;
  if (lower.includes("failed") || line.includes("✗") || lower.includes("fail"))
    return colors.primary;
  if (lower.includes("phase")) return colors.text.secondary;
  return colors.text.primary;
}
