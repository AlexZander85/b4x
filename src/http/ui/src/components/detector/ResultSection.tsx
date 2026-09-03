import { useState } from "react";
import { Box, Paper, Stack, Typography } from "@mui/material";
import { motion, AnimatePresence } from "motion/react";
import { ExpandIcon } from "@b4.icons";
import { colors } from "@design";
import { SummaryIcon } from "./StatusChip";
import { statusColors } from "./constants";

interface ResultSectionProps {
  title: string;
  icon: React.ReactNode;
  summary: string;
  ok: boolean;
  children: React.ReactNode;
}

export function ResultSection({
  title,
  icon,
  summary,
  ok,
  children,
}: ResultSectionProps) {
  const [expanded, setExpanded] = useState(true);
  const borderColor = ok ? statusColors.ok : statusColors.error;

  return (
    <motion.div
      initial={{ opacity: 0, x: -30 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
    >
      <Paper
        elevation={0}
        sx={{
          bgcolor: colors.background.paper,
          border: `1px solid ${colors.border.default}`,
          borderLeft: `4px solid ${borderColor}`,
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <Box
          onClick={() => setExpanded((v) => !v)}
          sx={{
            p: 2,
            bgcolor: colors.accent.primary,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            cursor: "pointer",
            userSelect: "none",
            "&:hover": { bgcolor: colors.accent.primaryHover },
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            {icon}
            <Typography variant="h6" sx={{ color: colors.text.primary }}>
              {title}
            </Typography>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SummaryIcon ok={ok} />
            <Typography
              variant="body2"
              sx={{
                color: ok ? statusColors.ok : statusColors.error,
                fontWeight: 600,
              }}
            >
              {summary}
            </Typography>
            <motion.div
              animate={{ rotate: expanded ? 180 : 0 }}
              transition={{ duration: 0.2 }}
              style={{ display: "flex" }}
            >
              <ExpandIcon sx={{ color: colors.text.secondary, fontSize: 20 }} />
            </motion.div>
          </Box>
        </Box>
        <AnimatePresence initial={false}>
          {expanded && (
            <motion.div
              key="content"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
              style={{ overflow: "hidden" }}
            >
              <Box sx={{ p: 2 }}>
                <Stack spacing={2}>{children}</Stack>
              </Box>
            </motion.div>
          )}
        </AnimatePresence>
      </Paper>
    </motion.div>
  );
}
