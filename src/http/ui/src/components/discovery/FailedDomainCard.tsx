import {
  Box,
  Typography,
  IconButton,
  Tooltip,
  Paper,
} from "@mui/material";
import { DeleteIcon } from "@b4.icons";
import { colors } from "@design";
import { B4Alert, B4Badge } from "@b4.elements";
import { useTranslation, Trans } from "react-i18next";

interface FailedDomainCardProps {
  domain: string;
  transportBlocked?: boolean;
  resultsCount?: number;
  timeAgo?: string;
  onDelete?: () => void;
}

export const FailedDomainCard = ({
  domain,
  transportBlocked,
  resultsCount,
  timeAgo,
  onDelete,
}: FailedDomainCardProps) => {
  const { t } = useTranslation();

  return (
    <Paper
      elevation={0}
      sx={{
        bgcolor: colors.background.paper,
        border: `1px solid ${colors.border.default}`,
        borderRadius: 2,
        overflow: "hidden",
      }}
    >
      <Box
        sx={{
          px: 2,
          py: onDelete ? 1.5 : 2,
          bgcolor: onDelete ? undefined : colors.accent.primary,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: onDelete ? 1.5 : 2 }}>
          <Typography
            variant={onDelete ? "body1" : "h6"}
            sx={{ color: colors.text.primary, fontWeight: onDelete ? 600 : undefined }}
          >
            {domain}
          </Typography>
          {transportBlocked ? (
            <B4Badge
              label={t("discovery.badges.blocked")}
              size="small"
              color="info"
            />
          ) : (
            <B4Badge
              label={t("core.failed")}
              size="small"
              color="error"
            />
          )}
        </Box>
        {onDelete ? (
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            {timeAgo && (
              <Typography
                variant="caption"
                sx={{ color: colors.text.secondary }}
              >
                {timeAgo}
              </Typography>
            )}
            <Tooltip title={t("core.history.removeFromHistory")}>
              <IconButton
                size="small"
                onClick={onDelete}
                sx={{
                  p: 0.5,
                  color: colors.text.secondary,
                  "&:hover": { color: colors.text.primary },
                }}
              >
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        ) : (
          <Typography
            variant="h6"
            sx={{ color: colors.text.secondary, fontWeight: 600 }}
          >
            {t("discovery.noWorkingConfig")}
          </Typography>
        )}
      </Box>
      <Box sx={{ p: 2, ...(onDelete ? { pt: 0 } : {}) }}>
        {transportBlocked ? (
          <B4Alert severity="warning">
            <Trans i18nKey="discovery.transportBlocked" />
          </B4Alert>
        ) : (
          <B4Alert severity="error">
            {t("discovery.allFailed", {
              count: resultsCount ?? 0,
            })}
          </B4Alert>
        )}
      </Box>
    </Paper>
  );
};
