import { Box, Button, Stack, Typography } from "@mui/material";
import { B4Badge } from "@b4.elements";
import { RestartIcon, SettingsIcon } from "@b4.icons";
import { colors } from "@design";
import { useTranslation } from "react-i18next";
import { TunnelCard as TunnelCardModel } from "@models/tunnels";

interface TunnelCardProps {
  card: TunnelCardModel;
  restarting: boolean;
  onRestart: () => void;
  onReload: () => void;
  onConfigure: () => void;
}

const KIND_ICONS: Record<string, string> = {
  warp: "🛡",
  masque: "🪐",
  h3: "⚡",
  opera: "🎭",
  vless: "🔗",
  fxvpn: "🦊",
  proton: "🔒",
  tor: "🧅",
};

export function TunnelCard({
  card,
  restarting,
  onRestart,
  onReload,
  onConfigure,
}: TunnelCardProps) {
  const { t } = useTranslation();

  const stateBadge = () => {
    if (!card.has_config_section) {
      return (
        <B4Badge label={t("tunnels.state.enginePending")} color="default" />
      );
    }
    if (!card.config_enabled) {
      return <B4Badge label={t("core.disabled")} color="default" />;
    }
    if (card.running && card.listening) {
      return <B4Badge label={t("tunnels.state.listening")} color="primary" />;
    }
    if (card.running) {
      return (
        <B4Badge
          label={card.state || t("tunnels.state.running")}
          color="secondary"
        />
      );
    }
    return <B4Badge label={t("tunnels.state.notRunning")} color="error" />;
  };

  const kindTitle = t(`tunnels.kind.${card.kind}`);

  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 2,
        border: `1px solid ${colors.border.default}`,
        bgcolor: colors.background.paper,
        display: "flex",
        flexDirection: "column",
        gap: 1.5,
        height: "100%",
        opacity: card.has_config_section ? 1 : 0.75,
      }}
    >
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        spacing={1}
      >
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography sx={{ fontSize: 20 }} component="span">
            {KIND_ICONS[card.kind] ?? "🔌"}
          </Typography>
          <Typography sx={{ fontWeight: 600, fontSize: 15 }}>
            {kindTitle}
          </Typography>
        </Stack>
        {stateBadge()}
      </Stack>

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        <B4Badge
          label={t(`tunnels.transport.${card.transport}`)}
          variant="outlined"
          color="default"
        />
        {card.supports_udp && (
          <B4Badge
            label="UDP"
            variant="outlined"
            color={card.transport === "udp-full-scope" ? "primary" : "default"}
          />
        )}
        {card.carrier_registered && (
          <B4Badge
            label={t("tunnels.carrierRegistered")}
            variant="outlined"
            color="primary"
          />
        )}
      </Stack>

      <Box sx={{ flex: 1 }}>
        <Typography variant="body2" color="text.secondary">
          {t(`tunnels.kindDesc.${card.kind}`)}
        </Typography>
        {card.note && (
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: "block", mt: 1 }}
          >
            {t(`tunnels.note.${card.note}`)}
          </Typography>
        )}
      </Box>

      <Stack direction="row" spacing={1} alignItems="center">
        <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
          {card.location_mode
            ? t("tunnels.locationValue", {
                value: card.location_value || card.location_mode,
              })
            : card.region
              ? t("tunnels.regionValue", { region: card.region })
              : ""}
        </Typography>
        {card.restartable && card.config_enabled && (
          <Button
            size="small"
            variant="outlined"
            startIcon={<RestartIcon />}
            disabled={restarting}
            onClick={onRestart}
            title={t("tunnels.restartHint")}
          >
            {restarting ? t("core.saving") : t("tunnels.restart")}
          </Button>
        )}
        {card.has_config_section && (
          <Button
            size="small"
            variant="contained"
            startIcon={<SettingsIcon />}
            onClick={onConfigure}
          >
            {t("tunnels.configure")}
          </Button>
        )}
      </Stack>
    </Box>
  );
}
