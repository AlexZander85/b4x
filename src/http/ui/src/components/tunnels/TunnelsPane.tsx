import { Box, Chip, Grid, Typography } from "@mui/material";
import { B4Alert, B4Badge, B4Section } from "@b4.elements";
import { RestartIcon, TunnelsIcon } from "@b4.icons";
import { colors } from "@design";
import { useTranslation } from "react-i18next";
import { TunnelCard } from "./TunnelCard";
import { TunnelSettingsDialog } from "./TunnelSettingsDialog";
import { Assignments } from "./Assignments";
import { useTunnels } from "@hooks/useTunnels";
import { TunnelKind } from "@models/config";
import { useState } from "react";

export function TunnelsPane() {
  const { t } = useTranslation();
  const { overview, loading, error, restarting, reload, restartTunnel } =
    useTunnels();
  const [configureKind, setConfigureKind] = useState<TunnelKind | null>(null);

  if (loading && !overview) {
    return (
      <Typography color="text.secondary" sx={{ p: 2 }}>
        {t("core.loading")}…
      </Typography>
    );
  }

  const registered = overview?.registered_carriers ?? [];
  const activeCount =
    overview?.tunnels.filter((c) => c.config_enabled && c.running).length ?? 0;
  const assignedCount = overview?.assignments.length ?? 0;

  return (
    <>
      {error && (
        <B4Alert severity="error">
          {t("tunnels.loadError")}: {error}
        </B4Alert>
      )}

      <B4Section
        title={t("tunnels.title")}
        description={t("tunnels.description")}
        icon={<TunnelsIcon />}
        action={
          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <B4Badge
              label={t("tunnels.summaryActive", { count: activeCount })}
              color={activeCount > 0 ? "primary" : "default"}
              variant="outlined"
            />
            <B4Badge
              label={t("tunnels.summaryAssigned", { count: assignedCount })}
              color={assignedCount > 0 ? "secondary" : "default"}
              variant="outlined"
            />
          </Box>
        }
      >
        <Grid container spacing={2}>
          {(overview?.tunnels ?? []).map((card) => (
            <Grid key={card.kind} size={{ xs: 12, sm: 6, md: 4, xl: 3 }}>
              <TunnelCard
                card={card}
                restarting={restarting === card.kind}
                onRestart={() => {
                  restartTunnel(card.kind).catch(() => {});
                }}
                onReload={() => {
                  reload().catch(() => {});
                }}
                onConfigure={() => {
                  setConfigureKind(card.kind);
                }}
              />
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 1 }}>
          <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
            {t("tunnels.registeredCarriers")}:
          </Typography>
          {registered.length === 0 ? (
            <Typography variant="caption" color="text.secondary">
              {t("tunnels.noRegisteredCarriers")}
            </Typography>
          ) : (
            registered.map((kind) => (
              <Chip
                key={kind}
                size="small"
                label={kind}
                sx={{
                  bgcolor: colors.accent.primary,
                  color: colors.primary,
                  fontFamily: "monospace",
                }}
              />
            ))
          )}
        </Box>
      </B4Section>

      <B4Section
        title={t("tunnels.chains.title")}
        description={t("tunnels.chains.description")}
      >
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
          {(overview?.chains ?? []).map((chain) => {
            const live = chain.available && chain.running;
            const noteKey = chain.note
              ? chain.note
              : live
                ? "chain_running"
                : null;
            return (
              <Chip
                key={chain.kind}
                label={`${chain.kind}  (${chain.outer} → ${chain.inner})${
                  live ? "  ●" : ""
                }`}
                variant={live ? "filled" : "outlined"}
                color={live ? "primary" : chain.enabled ? "secondary" : "default"}
                disabled={!chain.available}
                sx={{ fontFamily: "monospace" }}
                title={noteKey ? t(`tunnels.chains.${noteKey}`) : t(`tunnels.chains.${chain.kind}`)}
              />
            );
          })}
        </Box>
        <B4Alert severity="info" sx={{ mt: 2 }}>
          {t("tunnels.chains.note")}
        </B4Alert>
      </B4Section>

      <Assignments overview={overview} onToast={reload} />

      <TunnelSettingsDialog
        kind={configureKind}
        onClose={() => {
          setConfigureKind(null);
          reload().catch(() => {});
        }}
      />

      <Box sx={{ display: "flex", justifyContent: "flex-end", mt: -2 }}>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
        >
          <RestartIcon sx={{ fontSize: 14 }} />
          {t("tunnels.restartNote")}
        </Typography>
      </Box>
    </>
  );
}
