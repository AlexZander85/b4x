import { useCallback, useEffect, useState } from "react";
import {
  Box,
  Button,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { B4Alert, B4Badge, B4Section } from "@b4.elements";
import { B4TextField } from "@b4.fields";
import { AssignIcon } from "@b4.icons";
import { colors } from "@design";
import { useTranslation } from "react-i18next";
import { apiGet, apiPut } from "@api/apiClient";
import { useSnackbar } from "@context/SnackbarProvider";
import { B4SetConfig, TunnelKind } from "@models/config";
import { TunnelsOverview } from "@models/tunnels";

interface AssignmentsProps {
  overview: TunnelsOverview | null;
  onToast: () => void;
}

// Assignments: the sets whose routing.mode=tunnel, with the tunnel kind
// switcher. The change goes through PUT /api/sets/{id} (the same validated
// path as the set editor); routing.tunnel joins the set's routing identity.
export function Assignments({ overview, onToast }: AssignmentsProps) {
  const { t } = useTranslation();
  const { showSuccess, showError } = useSnackbar();
  const [sets, setSets] = useState<B4SetConfig[]>([]);
  const [switching, setSwitching] = useState<string | null>(null);

  const loadSets = useCallback(async () => {
    try {
      const data = await apiGet<B4SetConfig[]>("/api/sets");
      setSets(Array.isArray(data) ? data : []);
    } catch {
      // the overview keeps working without the set list
    }
  }, []);

  useEffect(() => {
    loadSets().catch(() => {});
  }, [loadSets]);

  const tunnelEnabled = useCallback(
    (kind: string): boolean => {
      const card = overview?.tunnels.find((c) => c.kind === kind);
      return Boolean(card?.has_config_section);
    },
    [overview],
  );

  const switchTunnel = useCallback(
    async (setId: string, kind: TunnelKind) => {
      try {
        setSwitching(setId);
        const set = await apiGet<B4SetConfig>(`/api/sets/${setId}`);
        const updated = {
          ...set,
          routing: { ...set.routing, mode: "tunnel" as const, tunnel: kind },
        };
        await apiPut<B4SetConfig>(`/api/sets/${setId}`, updated);
        showSuccess(t("tunnels.assignments.switched", { kind }));
        await loadSets();
        onToast();
      } catch (err) {
        showError(err instanceof Error ? err.message : "switch failed");
      } finally {
        setSwitching(null);
      }
    },
    [loadSets, onToast, showError, showSuccess, t],
  );

  const assigned = sets.filter(
    (set) => set.routing?.mode === "tunnel" && set.routing.tunnel,
  );
  const availableSets = sets.filter(
    (set) => set.routing?.mode !== "tunnel" || !set.routing.tunnel,
  );

  const renderRow = (set: B4SetConfig) => {
    const kind = set.routing.tunnel as TunnelKind;
    const card = overview?.tunnels.find((c) => c.kind === kind);
    return (
      <TableRow key={set.id}>
        <TableCell>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {set.name}
          </Typography>
          {!set.enabled && (
            <B4Badge label={t("core.disabled")} color="default" />
          )}
        </TableCell>
        <TableCell>
          <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
            {kind}
          </Typography>
        </TableCell>
        <TableCell>
          {card ? (
            <B4Badge
              label={
                card.config_enabled && card.running && card.listening
                  ? t("tunnels.state.listening")
                  : card.config_enabled && card.running
                    ? t("tunnels.state.running")
                    : t("tunnels.state.notRunning")
              }
              color={
                card.config_enabled && card.running && card.listening
                  ? "primary"
                  : card.config_enabled
                    ? "secondary"
                    : "error"
              }
            />
          ) : (
            <B4Badge label={t("tunnels.state.enginePending")} color="default" />
          )}
        </TableCell>
        <TableCell>
          <Typography variant="body2" color="text.secondary">
            {(set.targets?.sni_domains?.length ?? 0) +
              (set.targets?.geosite_categories?.length ?? 0) >
            0
              ? `${set.targets?.sni_domains?.length ?? 0} / ${
                  set.targets?.geosite_categories?.length ?? 0
                }`
              : "—"}
          </Typography>
        </TableCell>
        <TableCell>
          <B4TextField
            select
            size="small"
            value={kind}
            disabled={switching === set.id}
            onChange={(e) => {
              switchTunnel(set.id, e.target.value as TunnelKind).catch(() => {});
            }}
            sx={{ minWidth: 160 }}
          >
            {(overview?.tunnels ?? [])
              .filter((c) => tunnelEnabled(c.kind))
              .map((c) => (
                <MenuItem key={c.kind} value={c.kind}>
                  {t(`tunnels.kind.${c.kind}`)}
                </MenuItem>
              ))}
          </B4TextField>
        </TableCell>
      </TableRow>
    );
  };

  return (
    <B4Section
      title={t("tunnels.assignments.title")}
      description={t("tunnels.assignments.description")}
      icon={<AssignIcon />}
    >
      {assigned.length === 0 ? (
        <B4Alert severity="info">{t("tunnels.assignments.empty")}</B4Alert>
      ) : (
        <TableContainer
          sx={{ border: `1px solid ${colors.border.default}`, borderRadius: 1 }}
        >
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{t("tunnels.assignments.set")}</TableCell>
                <TableCell>{t("tunnels.assignments.tunnel")}</TableCell>
                <TableCell>{t("tunnels.assignments.tunnelState")}</TableCell>
                <TableCell>{t("tunnels.assignments.targets")}</TableCell>
                <TableCell>{t("tunnels.assignments.switchTo")}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>{assigned.map(renderRow)}</TableBody>
          </Table>
        </TableContainer>
      )}

      {availableSets.length > 0 && (
        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            {t("tunnels.assignments.attachTitle")}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
            {t("tunnels.assignments.attachDescription")}
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {availableSets.map((set) => (
              <Button
                key={set.id}
                size="small"
                variant="outlined"
                onClick={() => {
                  const firstKind = (overview?.tunnels ?? []).find((c) =>
                    tunnelEnabled(c.kind),
                  )?.kind;
                  if (firstKind) {
                    switchTunnel(set.id, firstKind).catch(() => {});
                  }
                }}
                title={t("tunnels.assignments.attachHint")}
              >
                {set.name}
              </Button>
            ))}
          </Box>
        </Box>
      )}
    </B4Section>
  );
}
