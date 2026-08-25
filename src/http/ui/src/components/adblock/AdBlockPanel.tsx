import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Box,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from "@mui/material";
import { BlockIcon, RefreshIcon, DeleteIcon } from "@b4.icons";
import { colors } from "@design";
import {
  B4Badge,
  B4FormGroup,
  B4NumberField,
  B4PlusButton,
  B4Section,
  B4Select,
  B4Switch,
  B4TextField,
} from "@b4.elements";
import { StatCard } from "@components/dashboard/StatCard";
import { useAdBlock } from "@hooks/useAdBlock";
import { useSnackbar } from "@context/SnackbarProvider";
import { AdBlockListEntry } from "@models/adblock";

function formatBytes(n: number): string {
  if (n <= 0) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(iso: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "-";
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 60) return "<1m";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h`;
  if (diffSec < 86400 * 30) return `${Math.floor(diffSec / 86400)}d`;
  return d.toLocaleDateString();
}

function ListRow({
  entry,
  onToggle,
  onRemove,
}: Readonly<{
  entry: AdBlockListEntry;
  onToggle: (source: string, enabled: boolean) => void;
  onRemove: (source: string) => void;
}>) {
  const { t } = useTranslation();
  return (
    <TableRow sx={{ "&:last-child td, &:last-child th": { border: 0 } }}>
      <TableCell>
        <B4Switch
          label=""
          checked={entry.enabled}
          onChange={(v) => onToggle(entry.source, v)}
        />
      </TableCell>
      <TableCell>
        <Tooltip title={entry.source} placement="top-start">
          <Typography
            variant="body2"
            sx={{
              fontWeight: 500,
              maxWidth: 420,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {entry.source}
          </Typography>
        </Tooltip>
      </TableCell>
      <TableCell>
        <B4Badge
          label={entry.type === "url" ? t("adblock.typeUrl") : t("adblock.typeFile")}
          color={entry.type === "url" ? "primary" : "default"}
          variant="outlined"
        />
      </TableCell>
      <TableCell>
        {entry.cached ? (
          <B4Badge
            label={t("adblock.cachedYes")}
            color="primary"
            variant="outlined"
          />
        ) : (
          <B4Badge
            label={t("adblock.cachedNo")}
            color={entry.enabled ? "secondary" : "default"}
            variant="outlined"
          />
        )}
      </TableCell>
      <TableCell>
        <Typography variant="body2" color="text.secondary">
          {formatBytes(entry.size_bytes)}
        </Typography>
      </TableCell>
      <TableCell>
        <Tooltip title={entry.last_modified || ""}>
          <Typography variant="body2" color="text.secondary">
            {formatTime(entry.last_modified)}
          </Typography>
        </Tooltip>
      </TableCell>
      <TableCell align="right">
        <Tooltip title={t("adblock.removeList")}>
          <IconButton
            size="small"
            color="error"
            onClick={() => onRemove(entry.source)}
          >
            <DeleteIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
      </TableCell>
    </TableRow>
  );
}

export function AdBlockPanel() {
  const { t } = useTranslation();
  const { showError } = useSnackbar();
  const {
    status,
    loading,
    refreshing,
    updateConfig,
    addList,
    removeList,
    toggleList,
    refreshSubscriptions,
  } = useAdBlock();

  const [newSource, setNewSource] = useState("");
  const [hoursDraft, setHoursDraft] = useState<number | null>(null);

  const onError = (err: unknown) =>
    showError(err instanceof Error ? err.message : String(err));

  const handleAddSource = () => {
    const source = newSource.trim();
    if (!source) return;
    addList(source)
      .then(() => setNewSource(""))
      .catch(onError);
  };

  const commitHours = () => {
    if (!status || hoursDraft === null) return;
    const n = hoursDraft;
    setHoursDraft(null);
    if (n !== status.refresh_hours) {
      updateConfig({ refresh_hours: n }).catch(onError);
    }
  };

  if (loading || !status) {
    return null;
  }

  const stats = status.stats;

  return (
    <B4Section
      title={t("adblock.title")}
      description={t("adblock.description")}
      icon={<BlockIcon />}
      action={
        <Tooltip title={t("adblock.refresh")}>
          <span>
            <IconButton
              size="small"
              onClick={() => {
                refreshSubscriptions().catch(onError);
              }}
              disabled={refreshing}
            >
              <RefreshIcon
                sx={{
                  fontSize: 20,
                  ...(refreshing && {
                    animation: "b4-adblock-spin 1s linear infinite",
                    "@keyframes b4-adblock-spin": {
                      from: { transform: "rotate(0deg)" },
                      to: { transform: "rotate(360deg)" },
                    },
                  }),
                }}
              />
            </IconButton>
          </span>
        </Tooltip>
      }
    >
      <Stack spacing={3}>
        {refreshing && (
          <Typography variant="caption" sx={{ color: colors.secondary }}>
            {t("adblock.refreshing")}
          </Typography>
        )}

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "repeat(2, 1fr)",
              sm: "repeat(5, 1fr)",
            },
            gridAutoRows: "1fr",
            border: `1px solid ${colors.border.default}`,
            borderRadius: "8px",
            mr: "-1px",
            mb: "-1px",
            "& > *": {
              borderRight: `1px solid ${colors.border.light}`,
              borderBottom: `1px solid ${colors.border.light}`,
            },
          }}
        >
          <StatCard
            label={t("adblock.statBlocked")}
            value={stats.blocked_total}
            sub={t("adblock.statBlockedSub", { count: stats.allowlisted })}
            tone="primary"
          />
          <StatCard
            label={t("adblock.statPass")}
            value={stats.pass_total}
            sub={t("adblock.statPassSub")}
            tone="muted"
          />
          <StatCard
            label={t("adblock.statEch")}
            value={stats.ech_skipped}
            sub={t("adblock.statEchSub")}
            tone="secondary"
          />
          <StatCard
            label={t("adblock.statFetchOk")}
            value={stats.fetch_ok}
            tone="primary"
            sub={t("adblock.statFetchSub", {
              ok: stats.fetch_ok,
              fail: stats.fetch_fail,
            })}
          />
          <StatCard
            label={t("adblock.statFetchFail")}
            value={stats.fetch_fail}
            tone="secondary"
            sub={t("adblock.statIntegrity", {
              missing: stats.list_missing,
              invalid: stats.list_invalid,
              reloadFailed: stats.reload_failed,
            })}
          />
        </Box>

        <Box>
          <B4Switch
            label={t("adblock.enabled")}
            description={t("adblock.enabledHelp")}
            checked={status.enabled}
            onChange={(v) => {
              updateConfig({ enabled: v }).catch(onError);
            }}
          />
        </Box>

        <B4FormGroup label={t("adblock.configGroup")} columns={2}>
          <B4Select
            label={t("adblock.action")}
            value={status.action}
            options={[
              { value: "drop", label: t("adblock.actionDrop") },
              { value: "rst", label: t("adblock.actionRst") },
            ]}
            onChange={(e) => {
              updateConfig({
                action: e.target.value as "drop" | "rst",
              }).catch(onError);
            }}
            helperText={t("adblock.actionHelp")}
            disabled={!status.enabled}
          />
          <B4NumberField
            label={t("adblock.refreshHours")}
            value={hoursDraft ?? status.refresh_hours}
            min={0}
            onChange={(n) => setHoursDraft(n)}
            onBlur={commitHours}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                (e.target as HTMLElement).blur();
              }
            }}
            helperText={t("adblock.refreshHoursHelp")}
            disabled={!status.enabled}
          />
          <Box sx={{ pt: 1 }}>
            <B4Switch
              label={t("adblock.logMatches")}
              description={t("adblock.logMatchesHelp")}
              checked={status.log_matches}
              onChange={(v) => {
                updateConfig({ log_matches: v }).catch(onError);
              }}
            />
          </Box>
        </B4FormGroup>

        <Stack direction="row" spacing={1} alignItems="center">
          <B4TextField
            size="small"
            value={newSource}
            onChange={(e) => setNewSource(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleAddSource();
              }
            }}
            placeholder={t("adblock.addPlaceholder")}
            sx={{ flex: 1 }}
          />
          <B4PlusButton
            onClick={handleAddSource}
            disabled={!newSource.trim()}
          />
        </Stack>

        {status.lists.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            {status.enabled
              ? t("adblock.noListsDefaults")
              : t("adblock.noLists")}
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width="60px">{t("adblock.colEnabled")}</TableCell>
                  <TableCell>{t("adblock.colSource")}</TableCell>
                  <TableCell>{t("adblock.colType")}</TableCell>
                  <TableCell>{t("adblock.colCache")}</TableCell>
                  <TableCell>{t("adblock.colSize")}</TableCell>
                  <TableCell>{t("adblock.colUpdated")}</TableCell>
                  <TableCell align="right">
                    {t("adblock.colActions")}
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {status.lists.map((entry) => (
                  <ListRow
                    key={entry.source}
                    entry={entry}
                    onToggle={(src, v) => {
                      toggleList(src, v).catch(onError);
                    }}
                    onRemove={(src) => {
                      removeList(src).catch(onError);
                    }}
                  />
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        <Typography variant="caption" sx={{ color: colors.text.disabled }}>
          {t("adblock.cacheDir", { dir: status.cache_dir })}
        </Typography>
      </Stack>
    </B4Section>
  );
}

export default AdBlockPanel;
