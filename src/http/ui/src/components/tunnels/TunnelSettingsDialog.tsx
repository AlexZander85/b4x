import { useCallback, useEffect, useMemo, useState } from "react";
import { Box, Button, CircularProgress, Grid, MenuItem, Stack } from "@mui/material";
import { B4Alert, B4Dialog, B4NumberField, B4Switch } from "@b4.elements";
import { B4TextField } from "@b4.fields";
import { SaveIcon, TunnelsIcon } from "@b4.icons";
import { useTranslation } from "react-i18next";
import { configApi } from "@api/settings";
import { tunnelLocationApi } from "@api/tunnels";
import { useSnackbar } from "@context/SnackbarProvider";
import {
  B4Config,
  FxVPNTunnelConfig,
  OperaTunnelConfig,
  ProtonTunnelConfig,
  TorTunnelConfig,
  VlessTunnelConfig,
  TunnelKind,
  WarpAWGConfig,
  WarpNonRUConfig,
  WarpTunnelConfig,
} from "@models/config";
import { StringListField } from "./StringListField";

interface TunnelSettingsDialogProps {
  kind: TunnelKind | null;
  onClose: () => void;
}

const CONFIG_SECTION: Record<string, keyof B4Config["system"]> = {
  masque: "warp",
  warp: "warp", // the AWG-WARP branch lives in system.warp.awg
  nonru: "warp", // the НЕ РФ branch lives in system.warp.nonru
  opera: "opera",
  vless: "vless",
  fxvpn: "fxvpn",
  proton: "proton",
  tor: "tor",
};

// AWG-WARP profiles (vanilla-safe cf-warp family of the versioned catalog).
const AWG_PROFILE_IDS = [
  "",
  "quic-a",
  "quic-b",
  "sip-invite",
  "crlf-light",
  "crlf-aggressive",
  "vanilla-off",
];

function defaultsFor(kind: TunnelKind): unknown {
  switch (kind) {
    case "warp":
      return {
        enabled: false,
        identity_path: "",
        endpoint: "",
        profile: "",
        mtu: 0,
        max_restarts_per_hour: 6,
      } satisfies WarpAWGConfig;
    case "masque":
      return {
        enabled: false,
        identity_path: "",
        endpoint: "",
        defer_revalidation: false,
        masquerade: { fingerprint: "" },
      } satisfies WarpTunnelConfig;
    case "nonru":
      return {
        enabled: false,
        identity_path: "",
        endpoint: "",
        fingerprint: "",
        inner_mtu: 0,
        attestation_ttl_seconds: 0,
        refresh_interval_seconds: 0,
        ru_countries: [],
        fallback_to_base: false,
        // socks5 is a BASE system.warp field (viewed here because the НЕ РУ
        // option is where the operator looks for a non-RU egress); it is
        // stripped from the nonru section on save.
        socks5: "",
      } satisfies WarpNonRUConfig & { socks5: string };
    case "opera":
      return {
        enabled: false,
        identity_path: "",
        region: "EU",
        fake_sni: "",
        control_target: "",
        masquerade: {
          profile: "browser",
          sni_mode: "node",
          sni_pool: [],
          alpn: ["h2", "http/1.1"],
          session_resumption: true,
          ttl_fake: false,
        },
      } satisfies OperaTunnelConfig;
    case "vless":
      return {
        enabled: false,
        client: "auto",
        helper: "xray",
        helper_path: "",
        helper_manage: true,
        socks_addr: "127.0.0.1:1081",
        nodes: [],
        bundled_sources: true,
        subscriptions: [],
        subscription_interval_sec: 21600,
        node_cache_path: "",
        identity_path: "",
        control_target: "www.cloudflare.com",
        prefer_nonru: true,
        country_allow: [],
        country_deny: ["RU"],
        max_restarts_per_hour: 6,
        seek_interval_sec: 300,
        seek_tolerance_ms: 50,
        pin_node: "",
        udp: false,
        mixed: false,
      } satisfies VlessTunnelConfig;
    case "fxvpn":
      return {
        enabled: false,
        accounts_path: "",
        location: { mode: "auto", country: "", city: "", host: "" },
        prefer_h3: false,
        rotate_threshold_pct: 15,
        bootstrap_through_carrier: false,
        control_target: "www.cloudflare.com",
        masquerade: {
          profile: "firefox",
          preflight_fake: true,
          fake_sni_pool: [],
          fake_ttl: 4,
          fake_count: 2,
          initial_padding: 1250,
          hello_shaping: true,
          nest_on_port_block: true,
        },
      } satisfies FxVPNTunnelConfig;
    case "proton":
      return {
        enabled: false,
        identity_path: "",
        location: { mode: "auto", country: "", host: "" },
        obfuscation: {
          enabled: false,
          preferred_profile: "",
          sni_pool: [],
          i1_adaptation: false,
        },
        port: 0,
        mtu: 1420,
        bootstrap_through_carrier: false,
        user_agent: "",
        app_version: "",
        api_version: "",
        max_restarts_per_hour: 6,
        tunnel_mode: "netstack",
        kernel_device: "",
        route_mark: 0,
        route_table: 0,
      } satisfies ProtonTunnelConfig;
    case "tor":
      return {
        enabled: false,
        binary_path: "",
        data_path: "",
        entry: { mode: "auto", race_window: 2 },
        bridges: {
          lines: [],
          builtin_snowflake: true,
          collect_urls: [],
          country: "",
          recollect_pause_sec: 300,
        },
        egress: { through: "none", bait_profile: "none" },
        speed: {
          conflux: "auto",
          padding: "reduced",
          geoip: false,
          snowflake_max: 2,
          isolation: "none",
        },
        scopes: { suffixes: [] },
        relay_scan: {
          enabled: false,
          ports: [443, 9001],
          countries: [],
          goal: 6,
          timeout_sec: 90,
        },
        max_restarts_per_hour: 6,
        bootstrap_timeout_sec: 180,
      } satisfies TorTunnelConfig;
    default:
      return {};
  }
}

export function TunnelSettingsDialog({ kind, onClose }: TunnelSettingsDialogProps) {
  const { t } = useTranslation();
  const { showSuccess, showError } = useSnackbar();
  const [config, setConfig] = useState<B4Config | null>(null);
  const [section, setSection] = useState<Record<string, unknown> | null>(null);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(false);

  const sectionKey = kind ? CONFIG_SECTION[kind] : null;
  const open = kind !== null && sectionKey !== null;

  useEffect(() => {
    if (!open || !kind || !sectionKey) {
      setConfig(null);
      setSection(null);
      return;
    }
    setLoading(true);
    configApi
      .get()
      .then((cfg) => {
        setConfig(cfg);
        // The warp kind edits the AWG-WARP BRANCH (system.warp.awg), not the
        // whole system.warp section — the MASQUE fields keep their own dialog;
        // the nonru kind edits the НЕ РФ branch (system.warp.nonru) the same way.
        const raw =
          kind === "warp"
            ? (cfg.system[sectionKey] as WarpTunnelConfig | undefined)?.awg
            : kind === "nonru"
              ? (cfg.system[sectionKey] as WarpTunnelConfig | undefined)?.nonru
              : cfg.system[sectionKey];
        const base = defaultsFor(kind) as Record<string, unknown>;
        const merged = { ...base, ...((raw ?? {}) as Record<string, unknown>) };
        if (kind === "opera") {
          const m = merged.masquerade as Record<string, unknown>;
          const dm = (defaultsFor("opera") as OperaTunnelConfig).masquerade;
          merged.masquerade = { ...dm, ...(m ?? {}) };
        }
        if (kind === "fxvpn") {
          const m = merged.masquerade as Record<string, unknown>;
          const dm = (defaultsFor("fxvpn") as FxVPNTunnelConfig).masquerade;
          merged.masquerade = { ...dm, ...(m ?? {}) };
          const l = merged.location as Record<string, unknown>;
          const dl = (defaultsFor("fxvpn") as FxVPNTunnelConfig).location;
          merged.location = { ...dl, ...(l ?? {}) };
        }
        if (kind === "proton") {
          const l = merged.location as Record<string, unknown>;
          const dl = (defaultsFor("proton") as ProtonTunnelConfig).location;
          merged.location = { ...dl, ...(l ?? {}) };
          const o = merged.obfuscation as Record<string, unknown>;
          const dov = (defaultsFor("proton") as ProtonTunnelConfig).obfuscation;
          merged.obfuscation = { ...dov, ...(o ?? {}) };
        }
        if (kind === "tor") {
          for (const sub of ["entry", "bridges", "egress", "speed", "scopes", "relay_scan"] as const) {
            const cur = merged[sub] as Record<string, unknown> | undefined;
            const dflt = (defaultsFor("tor") as unknown as Record<string, Record<string, unknown>>)[sub];
            merged[sub] = { ...dflt, ...(cur ?? {}) };
          }
        }
        if (kind === "masque") {
          const m = merged.masquerade as Record<string, unknown>;
          const dm = (defaultsFor("masque") as WarpTunnelConfig).masquerade;
          merged.masquerade = { ...dm, ...(m ?? {}) };
        }
        if (kind === "nonru") {
          // Pull the BASE system.warp.socks5 into the view: the НЕ РУ dialog is
          // where the operator enters the non-RU egress proxy, but the value
          // lives on the base warp section (that is what warpservice reads).
          merged.socks5 =
            (cfg.system[sectionKey] as WarpTunnelConfig | undefined)?.socks5 ?? "";
        }
        setSection(merged);
      })
      .catch((err: unknown) => {
        showError(err instanceof Error ? err.message : "load failed");
        onClose();
      })
      .finally(() => {
        setLoading(false);
      });
  }, [open, kind, sectionKey, onClose, showError]);

  // dot-path setter over the local section copy
  const setField = useCallback(
    (path: string, value: unknown) => {
      setSection((prev) => {
        if (!prev) return prev;
        const keys = path.split(".");
        const next = { ...prev };
        let cur: Record<string, unknown> = next;
        for (let i = 0; i < keys.length - 1; i++) {
          cur[keys[i]] = { ...(cur[keys[i]] as Record<string, unknown>) };
          cur = cur[keys[i]] as Record<string, unknown>;
        }
        cur[keys.at(-1)!] = value;
        return next;
      });
    },
    [],
  );

  const g = (path: string): unknown => {
    if (!section) return undefined;
    return path.split(".").reduce<unknown>((acc, key) => {
      if (acc && typeof acc === "object") {
        return (acc as Record<string, unknown>)[key];
      }
      return undefined;
    }, section);
  };
  const s = (path: string, fb = ""): string => {
    const v = g(path);
    return typeof v === "string" ? v : fb;
  };
  const n = (path: string, fb = 0): number => {
    const v = g(path);
    return typeof v === "number" ? v : fb;
  };
  const b = (path: string, fb = false): boolean => {
    const v = g(path);
    return typeof v === "boolean" ? v : fb;
  };
  const arr = (path: string): string[] => {
    const v = g(path);
    return Array.isArray(v) ? (v.filter((x) => typeof x === "string") as string[]) : [];
  };

  const dirty = useMemo(() => {
    if (!config || !sectionKey || !section) return false;
    const original =
      kind === "warp"
        ? (config.system[sectionKey] as WarpTunnelConfig | undefined)?.awg ?? defaultsFor("warp")
        : kind === "nonru"
          ? {
              ...(((config.system[sectionKey] as WarpTunnelConfig | undefined)?.nonru ??
                defaultsFor("nonru")) as Record<string, unknown>),
              socks5: (config.system[sectionKey] as WarpTunnelConfig | undefined)?.socks5 ?? "",
            }
          : config.system[sectionKey] ?? defaultsFor(kind ?? "masque");
    return JSON.stringify(section) !== JSON.stringify(original);
  }, [config, section, sectionKey, kind]);

  const applyNow = useMemo(() => {
    // live location/region switch needs a running tunnel
    return kind === "opera" || kind === "proton" || kind === "fxvpn";
  }, [kind]);

  const save = async () => {
    if (!config || !sectionKey || !section) return;
    try {
      setSaving(true);
      const next =
        kind === "warp"
          ? {
              ...config,
              system: {
                ...config.system,
                warp: {
                  ...(config.system.warp ?? {}),
                  awg: section as unknown as WarpAWGConfig,
                } as WarpTunnelConfig,
              },
            }
          : kind === "nonru"
            ? (() => {
                // socks5 belongs to the BASE warp section, not to nonru.
                const { socks5, ...nonruSection } = section as Record<string, unknown>;
                return {
                  ...config,
                  system: {
                    ...config.system,
                    warp: {
                      ...(config.system.warp ?? {}),
                      socks5: typeof socks5 === "string" ? socks5 : "",
                      nonru: nonruSection as unknown as WarpNonRUConfig,
                    } as WarpTunnelConfig,
                  },
                };
              })()
            : {
              ...config,
              system: { ...config.system, [sectionKey]: section },
            };
      await configApi.save(next);
      showSuccess(t("core.configSavedRestart"));
      if (applyNow) {
        try {
          if (kind === "opera" && s("region")) {
            await tunnelLocationApi.operaRegion(s("region"));
          }
          if (kind === "proton") {
            await tunnelLocationApi.protonLocation({
              mode: s("location.mode", "auto"),
              country: s("location.country"),
              host: s("location.host"),
            });
          }
          if (kind === "fxvpn") {
            await tunnelLocationApi.fxvpnLocation({
              mode: s("location.mode", "auto"),
              country: s("location.country"),
              city: s("location.city"),
              host: s("location.host"),
            });
          }
        } catch {
          // live switch is best-effort (tunnel may be disabled); the
          // persisted config is the source of truth after the restart.
        }
      }
      onClose();
    } catch (err) {
      showError(err instanceof Error ? err.message : "save failed");
    } finally {
      setSaving(false);
    }
  };

  if (!kind || !sectionKey) {
    return null;
  }

  const renderFields = () => {
    switch (kind) {
      case "warp":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.awg.endpoint")}
                value={s("endpoint")}
                onChange={(e) => setField("endpoint", e.target.value)}
                helperText={t("tunnels.awg.endpointHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.awg.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
                helperText={t("tunnels.awg.identityPathHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.awg.profile")}
                select
                value={s("profile")}
                onChange={(e) => setField("profile", e.target.value)}
                helperText={t("tunnels.awg.profileHint")}
              >
                {AWG_PROFILE_IDS.map((id) => (
                  <MenuItem key={id || "default"} value={id}>
                    {id === "" ? t("tunnels.awg.profileAuto") : id}
                  </MenuItem>
                ))}
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 3 }}>
              <B4NumberField
                label={t("tunnels.awg.mtu")}
                value={n("mtu", 0)}
                onChange={(v) => setField("mtu", v)}
                min={0}
                max={1480}
                helperText={t("tunnels.awg.mtuHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 3 }}>
              <B4NumberField
                label={t("tunnels.awg.maxRestarts")}
                value={n("max_restarts_per_hour", 6)}
                onChange={(v) => setField("max_restarts_per_hour", v)}
                min={0}
                max={60}
                helperText={t("tunnels.awg.maxRestartsHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.awg.mode")}
                select
                value={s("mode", "netstack") || "netstack"}
                onChange={(e) => setField("mode", e.target.value)}
                helperText={t("tunnels.awg.modeHint")}
              >
                <MenuItem value="netstack">
                  {t("tunnels.awg.modeNetstack")}
                </MenuItem>
                <MenuItem value="kernel">{t("tunnels.awg.modeKernel")}</MenuItem>
              </B4TextField>
            </Grid>
            {(s("mode", "netstack") || "netstack") === "kernel" && (
              <>
                <Grid size={{ xs: 12 }}>
                  <B4Alert severity="info">{t("tunnels.awg.kernelNote")}</B4Alert>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <B4TextField
                    label={t("tunnels.awg.kernelInterface")}
                    value={s("kernel.interface")}
                    onChange={(e) => setField("kernel.interface", e.target.value)}
                    helperText={t("tunnels.awg.kernelInterfaceHint")}
                  />
                </Grid>
                <Grid size={{ xs: 6, md: 3 }}>
                  <B4NumberField
                    label={t("tunnels.awg.kernelTable")}
                    value={n("kernel.table", 0)}
                    onChange={(v) => setField("kernel.table", v)}
                    min={0}
                    max={4294967294}
                    helperText={t("tunnels.awg.kernelTableHint")}
                  />
                </Grid>
                <Grid size={{ xs: 6, md: 3 }}>
                  <B4NumberField
                    label={t("tunnels.awg.kernelPriority")}
                    value={n("kernel.rule_priority", 0)}
                    onChange={(v) => setField("kernel.rule_priority", v)}
                    min={0}
                    max={32765}
                    helperText={t("tunnels.awg.kernelPriorityHint")}
                  />
                </Grid>
                <Grid size={{ xs: 6, md: 3 }}>
                  <B4NumberField
                    label={t("tunnels.awg.kernelFwmark")}
                    value={n("kernel.fwmark", 0)}
                    onChange={(v) => setField("kernel.fwmark", v)}
                    min={0}
                    max={4294967295}
                    helperText={t("tunnels.awg.kernelFwmarkHint")}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <StringListField
                    label={t("tunnels.awg.kernelFromCidrs")}
                    values={arr("kernel.from_cidrs")}
                    onChange={(values) => setField("kernel.from_cidrs", values)}
                    placeholder="192.168.1.0/24"
                    helperText={t("tunnels.awg.kernelFromCidrsHint")}
                  />
                </Grid>
              </>
            )}
          </Grid>
        );
      case "masque":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.masque.endpoint")}
                value={s("endpoint")}
                onChange={(e) => setField("endpoint", e.target.value)}
                helperText={t("tunnels.masque.endpointHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.masque.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
                helperText={t("tunnels.masque.identityPathHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.masque.fingerprint")}
                select
                value={s("masquerade.fingerprint")}
                onChange={(e) => setField("masquerade.fingerprint", e.target.value)}
                helperText={t("tunnels.masque.fingerprintHint")}
              >
                <MenuItem value="">{t("tunnels.masque.fpAuto")}</MenuItem>
                <MenuItem value="chrome120">chrome120</MenuItem>
                <MenuItem value="firefox">firefox</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.masque.deferRevalidation")}
                checked={b("defer_revalidation")}
                onChange={(v) => setField("defer_revalidation", v)}
                description={t("tunnels.masque.deferRevalidationDesc")}
              />
            </Grid>
          </Grid>
        );
      case "nonru":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.nonru.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <B4Alert severity="warning">
                {t("tunnels.nonru.experimental")}
              </B4Alert>
            </Grid>
            <Grid size={{ xs: 12 }}>
              <B4TextField
                label={t("tunnels.nonru.socks5")}
                value={s("socks5")}
                onChange={(e) => setField("socks5", e.target.value)}
                helperText={t("tunnels.nonru.socks5Hint")}
                placeholder="socks5://user:pass@host:port"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
                helperText={t("tunnels.nonru.identityPathHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.endpoint")}
                value={s("endpoint")}
                onChange={(e) => setField("endpoint", e.target.value)}
                helperText={t("tunnels.nonru.endpointHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.fingerprint")}
                select
                value={s("fingerprint")}
                onChange={(e) => setField("fingerprint", e.target.value)}
                helperText={t("tunnels.nonru.fingerprintHint")}
              >
                <MenuItem value="">{t("tunnels.masque.fpAuto")}</MenuItem>
                <MenuItem value="chrome120">chrome120</MenuItem>
                <MenuItem value="firefox">firefox</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.innerMtu")}
                type="number"
                value={n("inner_mtu")}
                onChange={(e) => setField("inner_mtu", Number(e.target.value) || 0)}
                inputProps={{ min: 0, max: 1200, step: 1 }}
                helperText={t("tunnels.nonru.innerMtuHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.attestationTtl")}
                type="number"
                value={n("attestation_ttl_seconds")}
                onChange={(e) => setField("attestation_ttl_seconds", Number(e.target.value) || 0)}
                inputProps={{ min: 0, step: 1 }}
                helperText={t("tunnels.nonru.attestationTtlHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.nonru.refreshInterval")}
                type="number"
                value={n("refresh_interval_seconds")}
                onChange={(e) => setField("refresh_interval_seconds", Number(e.target.value) || 0)}
                inputProps={{ min: 0, step: 1 }}
                helperText={t("tunnels.nonru.refreshIntervalHint")}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <StringListField
                label={t("tunnels.nonru.ruCountries")}
                values={arr("ru_countries")}
                onChange={(values) => setField("ru_countries", values)}
                placeholder="RU"
                helperText={t("tunnels.nonru.ruCountriesHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.nonru.fallbackToBase")}
                checked={b("fallback_to_base")}
                onChange={(v) => setField("fallback_to_base", v)}
                description={t("tunnels.nonru.fallbackToBaseDesc")}
              />
            </Grid>
          </Grid>
        );
      case "opera":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.opera.region")}
                select
                value={s("region", "EU")}
                onChange={(e) => setField("region", e.target.value)}
                helperText={t("tunnels.opera.regionHint")}
              >
                <MenuItem value="EU">EU</MenuItem>
                <MenuItem value="AS">AS</MenuItem>
                <MenuItem value="AM">AM</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.opera.controlTarget")}
                value={s("control_target")}
                onChange={(e) => setField("control_target", e.target.value)}
                helperText={t("tunnels.opera.controlTargetHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.opera.fakeSni")}
                value={s("fake_sni")}
                onChange={(e) => setField("fake_sni", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.opera.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.opera.profile")}
                select
                value={s("masquerade.profile", "browser")}
                onChange={(e) => setField("masquerade.profile", e.target.value)}
              >
                <MenuItem value="browser">browser</MenuItem>
                <MenuItem value="minimal">minimal</MenuItem>
                <MenuItem value="off">off</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.opera.sniMode")}
                select
                value={s("masquerade.sni_mode", "node")}
                onChange={(e) => setField("masquerade.sni_mode", e.target.value)}
              >
                <MenuItem value="node">node</MenuItem>
                <MenuItem value="pool">pool</MenuItem>
                <MenuItem value="none">none</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4Switch
                label={t("tunnels.opera.ttlFake")}
                checked={b("masquerade.ttl_fake")}
                onChange={(v) => setField("masquerade.ttl_fake", v)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <StringListField
                label={t("tunnels.opera.sniPool")}
                values={arr("masquerade.sni_pool")}
                onChange={(v) => setField("masquerade.sni_pool", v)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <StringListField
                label={t("tunnels.opera.alpn")}
                values={arr("masquerade.alpn")}
                onChange={(v) => setField("masquerade.alpn", v)}
              />
            </Grid>
          </Grid>
        );
      case "vless":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.vless.client")}
                select
                value={s("client", "auto")}
                onChange={(e) => setField("client", e.target.value)}
                helperText={t("tunnels.vless.clientHint")}
              >
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="in-process">in-process</MenuItem>
                <MenuItem value="helper">helper</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.vless.helper")}
                select
                value={s("helper", "xray")}
                onChange={(e) => setField("helper", e.target.value)}
                helperText={t("tunnels.vless.helperHint")}
              >
                <MenuItem value="xray">xray</MenuItem>
                <MenuItem value="sing-box">sing-box</MenuItem>
                <MenuItem value="external">external</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.vless.helperPath")}
                value={s("helper_path")}
                onChange={(e) => setField("helper_path", e.target.value)}
                helperText={t("tunnels.vless.helperPathHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.vless.socksAddr")}
                value={s("socks_addr", "127.0.0.1:1081")}
                onChange={(e) => setField("socks_addr", e.target.value)}
                helperText={t("tunnels.vless.socksAddrHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.vless.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.vless.controlTarget")}
                value={s("control_target", "www.cloudflare.com")}
                onChange={(e) => setField("control_target", e.target.value)}
                helperText={t("tunnels.vless.controlTargetHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.vless.bundledSources")}
                checked={b("bundled_sources", true)}
                onChange={(v) => setField("bundled_sources", v)}
                description={t("tunnels.vless.bundledSourcesDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.vless.preferNonru")}
                checked={b("prefer_nonru", true)}
                onChange={(v) => setField("prefer_nonru", v)}
                description={t("tunnels.vless.preferNonruDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4NumberField
                label={t("tunnels.vless.subscriptionInterval")}
                value={n("subscription_interval_sec", 21600)}
                onChange={(v) => setField("subscription_interval_sec", v)}
                min={60}
                max={604800}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4NumberField
                label={t("tunnels.vless.maxRestarts")}
                value={n("max_restarts_per_hour", 6)}
                onChange={(v) => setField("max_restarts_per_hour", v)}
                min={0}
                max={60}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.vless.seekInterval")}
                value={n("seek_interval_sec", 300)}
                onChange={(v) => setField("seek_interval_sec", v)}
                min={30}
                max={86400}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.vless.seekTolerance")}
                value={n("seek_tolerance_ms", 50)}
                onChange={(v) => setField("seek_tolerance_ms", v)}
                min={0}
                max={5000}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.vless.pinNode")}
                value={s("pin_node")}
                onChange={(e) => setField("pin_node", e.target.value)}
                helperText={t("tunnels.vless.pinNodeHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.vless.udp")}
                checked={b("udp")}
                onChange={(v) => setField("udp", v)}
                description={t("tunnels.vless.udpDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.vless.mixed")}
                checked={b("mixed")}
                onChange={(v) => setField("mixed", v)}
                description={t("tunnels.vless.mixedDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <StringListField
                label={t("tunnels.vless.nodes")}
                values={arr("nodes")}
                onChange={(v) => setField("nodes", v)}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <StringListField
                label={t("tunnels.vless.subscriptions")}
                values={arr("subscriptions")}
                onChange={(v) => setField("subscriptions", v)}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <StringListField
                label={t("tunnels.vless.countryDeny")}
                values={arr("country_deny")}
                onChange={(v) => setField("country_deny", v)}
              />
            </Grid>
          </Grid>
        );
      case "fxvpn":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.locationMode")}
                select
                value={s("location.mode", "auto")}
                onChange={(e) => setField("location.mode", e.target.value)}
              >
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="country">country</MenuItem>
                <MenuItem value="host">host</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.country")}
                value={s("location.country")}
                onChange={(e) => setField("location.country", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.city")}
                value={s("location.city")}
                onChange={(e) => setField("location.city", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.fields.host")}
                value={s("location.host")}
                onChange={(e) => setField("location.host", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.fxvpn.accountsPath")}
                value={s("accounts_path")}
                onChange={(e) => setField("accounts_path", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.fxvpn.preferH3")}
                checked={b("prefer_h3")}
                onChange={(v) => setField("prefer_h3", v)}
                description={t("tunnels.fxvpn.preferH3Desc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4NumberField
                label={t("tunnels.fxvpn.rotateThreshold")}
                value={n("rotate_threshold_pct", 15)}
                onChange={(v) => setField("rotate_threshold_pct", v)}
                min={0}
                max={100}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fxvpn.profile")}
                select
                value={s("masquerade.profile", "firefox")}
                onChange={(e) => setField("masquerade.profile", e.target.value)}
              >
                <MenuItem value="firefox">firefox</MenuItem>
                <MenuItem value="go-plain">go-plain</MenuItem>
                <MenuItem value="off">off</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.fxvpn.fakeTtl")}
                value={n("masquerade.fake_ttl", 4)}
                onChange={(v) => setField("masquerade.fake_ttl", v)}
                min={2}
                max={8}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.fxvpn.fakeCount")}
                value={n("masquerade.fake_count", 2)}
                onChange={(v) => setField("masquerade.fake_count", v)}
                min={1}
                max={2}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.fxvpn.initialPadding")}
                value={n("masquerade.initial_padding", 1250)}
                onChange={(v) => setField("masquerade.initial_padding", v)}
                min={0}
                max={65000}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4Switch
                label={t("tunnels.fxvpn.preflightFake")}
                checked={b("masquerade.preflight_fake")}
                onChange={(v) => setField("masquerade.preflight_fake", v)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4Switch
                label={t("tunnels.fxvpn.helloShaping")}
                checked={b("masquerade.hello_shaping", true)}
                onChange={(v) => setField("masquerade.hello_shaping", v)}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fxvpn.nestOnPortBlock")}
                checked={b("masquerade.nest_on_port_block")}
                onChange={(v) => setField("masquerade.nest_on_port_block", v)}
                description={t("tunnels.fxvpn.nestOnPortBlockDesc")}
              />
            </Grid>
          </Grid>
        );
      case "proton":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.locationMode")}
                select
                value={s("location.mode", "auto")}
                onChange={(e) => setField("location.mode", e.target.value)}
              >
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="country">country</MenuItem>
                <MenuItem value="host">host</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.country")}
                value={s("location.country")}
                onChange={(e) => setField("location.country", e.target.value)}
                helperText={t("tunnels.proton.countryHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.fields.host")}
                value={s("location.host")}
                onChange={(e) => setField("location.host", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4TextField
                label={t("tunnels.proton.identityPath")}
                value={s("identity_path")}
                onChange={(e) => setField("identity_path", e.target.value)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4NumberField
                label={t("tunnels.proton.port")}
                value={n("port")}
                onChange={(v) => setField("port", v)}
                min={0}
                max={65535}
                helperText={t("tunnels.proton.portHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label="MTU"
                value={n("mtu", 1420)}
                onChange={(v) => setField("mtu", v)}
                min={1280}
                max={1420}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.proton.tunnelMode")}
                select
                value={s("tunnel_mode", "netstack")}
                onChange={(e) => setField("tunnel_mode", e.target.value)}
              >
                <MenuItem value="netstack">netstack</MenuItem>
                <MenuItem value="kernel">kernel</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.proton.maxRestarts")}
                value={n("max_restarts_per_hour", 6)}
                onChange={(v) => setField("max_restarts_per_hour", v)}
                min={0}
                max={60}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.proton.obfuscation")}
                checked={b("obfuscation.enabled")}
                onChange={(v) => setField("obfuscation.enabled", v)}
                description={t("tunnels.proton.obfuscationDesc")}
              />
            </Grid>
            {b("obfuscation.enabled") && (
              <>
                <Grid size={{ xs: 12, md: 6 }}>
                  <B4TextField
                    label={t("tunnels.proton.preferredProfile")}
                    select
                    value={s("obfuscation.preferred_profile")}
                    onChange={(e) =>
                      setField("obfuscation.preferred_profile", e.target.value)
                    }
                    helperText={t("tunnels.proton.preferredProfileHint")}
                  >
                    <MenuItem value="">{t("tunnels.masque.fpAuto")}</MenuItem>
                    <MenuItem value="proton-quic">proton-quic</MenuItem>
                  </B4TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <B4Switch
                    label={t("tunnels.proton.i1Adaptation")}
                    checked={b("obfuscation.i1_adaptation")}
                    onChange={(v) => setField("obfuscation.i1_adaptation", v)}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <StringListField
                    label={t("tunnels.proton.sniPool")}
                    values={arr("obfuscation.sni_pool")}
                    onChange={(v) => setField("obfuscation.sni_pool", v)}
                  />
                </Grid>
              </>
            )}
          </Grid>
        );
      case "tor":
        return (
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <B4Switch
                label={t("tunnels.fields.enabled")}
                checked={b("enabled")}
                onChange={(v) => setField("enabled", v)}
                description={t("tunnels.fields.enabledDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.entryMode")}
                select
                value={s("entry.mode", "auto")}
                onChange={(e) => setField("entry.mode", e.target.value)}
                helperText={t("tunnels.tor.entryModeHint")}
              >
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="webtunnel">webtunnel</MenuItem>
                <MenuItem value="obfs4">obfs4</MenuItem>
                <MenuItem value="snowflake">snowflake</MenuItem>
                <MenuItem value="meek">meek</MenuItem>
                <MenuItem value="vanilla">vanilla</MenuItem>
                <MenuItem value="direct">direct</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.tor.raceWindow")}
                value={n("entry.race_window", 2)}
                onChange={(v) => setField("entry.race_window", v)}
                min={0}
                max={4}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.egressThrough")}
                select
                value={s("egress.through", "none")}
                onChange={(e) => setField("egress.through", e.target.value)}
                helperText={t("tunnels.tor.egressThroughHint")}
              >
                <MenuItem value="none">none</MenuItem>
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="masque">masque</MenuItem>
                <MenuItem value="opera">opera</MenuItem>
                <MenuItem value="fxvpn">fxvpn</MenuItem>
                <MenuItem value="proton">proton</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.baitProfile")}
                select
                value={s("egress.bait_profile", "none")}
                onChange={(e) => setField("egress.bait_profile", e.target.value)}
              >
                <MenuItem value="none">none</MenuItem>
                <MenuItem value="first-flight">first-flight</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.conflux")}
                select
                value={s("speed.conflux", "auto")}
                onChange={(e) => setField("speed.conflux", e.target.value)}
              >
                <MenuItem value="auto">auto</MenuItem>
                <MenuItem value="off">off</MenuItem>
                <MenuItem value="throughput">throughput</MenuItem>
                <MenuItem value="latency">latency</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.padding")}
                select
                value={s("speed.padding", "reduced")}
                onChange={(e) => setField("speed.padding", e.target.value)}
              >
                <MenuItem value="reduced">reduced</MenuItem>
                <MenuItem value="full">full</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4TextField
                label={t("tunnels.tor.isolation")}
                select
                value={s("speed.isolation", "none")}
                onChange={(e) => setField("speed.isolation", e.target.value)}
              >
                <MenuItem value="none">none</MenuItem>
                <MenuItem value="per-destination">per-destination</MenuItem>
              </B4TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.tor.snowflakeMax")}
                value={n("speed.snowflake_max", 2)}
                onChange={(v) => setField("speed.snowflake_max", v)}
                min={1}
                max={8}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.tor.bootstrapTimeout")}
                value={n("bootstrap_timeout_sec", 180)}
                onChange={(v) => setField("bootstrap_timeout_sec", v)}
                min={30}
                max={600}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <B4NumberField
                label={t("tunnels.tor.maxRestarts")}
                value={n("max_restarts_per_hour", 6)}
                onChange={(v) => setField("max_restarts_per_hour", v)}
                min={0}
                max={60}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.tor.builtinSnowflake")}
                checked={b("bridges.builtin_snowflake", true)}
                onChange={(v) => setField("bridges.builtin_snowflake", v)}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <B4Switch
                label={t("tunnels.tor.relayScan")}
                checked={b("relay_scan.enabled")}
                onChange={(v) => setField("relay_scan.enabled", v)}
                description={t("tunnels.tor.relayScanDesc")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <StringListField
                label={t("tunnels.tor.bridgeLines")}
                values={arr("bridges.lines")}
                onChange={(v) => setField("bridges.lines", v)}
                helperText={t("tunnels.tor.bridgeLinesHint")}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <StringListField
                label={t("tunnels.tor.scopeSuffixes")}
                values={arr("scopes.suffixes")}
                onChange={(v) => setField("scopes.suffixes", v)}
                helperText={t("tunnels.tor.scopeSuffixesHint")}
              />
            </Grid>
          </Grid>
        );
      default:
        return (
          <B4Alert severity="info">{t("tunnels.noConfigSection")}</B4Alert>
        );
    }
  };

  return (
    <B4Dialog
      open={open}
      onClose={onClose}
      title={`${t("tunnels.settingsTitle")} — ${t(`tunnels.kind.${kind}`)}`}
      subtitle={t(`tunnels.kindDesc.${kind}`)}
      icon={<TunnelsIcon />}
      maxWidth="md"
      fullWidth
      scroll="body"
      headerAlert={
        <B4Alert severity="warning">{t("tunnels.settingsRestartWarning")}</B4Alert>
      }
      actions={
        <>
          <Button onClick={onClose}>{t("core.cancel")}</Button>
          <Button
            variant="contained"
            startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
            disabled={!dirty || saving || loading}
            onClick={() => {
              void save();
            }}
          >
            {t("core.save")}
          </Button>
        </>
      }
    >
      {loading || !section ? (
        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
          <CircularProgress />
        </Box>
      ) : (
        renderFields()
      )}
      {applyNow && (
        <Stack sx={{ mt: 2 }}>
          <B4Alert severity="info">{t("tunnels.applyNowNote")}</B4Alert>
        </Stack>
      )}
    </B4Dialog>
  );
}
