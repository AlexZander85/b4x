import { TunnelKind } from "@models/config";

// Tunnel pane models (GET /api/tunnels; design TUNNELS_PANEL_DESIGN.md).

export interface TunnelCard {
  kind: TunnelKind;
  priority: number;
  transport: "udp-full-scope" | "tcp-only" | string;
  supports_udp: boolean;
  has_config_section: boolean;
  config_enabled: boolean;
  carrier_registered: boolean;
  running: boolean;
  listening: boolean;
  state?: string;
  region?: string;
  location_mode?: string;
  location_value?: string;
  restartable: boolean;
  note?: string;
  // Last health measurement (design TUNNELS_PANEL_DESIGN.md §8). Present
  // only after POST /api/tunnels/measure ran for this kind. Recommendation
  // only — it never changes which tunnel routes traffic.
  health?: TunnelHealth;
}

// TunnelHealth mirrors src/transport/health.Metrics.
export interface TunnelHealth {
  kind: string;
  available: boolean;
  rtt_ms?: number;
  ttfb_ms?: number;
  throughput_mbps?: number;
  loss_pct?: number;
  bytes?: number;
  probes: number;
  failures: number;
  score: number;
  // healthy | degraded | poor | unavailable (kept loose: the backend may
  // add verdicts; the UI maps unknown values to a default chip).
  verdict: string;
  error?: string;
  measured_at: string;
}

export interface TunnelsMeasureResult {
  results: Record<string, TunnelHealth>;
}

export interface TunnelsStartAllResult {
  success: boolean;
  enabled: string[];
  restart_required: boolean;
}

export interface ChainPreset {
  kind: string;
  outer: string;
  inner: string;
  available: boolean;
  // Stage 2: the shipped compositions reflect the config entry and the
  // live engine (warpchainservice).
  configured?: boolean;
  enabled?: boolean;
  running?: boolean;
  state?: string;
  note?: string;
}

export interface TunnelAssignment {
  set_id: string;
  set_name: string;
  set_enabled: boolean;
  tunnel: TunnelKind;
  tunnel_running: boolean;
  domains: number;
  geosite_categories: number;
  udp: boolean;
  fail_open: boolean;
}

export interface TunnelsOverview {
  tunnels: TunnelCard[];
  chains: ChainPreset[];
  assignments: TunnelAssignment[];
  registered_carriers: string[];
}

export interface TunnelsRestartResult {
  success: boolean;
  kind: string;
}
