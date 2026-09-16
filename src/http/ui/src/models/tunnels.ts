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
}

export interface ChainPreset {
  kind: string;
  outer: string;
  inner: string;
  available: boolean;
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
