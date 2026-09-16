import { apiGet, apiPost, apiPut } from "./apiClient";
import { TunnelKind } from "@models/config";
import {
  TunnelsOverview,
  TunnelsRestartResult,
} from "@models/tunnels";

// Tunnels pane API (design TUNNELS_PANEL_DESIGN.md): the overview surface
// plus the thin dispatchers over the existing per-service endpoints.

export const tunnelsApi = {
  overview: () => apiGet<TunnelsOverview>("/api/tunnels"),
  restart: (kind: TunnelKind) =>
    apiPost<TunnelsRestartResult>(
      `/api/tunnels/restart?kind=${encodeURIComponent(kind)}`,
    ),
};

// Quick region/location switch on a RUNNING tunnel (validation + one
// supervision cycle server-side). The b4.json persistence belongs to the
// generic config save.
export interface LocationSwitchRequest {
  mode?: string;
  country?: string;
  city?: string;
  host?: string;
  region?: string;
}

export const tunnelLocationApi = {
  operaRegion: (region: string) =>
    apiPut<unknown>("/api/opera/region", { region }),
  protonLocation: (req: LocationSwitchRequest) =>
    apiPut<unknown>("/api/proton/location", req),
  fxvpnLocation: (req: LocationSwitchRequest) =>
    apiPut<unknown>("/api/fxvpn/location", req),
};
