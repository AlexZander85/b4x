import { apiGet, apiPost, apiPut } from "./apiClient";
import { TunnelKind } from "@models/config";
import {
  TunnelsMeasureResult,
  TunnelsOverview,
  TunnelsRestartResult,
  TunnelsStartAllResult,
} from "@models/tunnels";

// Tunnels pane API (design TUNNELS_PANEL_DESIGN.md): the overview surface
// plus the thin dispatchers over the existing per-service endpoints.

export const tunnelsApi = {
  overview: () => apiGet<TunnelsOverview>("/api/tunnels"),
  restart: (kind: TunnelKind) =>
    apiPost<TunnelsRestartResult>(
      `/api/tunnels/restart?kind=${encodeURIComponent(kind)}`,
    ),
  // On-demand health measurement (design §8). Omit kind to measure every
  // registered carrier. Recommendation/score only.
  measure: (kind?: TunnelKind) =>
    apiPost<TunnelsMeasureResult>(
      kind
        ? `/api/tunnels/measure?kind=${encodeURIComponent(kind)}`
        : "/api/tunnels/measure",
    ),
  // Enable every tunnel section (config write). Engine startup needs a
  // daemon restart; the UI follows up with systemApi.restart().
  startAll: () => apiPost<TunnelsStartAllResult>("/api/tunnels/start"),
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

// Available locations (countries → cities → hosts) for the country/city/host
// dropdowns. Both surfaces answer only while the engine is wired (proton needs
// its cached catalog, fxvpn its serverlist); the UI falls back to a free-text
// field when the list is unavailable.
export interface LocationHost {
  name?: string;
  hostname?: string;
  entry_ip?: string;
}

export interface LocationCity {
  name?: string;
  code?: string;
  hosts?: LocationHost[];
}

export interface LocationCountry {
  code: string;
  name?: string;
  cities?: LocationCity[];
}

export interface LocationsView {
  fetched_at?: string;
  countries: LocationCountry[];
}

export const tunnelLocationsApi = {
  proton: () => apiGet<LocationsView>("/api/proton/locations"),
  fxvpn: () => apiGet<LocationsView>("/api/fxvpn/locations"),
};
