export interface AdBlockStats {
  blocked_total: number;
  pass_total: number;
  ech_skipped: number;
  allowlisted: number;
  list_missing: number;
  list_invalid: number;
  reload_failed: number;
  fetch_ok: number;
  fetch_fail: number;
  enabled: boolean;
}

export interface AdBlockListEntry {
  source: string;
  type: "url" | "file";
  enabled: boolean;
  cached: boolean;
  size_bytes: number;
  /** RFC3339 timestamp, empty when unknown */
  last_modified: string;
}

export interface AdBlockStatus {
  enabled: boolean;
  action: "drop" | "rst";
  refresh_hours: number;
  log_matches: boolean;
  cache_dir: string;
  lists: AdBlockListEntry[];
  allowlist: string[];
  stats: AdBlockStats;
}

export interface AdBlockConfigPatch {
  enabled?: boolean;
  action?: "drop" | "rst";
  refresh_hours?: number;
  log_matches?: boolean;
}
