// SNI ad-block control plane (GUI "пульт"): status+stats, config toggle,
// per-list add/remove/toggle/refresh. Follows the sets.go discipline:
// clone → mutate → saveAndPushConfig; worker propagation happens through
// Worker.UpdateConfig → adblock.ApplyConfig.
package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

func (api *API) RegisterAdBlockApi() {
	api.mux.HandleFunc("/api/adblock", api.handleAdBlock)
	api.mux.HandleFunc("/api/adblock/config", api.handleAdBlockConfig)
	api.mux.HandleFunc("/api/adblock/lists/add", api.handleAdBlockListAdd)
	api.mux.HandleFunc("/api/adblock/lists/remove", api.handleAdBlockListRemove)
	api.mux.HandleFunc("/api/adblock/lists/toggle", api.handleAdBlockListToggle)
	api.mux.HandleFunc("/api/adblock/refresh", api.handleAdBlockRefresh)
}

type adBlockListEntry struct {
	Source    string `json:"source"`
	Type      string `json:"type"` // "url" | "file"
	Enabled   bool   `json:"enabled"`
	Cached    bool   `json:"cached"`        // subscription cache file present
	SizeBytes int64  `json:"size_bytes"`    // 0 when unknown
	ModTime   string `json:"last_modified"` // RFC3339, empty when unknown
}

type adBlockStatus struct {
	Enabled      bool               `json:"enabled"`
	Action       string             `json:"action"`
	RefreshHours int                `json:"refresh_hours"`
	LogMatches   bool               `json:"log_matches"`
	CacheDir     string             `json:"cache_dir"`
	Lists        []adBlockListEntry `json:"lists"`
	Allowlist    []string           `json:"allowlist"`
	Stats        adblock.Stats      `json:"stats"`
}

func adBlockCacheDir(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return adblock.ResolveCacheDir(cfg.AdBlock, cfg.ConfigPath)
}

func buildAdBlockStatus(cfg *config.Config) adBlockStatus {
	cfg.AdBlock.FillDefaults()
	st := adBlockStatus{
		Enabled:      cfg.AdBlock.Enabled,
		Action:       cfg.AdBlock.Action,
		RefreshHours: cfg.AdBlock.RefreshHours,
		LogMatches:   cfg.AdBlock.LogMatches,
		CacheDir:     adBlockCacheDir(cfg),
		Lists:        []adBlockListEntry{},
		Allowlist:    append([]string(nil), cfg.AdBlock.Allowlist...),
		Stats:        adblock.GetStats(),
	}
	cacheDir := st.CacheDir
	for _, l := range cfg.AdBlock.Lists {
		e := adBlockListEntry{
			Source:  l.Source,
			Type:    "file",
			Enabled: l.Enabled,
		}
		if strings.HasPrefix(l.Source, "http://") || strings.HasPrefix(l.Source, "https://") {
			e.Type = "url"
			if p := adblock.CachePathFor(cacheDir, l.Source); p != "" {
				if fi, err := os.Stat(p); err == nil {
					e.Cached = true
					e.SizeBytes = fi.Size()
					e.ModTime = fi.ModTime().Format(time.RFC3339)
				}
			}
		} else if fi, err := os.Stat(l.Source); err == nil {
			e.Cached = true
			e.SizeBytes = fi.Size()
			e.ModTime = fi.ModTime().Format(time.RFC3339)
		}
		st.Lists = append(st.Lists, e)
	}
	sort.Slice(st.Lists, func(i, j int) bool { return st.Lists[i].Source < st.Lists[j].Source })
	return st
}

// GET /api/adblock — full panel payload.
func (api *API) handleAdBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(buildAdBlockStatus(api.getCfg()))
}

// PUT /api/adblock/config — update toggles: enabled/action/refresh_hours/
// log_matches. Lists are managed through the dedicated endpoints.
func (api *API) handleAdBlockConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled      *bool   `json:"enabled"`
		Action       *string `json:"action"`
		RefreshHours *int    `json:"refresh_hours"`
		LogMatches   *bool   `json:"log_matches"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, ErrInvalidJSON())
		return
	}
	if req.Action != nil && *req.Action != "drop" && *req.Action != "rst" {
		writeAPIError(w, ErrBadRequest("action must be drop or rst"))
		return
	}

	oldCfg := api.getCfg()
	newCfg := oldCfg.Clone()
	if req.Enabled != nil {
		newCfg.AdBlock.Enabled = *req.Enabled
	}
	if req.Action != nil {
		newCfg.AdBlock.Action = *req.Action
	}
	if req.RefreshHours != nil {
		if *req.RefreshHours < 0 {
			writeAPIError(w, ErrBadRequest("refresh_hours must be >= 0"))
			return
		}
		newCfg.AdBlock.RefreshHours = *req.RefreshHours
	}
	if req.LogMatches != nil {
		newCfg.AdBlock.LogMatches = *req.LogMatches
	}

	if err := api.saveAndPushConfig(newCfg); err != nil {
		log.Errorf("adblock config save failed: %v", err)
		writeAPIError(w, err)
		return
	}
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(buildAdBlockStatus(newCfg))
}

func findListIndex(cfg *config.Config, source string) int {
	for i, l := range cfg.AdBlock.Lists {
		if strings.EqualFold(strings.TrimSpace(l.Source), strings.TrimSpace(source)) {
			return i
		}
	}
	return -1
}

// POST /api/adblock/lists/add {"source": "..."} — URL or local path.
func (api *API) handleAdBlockListAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Source) == "" {
		writeAPIError(w, ErrBadRequest("source required"))
		return
	}
	req.Source = strings.TrimSpace(req.Source)

	oldCfg := api.getCfg()
	newCfg := oldCfg.Clone()
	if idx := findListIndex(newCfg, req.Source); idx >= 0 {
		writeAPIError(w, ErrBadRequest("source already configured"))
		return
	}
	newCfg.AdBlock.Lists = append(newCfg.AdBlock.Lists,
		config.AdBlockList{Source: req.Source, Enabled: true})

	if err := api.saveAndPushConfig(newCfg); err != nil {
		writeAPIError(w, err)
		return
	}
	log.Infof("adblock: list added: %s", req.Source)
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(buildAdBlockStatus(newCfg))
}

// POST /api/adblock/lists/remove {"source": "..."}.
func (api *API) handleAdBlockListRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, ErrInvalidJSON())
		return
	}
	oldCfg := api.getCfg()
	newCfg := oldCfg.Clone()
	idx := findListIndex(newCfg, req.Source)
	if idx < 0 {
		writeAPIError(w, ErrNotFound("source not configured"))
		return
	}
	removed := newCfg.AdBlock.Lists[idx]
	newCfg.AdBlock.Lists = append(newCfg.AdBlock.Lists[:idx], newCfg.AdBlock.Lists[idx+1:]...)

	if err := api.saveAndPushConfig(newCfg); err != nil {
		writeAPIError(w, err)
		return
	}
	// Drop the cached copy of a removed subscription (best effort).
	if strings.HasPrefix(removed.Source, "http") {
		if dir := adBlockCacheDir(newCfg); dir != "" {
			_ = os.Remove(adblock.CachePathFor(dir, removed.Source))
		}
	}
	log.Infof("adblock: list removed: %s", removed.Source)
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(buildAdBlockStatus(newCfg))
}

// POST /api/adblock/lists/toggle {"source":"...", "enabled":true|false}.
func (api *API) handleAdBlockListToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source  string `json:"source"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, ErrInvalidJSON())
		return
	}
	oldCfg := api.getCfg()
	newCfg := oldCfg.Clone()
	idx := findListIndex(newCfg, req.Source)
	if idx < 0 {
		writeAPIError(w, ErrNotFound("source not configured"))
		return
	}
	newCfg.AdBlock.Lists[idx].Enabled = req.Enabled

	if err := api.saveAndPushConfig(newCfg); err != nil {
		writeAPIError(w, err)
		return
	}
	log.Infof("adblock: list %s enabled=%v", newCfg.AdBlock.Lists[idx].Source, req.Enabled)
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(buildAdBlockStatus(newCfg))
}

// POST /api/adblock/refresh — force re-download of all enabled subscriptions
// in background; poll GET /api/adblock for updated stats/cached markers.
func (api *API) handleAdBlockRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := api.getCfg()
	go adblock.ForceRefresh(cfg.AdBlock, adBlockCacheDir(cfg))
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "refresh_started"})
}
