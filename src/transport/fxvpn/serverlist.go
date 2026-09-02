// Server list from Mozilla Remote Settings
// (firefox.settings.services.mozilla.com/v1/buckets/main/collections/
// vpn-serverlist/records). Facts verified against the reference serverlist.go
// AND the live production list (design Дополнение 2):
//   - envelope {"data": [...records]}; a record IS a Country when it parses
//     with code+cities (one record per country).
//   - PRODUCTION RECORDS TODAY ARE BARE: {hostname, port=2499} without
//     protocols[] — Firefox defaults them to the "connect" dialect
//     (IPProtectionServerlist: "Default to connect if no protocols are
//     specified"). Both forms are normalized here; protocols[].name=="connect"
//     entries override hostname/port when present.
//   - quarantined servers are excluded from candidates.
//   - versioned filter_expression exist (US >=151.0a1 etc.) — the cache keeps
//     the raw applied set and its ETag so a 304 round-trip reuses it.
package fxvpn

import (
        "context"
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "net/http"
        "strings"
        "sync"
        "time"
)

const (
        serverlistFormatVersion = 1
        defaultServerlistTTL    = 6 * time.Hour
)

type Protocol struct {
        Name           string `json:"name"`
        Host           string `json:"host"`
        Port           int    `json:"port"`
        Scheme         string `json:"scheme,omitempty"`
        TemplateString string `json:"templateString,omitempty"` // masque UriTemplate (задел FX2+)
}

type Server struct {
        Hostname    string     `json:"hostname"`
        Port        int        `json:"port"`
        Quarantined bool       `json:"quarantined"`
        Protocols   []Protocol `json:"protocols"`
}

type City struct {
        Name    string   `json:"name"`
        Code    string   `json:"code"`
        Servers []Server `json:"servers"`
}

type Country struct {
        Name   string `json:"name"`
        Code   string `json:"code"`
        Cities []City `json:"cities"`
}

// ConnectCandidate is one normalized dial target of the "connect" dialect.
type ConnectCandidate struct {
        Hostname    string
        Port        int
        Scheme      string // "https" default
        CityCode    string
        CountryCode string
}

type cachedServerlist struct {
        Version   int       `json:"version"`
        ETag      string    `json:"etag,omitempty"`
        FetchedAt time.Time `json:"fetched_at"`
        Countries []Country `json:"countries"`
}

// ServerlistCache fetches and caches the collection with ETag/TTL.
type ServerlistCache struct {
        CP   *ControlPlane
        Path string // empty = memory-only (tests)
        TTL  time.Duration
        Now  func() time.Time

        mu  sync.Mutex
        cur *cachedServerlist
}

// NewServerlistCache builds a cache; path empty keeps it in memory.
func NewServerlistCache(cp *ControlPlane, path string) (*ServerlistCache, error) {
        sc := &ServerlistCache{
                CP:   cp,
                Path: path,
                TTL:  defaultServerlistTTL,
                Now:  time.Now,
        }
        if path == "" {
                return sc, nil
        }
        blob, err := readStoreFile(path)
        if err != nil {
                if errors.Is(err, ErrStoreAbsent) {
                        return sc, nil
                }
                return nil, err
        }
        var f cachedServerlist
        if jerr := json.Unmarshal(blob, &f); jerr != nil || f.Version != serverlistFormatVersion {
                if qerr := quarantinePath(path); qerr != nil {
                        return sc, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrStoreCorrupt, jerr, qerr)
                }
                return sc, fmt.Errorf("%w: %v", ErrStoreCorrupt, jerr)
        }
        sc.cur = &f
        return sc, nil
}

// Get returns the country list, refreshing over the wire only when the TTL
// expired. A conditional request answered 304 refreshes freshness without
// replacing content. The bool reports whether the value came from cache.
func (sc *ServerlistCache) Get(ctx context.Context) ([]Country, bool, error) {
        sc.mu.Lock()
        defer sc.mu.Unlock()

        now := sc.now()
        if sc.cur != nil && now.Sub(sc.cur.FetchedAt) < sc.TTL {
                return sc.cur.Countries, true, nil
        }

        etag := ""
        if sc.cur != nil {
                etag = sc.cur.ETag
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc.CP.EP.RemoteSettings, nil)
        if err != nil {
                return nil, false, err
        }
        applyMozillaHeaders(req)
        if etag != "" {
                req.Header.Set("If-None-Match", etag)
        }

        resp, err := sc.CP.Do(req)
        if err != nil {
                // Stale-but-present beats dead network for reserve-transport duty.
                if sc.cur != nil {
                        return sc.cur.Countries, true, nil
                }
                return nil, false, fmt.Errorf("fxvpn: fetching server list: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusNotModified && sc.cur != nil {
                sc.cur.FetchedAt = now
                if serr := sc.persistLocked(); serr != nil {
                        return sc.cur.Countries, true, fmt.Errorf("fxvpn: server list cache persist: %w", serr)
                }
                return sc.cur.Countries, true, nil
        }

        if resp.StatusCode != http.StatusOK {
                if sc.cur != nil {
                        return sc.cur.Countries, true, nil
                }
                return nil, false, &GuardianHTTPError{Operation: "serverlist", Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
        }

        body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
        if rerr != nil {
                return nil, false, fmt.Errorf("fxvpn: reading server list response: %w", rerr)
        }

        countries, perr := ParseServerList(body)
        if perr != nil {
                if sc.cur != nil {
                        return sc.cur.Countries, true, nil
                }
                return nil, false, perr
        }

        next := &cachedServerlist{
                Version:   serverlistFormatVersion,
                ETag:      strings.TrimPrefix(resp.Header.Get("ETag"), "W/"),
                FetchedAt: now,
                Countries: countries,
        }
        sc.cur = next
        if serr := sc.persistLocked(); serr != nil {
                return sc.cur.Countries, false, fmt.Errorf("fxvpn: server list cache persist: %w", serr)
        }
        return sc.cur.Countries, false, nil
}

func (sc *ServerlistCache) now() time.Time {
        if sc.Now != nil {
                return sc.Now()
        }
        return time.Now()
}

// FetchedAt returns the freshness stamp of the cached snapshot (zero when
// nothing was fetched yet) — the LocationsView field of the same name (L1).
func (sc *ServerlistCache) FetchedAt() time.Time {
        sc.mu.Lock()
        defer sc.mu.Unlock()
        if sc.cur == nil {
                return time.Time{}
        }
        return sc.cur.FetchedAt
}

func (sc *ServerlistCache) persistLocked() error {
        if sc.Path == "" || sc.cur == nil {
                return nil
        }
        blob, err := json.MarshalIndent(sc.cur, "", "  ")
        if err != nil {
                return err
        }
        return saveAtomic(sc.Path, blob)
}

// ParseServerList decodes the Remote Settings envelope, keeping records that
// parse as Countries with code+cities (reference serverlist.go:73-90).
func ParseServerList(body []byte) ([]Country, error) {
        var rsResp struct {
                Data []json.RawMessage `json:"data"`
        }
        if err := json.Unmarshal(body, &rsResp); err != nil {
                return nil, fmt.Errorf("fxvpn: parsing server list envelope: %w", err)
        }
        var countries []Country
        for _, raw := range rsResp.Data {
                var c Country
                if err := json.Unmarshal(raw, &c); err != nil {
                        continue
                }
                if c.Code != "" && len(c.Cities) > 0 {
                        countries = append(countries, c)
                }
        }
        if len(countries) == 0 {
                return nil, errors.New("fxvpn: server list contains no usable country records")
        }
        return countries, nil
}

// ConnectCandidates normalizes location-filtered connect targets:
// quarantined excluded; protocols[].name=="connect" overrides host/port;
// bare servers default to https://hostname:port. Empty filters match all.
func ConnectCandidates(countries []Country, countryCode, cityCode, host string) []ConnectCandidate {
        out := make([]ConnectCandidate, 0, 16)
        for _, c := range countries {
                if countryCode != "" && !strings.EqualFold(c.Code, countryCode) {
                        continue
                }
                for _, city := range c.Cities {
                        if cityCode != "" && !strings.EqualFold(city.Code, cityCode) {
                                continue
                        }
                        for _, srv := range city.Servers {
                                if srv.Quarantined {
                                        continue
                                }
                                if host != "" && !strings.EqualFold(srv.Hostname, host) {
                                        continue
                                }
                                if len(srv.Protocols) == 0 {
                                        out = append(out, ConnectCandidate{
                                                Hostname:    srv.Hostname,
                                                Port:        srv.Port,
                                                Scheme:      "https",
                                                CityCode:    city.Code,
                                                CountryCode: c.Code,
                                        })
                                        continue
                                }
                                for _, proto := range srv.Protocols {
                                        if proto.Name != "connect" || proto.Host == "" || proto.Port <= 0 {
                                                continue
                                        }
                                        scheme := proto.Scheme
                                        if scheme == "" {
                                                scheme = "https"
                                        }
                                        out = append(out, ConnectCandidate{
                                                Hostname:    proto.Host,
                                                Port:        proto.Port,
                                                Scheme:      scheme,
                                                CityCode:    city.Code,
                                                CountryCode: c.Code,
                                        })
                                }
                        }
                }
        }
        return out
}

// FindHost locates one host across the list (location mode "host" validation).
func FindHost(countries []Country, host string) (ConnectCandidate, bool) {
        got := ConnectCandidates(countries, "", "", host)
        if len(got) == 0 {
                return ConnectCandidate{}, false
        }
        return got[0], true
}
