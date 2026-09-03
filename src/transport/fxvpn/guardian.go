// Guardian API client (vpn.mozilla.org /api/v1/fpn/*): proxy-pass JWT mint,
// entitlement status, activation. Protocol facts from the working reference
// guardian.go (file:line noted). JWT claims are parsed WITHOUT signature
// verification by design — transport authenticity comes from TOFU SPKI
// pinning, not from a JWT whose key we do not know.
package fxvpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const GuardianEndpointDefault = "https://vpn.mozilla.org"

// Proxy pass claim-time heuristics (guardian.go:18-20).
const (
	proxyPassClaimTimeTolerance = time.Minute
	proxyPassClaimTimeMaxFuture = 2 * time.Hour

	quotaHeaderMax   = "X-Quota-Limit"
	quotaHeaderLeft  = "X-Quota-Remaining"
	quotaHeaderReset = "X-Quota-Reset"
	retryAfterHeader = "Retry-After"
)

type ProxyPassClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

type ProxyPassInfo struct {
	RawToken        string
	Claims          ProxyPassClaims
	QuotaMax        string
	QuotaLeft       string
	QuotaReset      string
	claimTimeOffset time.Duration
}

func (p *ProxyPassInfo) NotBefore() time.Time { return p.claimTime(p.Claims.Nbf) }
func (p *ProxyPassInfo) ExpiresAt() time.Time { return p.claimTime(p.Claims.Exp) }

func (p *ProxyPassInfo) claimTime(sec int64) time.Time {
	return time.Unix(sec, 0).Add(p.claimTimeOffset)
}

// ClaimTimeCorrection exposes the detected server-clock offset.
func (p *ProxyPassInfo) ClaimTimeCorrection() time.Duration { return p.claimTimeOffset }

// BearerToken returns the Authorization header value for the data plane.
func (p *ProxyPassInfo) BearerToken() string { return "Bearer " + p.RawToken }

type Entitlement struct {
	Subscribed       bool   `json:"subscribed"`
	UID              int    `json:"uid"`
	MaxBytes         string `json:"maxBytes"`
	LimitedBandwidth bool   `json:"limited_bandwidth"`
}

type proxyPassResponse struct {
	Token string `json:"token"`
}

// Guardian is the client bound to one ControlPlane.
type Guardian struct {
	CP *ControlPlane
}

func guardianURL(cp *ControlPlane, path string) string {
	base := cp.EP.Guardian
	if base == "" {
		base = GuardianEndpointDefault
	}
	return strings.TrimRight(base, "/") + path
}

// FetchProxyPass GETs /api/v1/fpn/token and classifies 429 (quota,
// Retry-After honored next to X-Quota-*) and 401/403 (token invalid).
func (g *Guardian) FetchProxyPass(ctx context.Context, accessToken string) (*ProxyPassInfo, error) {
	url := guardianURL(g.CP, "/api/v1/fpn/token")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaHeaders(req)

	resp, err := g.CP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: guardian request failed: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		qe := &QuotaError{Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
		if ra, ok := parseRetryAfter(resp.Header.Get(retryAfterHeader)); ok {
			qe.RetryAfter = ra
			qe.HasRetryAfter = true
		}
		return nil, qe
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &TokenInvalidError{Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
	case resp.StatusCode != http.StatusOK:
		return nil, &GuardianHTTPError{Operation: "guardian", Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("fxvpn: reading guardian response: %w", err)
	}

	var passResp proxyPassResponse
	if err := json.Unmarshal(body, &passResp); err != nil {
		return nil, fmt.Errorf("fxvpn: parsing proxy pass response: %w", err)
	}
	if passResp.Token == "" {
		return nil, fmt.Errorf("fxvpn: empty token in guardian response")
	}

	claims, err := ParseJWTClaims(passResp.Token)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: parsing JWT claims: %w", err)
	}

	info := &ProxyPassInfo{
		RawToken:        passResp.Token,
		Claims:          *claims,
		QuotaMax:        resp.Header.Get(quotaHeaderMax),
		QuotaLeft:       resp.Header.Get(quotaHeaderLeft),
		QuotaReset:      resp.Header.Get(quotaHeaderReset),
		claimTimeOffset: DetectProxyPassClaimTimeOffset(*claims, time.Now()),
	}
	return info, nil
}

// FetchUserInfo GETs /api/v1/fpn/status (entitlement probe).
func (g *Guardian) FetchUserInfo(ctx context.Context, accessToken string) (*Entitlement, error) {
	url := guardianURL(g.CP, "/api/v1/fpn/status")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaHeaders(req)

	resp, err := g.CP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: guardian user info request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{Operation: "guardian user info", Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return nil, err
	}
	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return nil, fmt.Errorf("fxvpn: parsing entitlement: %w", err)
	}
	return &ent, nil
}

// Activate POSTs /api/v1/fpn/activate — the refresh-path step after a token
// invalid verdict before retrying FetchProxyPass.
func (g *Guardian) Activate(ctx context.Context, accessToken string) (*Entitlement, error) {
	url := guardianURL(g.CP, "/api/v1/fpn/activate")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaHeaders(req)

	resp, err := g.CP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: guardian activate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{Operation: "guardian activate", Status: resp.StatusCode, Body: truncateForLog(readErrBody(resp))}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return nil, err
	}
	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return nil, fmt.Errorf("fxvpn: parsing activation entitlement: %w", err)
	}
	return &ent, nil
}

// ParseJWTClaims decodes the unpadded-base64url JWT payload. Signature is
// NOT verified (pinning replaces it); malformed tokens are hard errors.
func ParseJWTClaims(token string) (*ProxyPassClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	var claims ProxyPassClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims JSON: %w", err)
	}
	return &claims, nil
}

// parseRetryAfter understands delta-seconds and HTTP-date forms; absence or
// garbage yields (0,false) — callers then fall back to their own backoff.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// DetectProxyPassClaimTimeOffset repairs skewed server clocks in the JWT
// claims (guardian.go:146-196): if now sits outside [start-tol, exp+tol],
// candidate offsets (local TZ delta plus a 15-minute grid -12h..+14h) are
// tried against both window edges; no match keeps offset zero.
func DetectProxyPassClaimTimeOffset(claims ProxyPassClaims, now time.Time) time.Duration {
	if claims.Exp == 0 {
		return 0
	}

	rawExp := time.Unix(claims.Exp, 0)
	rawStart, hasStart := proxyPassClaimStartTime(claims)
	if hasStart {
		if !rawStart.Before(rawExp) {
			return 0
		}
		if withinTimeWindow(now, rawStart.Add(-proxyPassClaimTimeTolerance), rawExp.Add(proxyPassClaimTimeTolerance)) {
			return 0
		}
	} else if proxyPassExpirationLooksFresh(now, rawExp) {
		return 0
	}

	for _, offset := range proxyPassClaimTimeOffsetCandidates(now) {
		shiftedExp := rawExp.Add(offset)
		if hasStart {
			shiftedStart := rawStart.Add(offset)
			if withinTimeWindow(now, shiftedStart.Add(-proxyPassClaimTimeTolerance), shiftedExp.Add(proxyPassClaimTimeTolerance)) {
				return offset
			}
		} else if proxyPassExpirationLooksFresh(now, shiftedExp) {
			return offset
		}
	}
	return 0
}

func proxyPassClaimTimeOffsetCandidates(now time.Time) []time.Duration {
	seen := make(map[time.Duration]bool)
	candidates := make([]time.Duration, 0, 107)
	add := func(offset time.Duration) {
		if offset == 0 || seen[offset] {
			return
		}
		seen[offset] = true
		candidates = append(candidates, offset)
	}

	_, offsetSeconds := now.Zone()
	add(time.Duration(offsetSeconds) * time.Second)

	for minutes := -12 * 60; minutes <= 14*60; minutes += 15 {
		add(time.Duration(minutes) * time.Minute)
	}
	return candidates
}

func proxyPassClaimStartTime(claims ProxyPassClaims) (time.Time, bool) {
	switch {
	case claims.Nbf > 0:
		return time.Unix(claims.Nbf, 0), true
	case claims.Iat > 0:
		return time.Unix(claims.Iat, 0), true
	default:
		return time.Time{}, false
	}
}

func proxyPassExpirationLooksFresh(now, exp time.Time) bool {
	if exp.Before(now.Add(-proxyPassClaimTimeTolerance)) {
		return false
	}
	return exp.Sub(now) <= proxyPassClaimTimeMaxFuture
}

func withinTimeWindow(t, start, end time.Time) bool {
	return !t.Before(start) && !t.After(end)
}
