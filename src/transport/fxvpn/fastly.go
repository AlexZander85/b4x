// Fastly anti-bot challenge solver (protocol facts from firefox-vpn-client
// fastly.go, verified against its sources):
//   - an API call answered HTTP 406 means the edge demands a client
//     challenge: a /_fs-ch-* page ("Client Challenge") on the API host or
//     the accounts.firefox.com site host — the earned cookie is issued with
//     Domain=firefox.com and BOUND TO THE EXIT IP that solved it
//     (fastly.go:84-115), so the solver shares this ControlPlane's transport
//     and installs cookies into its jar. Challenge and subsequent API calls
//     therefore leave through ONE exit by construction.
//   - challenge script carries init([challenges], "token", "prefix", ...);
//     types pow (SHA256(base+2 chars of [A-Za-z0-9]) == hash, space 62^2),
//     pat (Private Access Token; 401/400 => empty auth => server-side PoW
//     fallback) and clientmetrics (benign JSON) are solvable; captcha is not.
//   - post-back rounds are capped (maxPostBackRounds); success is probed on
//     the same jar before cookies are installed (exit-IP rotation catch,
//     fastly.go:196-205).
package fxvpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	fastlySolveTimeout = 60 * time.Second
	maxPostBackRounds  = 3

	// The solver presents as a browser to the challenge edge (the Mozilla
	// UA would be odd for script.js asset fetches); reference fastly.go:35.
	fastlySolverUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

var (
	fastlyChallengePrefixRe = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
	fastlyInitCallRe        = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

	// powAlphabet mirrors the challenge script's own alphabet (fastly.go:44).
	powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	errNoChallengePage      = errors.New("host did not serve a fastly challenge page")
	errChallengeNotAccepted = errors.New("challenge cookie not accepted on this exit ip")
)

type fastlyChallenge struct {
	Ty   string          `json:"ty"`
	Data json.RawMessage `json:"data"`
}

type fastlyPowData struct {
	Base    string `json:"base"`
	Expires string `json:"expires"`
	HMAC    string `json:"hmac"`
	Hash    string `json:"hash"`
}

type fastlyPostBack struct {
	Token string        `json:"token"`
	Data  []interface{} `json:"data"`
}

type fastlyPostBackResponse struct {
	Status string            `json:"status"`
	Ch     []fastlyChallenge `json:"ch"`
	Tok    string            `json:"tok"`
}

// SolveFastlyChallenge runs the full challenge handshake through this
// ControlPlane and installs the earned cookies into its jar. Serialized per
// client: two concurrent solvers would race the jar and the exit-IP-bound
// cookie (reference uses a package-global mutex for the same reason).
func (c *ControlPlane) SolveFastlyChallenge(ctx context.Context) error {
	c.chMu <- struct{}{}
	defer func() { <-c.chMu }()

	ctx, cancel := minBudgetContext(ctx, fastlySolveTimeout)
	defer cancel()

	apiBase := strings.TrimSuffix(strings.TrimRight(c.EP.FxAAPI, "/"), "/v1")
	if apiBase == "" || !strings.HasPrefix(apiBase, "http") {
		apiBase = strings.TrimRight(c.EP.FxAAPI, "/")
	}
	bases := []string{apiBase, strings.TrimRight(c.EP.FxASite, "/")}

	var lastErr error
	for _, base := range bases {
		err := c.solveChallengeOnHost(ctx, base)
		if err == nil {
			return nil
		}
		lastErr = err
		if errors.Is(err, errNoChallengePage) {
			continue
		}
	}
	if lastErr == nil {
		lastErr = errNoChallengePage
	}
	return lastErr
}

// solveChallengeOnHost runs one host's flow with a throw-away jar sharing
// our transport. Re-solving against a jar that already holds a valid cookie
// fails (fastly serves the real page instead), hence the fresh jar.
func (c *ControlPlane) solveChallengeOnHost(ctx context.Context, base string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("fxvpn: solver jar: %w", err)
	}
	client := &http.Client{
		Transport: c.HTTP.Transport,
		Jar:       jar,
		Timeout:   fastlySolveTimeout,
	}
	pageURL := base + "/"

	page, isChallenge, err := fetchChallengePage(ctx, client, pageURL)
	if err != nil {
		return err
	}
	if !isChallenge {
		return errNoChallengePage
	}

	prefix := fastlyChallengePrefixRe.FindString(page)
	if prefix == "" {
		return fmt.Errorf("fxvpn: challenge asset prefix not found on %s", base)
	}

	script, err := fetchText(ctx, client, base+prefix+"/script.js?reload=true")
	if err != nil {
		return fmt.Errorf("fxvpn: fetching challenge script: %w", err)
	}

	challenges, token, err := parseChallengeInit(script)
	if err != nil {
		return err
	}

	for round := 0; round < maxPostBackRounds; round++ {
		answers := make([]interface{}, 0, len(challenges))
		for _, ch := range challenges {
			answer, aerr := answerChallenge(ctx, client, base+prefix, token, ch)
			if aerr != nil {
				return aerr
			}
			answers = append(answers, answer)
		}

		postBack, merr := json.Marshal(fastlyPostBack{Token: token, Data: answers})
		if merr != nil {
			return merr
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, base+prefix+"/fst-post-back", strings.NewReader(string(postBack)))
		if rerr != nil {
			return rerr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", fastlySolverUserAgent)
		req.Header.Set("Origin", baseOrigin(base+prefix))

		resp, derr := client.Do(req)
		if derr != nil {
			return fmt.Errorf("fxvpn: challenge post-back: %w", derr)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("fxvpn: challenge post-back HTTP %d: %s", resp.StatusCode, truncateForLog(string(data)))
		}

		var pbResp fastlyPostBackResponse
		if uerr := json.Unmarshal(data, &pbResp); uerr != nil {
			return fmt.Errorf("fxvpn: parsing post-back response: %w", uerr)
		}
		if pbResp.Status == "success" {
			// Probe before installing: a rotated exit IP makes the cookie
			// worthless and the probe catches it immediately (fastly.go:197-204).
			if _, stillChallenged, perr := fetchChallengePage(ctx, client, pageURL); perr != nil {
				return perr
			} else if stillChallenged {
				return errChallengeNotAccepted
			}
			return installChallengeCookies(jar, pageURL, c.Jar(), c.EP.FxAAPI+"/", c.EP.FxASite+"/")
		}
		if len(pbResp.Ch) == 0 || pbResp.Tok == "" {
			return fmt.Errorf("fxvpn: unexpected post-back response: %s", truncateForLog(string(data)))
		}
		challenges, token = pbResp.Ch, pbResp.Tok
	}
	return fmt.Errorf("fxvpn: fastly challenge did not complete within %d rounds", maxPostBackRounds)
}

// fetchChallengePage reports whether pageURL served a challenge page
// (fastly.go:217-224).
func fetchChallengePage(ctx context.Context, client *http.Client, pageURL string) (string, bool, error) {
	body, err := fetchText(ctx, client, pageURL)
	if err != nil {
		return "", false, err
	}
	isChallenge := strings.Contains(body, "/_fs-ch-") && strings.Contains(body, "Client Challenge")
	return body, isChallenge, nil
}

func fetchText(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fastlySolverUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	return string(data), nil
}

// parseChallengeInit extracts challenges+token from the LAST init(...) call
// in the script (fastly.go:251-266).
func parseChallengeInit(script string) ([]fastlyChallenge, string, error) {
	matches := fastlyInitCallRe.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 {
		return nil, "", errors.New("fxvpn: challenge init call not found in script")
	}
	m := matches[len(matches)-1]

	var challenges []fastlyChallenge
	if err := json.Unmarshal([]byte(m[1]), &challenges); err != nil {
		return nil, "", fmt.Errorf("fxvpn: parsing challenge list: %w", err)
	}
	if len(challenges) == 0 {
		return nil, "", errors.New("fxvpn: empty challenge list")
	}
	return challenges, m[2], nil
}

// answerChallenge produces the fst-post-back payload for one task
// (fastly.go:270-299). Unknown types are hard errors: a captcha cannot be
// solved automatically and pretending otherwise would loop forever.
func answerChallenge(ctx context.Context, client *http.Client, prefixURL, token string, ch fastlyChallenge) (interface{}, error) {
	switch ch.Ty {
	case "pow":
		var d fastlyPowData
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return nil, fmt.Errorf("fxvpn: parsing pow challenge: %w", err)
		}
		answer, ok := solvePow(d.Base, d.Hash)
		if !ok {
			return nil, fmt.Errorf("fxvpn: no proof-of-work solution found for base %q", d.Base)
		}
		return map[string]interface{}{
			"ty":      "pow",
			"base":    d.Base,
			"answer":  answer,
			"hmac":    d.HMAC,
			"expires": d.Expires,
		}, nil
	case "pat":
		auth, err := fetchPAT(ctx, client, prefixURL, token)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ty": "pat", "auth": auth}, nil
	case "clientmetrics":
		return clientMetricsAnswer(), nil
	default:
		return nil, fmt.Errorf("fxvpn: unsupported fastly challenge type %q (captcha cannot be solved automatically)", ch.Ty)
	}
}

// solvePow brute-forces the two-character suffix with
// SHA256(base + suffix) == targetHex. Space is 62*62 = instant.
func solvePow(base, targetHex string) (string, bool) {
	target, err := hex.DecodeString(targetHex)
	if err != nil || len(target) != sha256.Size {
		return "", false
	}
	buf := make([]byte, len(base)+2)
	copy(buf, base)
	for i := 0; i < len(powAlphabet); i++ {
		buf[len(base)] = powAlphabet[i]
		for j := 0; j < len(powAlphabet); j++ {
			buf[len(base)+1] = powAlphabet[j]
			sum := sha256.Sum256(buf)
			if bytes.Equal(sum[:], target) {
				return string(buf[len(base):]), true
			}
		}
	}
	return "", false
}

// fetchPAT requests a Private Access Token. 401/400 mean "cannot mint PAT"
// (a browser platform feature): an empty auth makes Fastly fall back to
// solvable challenges server-side (fastly.go:328-367).
func fetchPAT(ctx context.Context, client *http.Client, prefixURL, token string) (string, error) {
	patURL := prefixURL + "/pat?token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, patURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fastlySolverUserAgent)
	req.Header.Set("Origin", baseOrigin(prefixURL))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fxvpn: PAT request: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fxvpn: PAT request HTTP %d: %s", resp.StatusCode, truncateForLog(string(data)))
	}
	var out struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("fxvpn: parsing PAT response: %w", err)
	}
	if out.Auth == "" {
		return "", errors.New("fxvpn: empty PAT auth token")
	}
	return out.Auth, nil
}

// clientMetricsAnswer fabricates the benign browser-metrics payload
// (fastly.go:372-381); current Mozilla config issues only PAT/PoW.
func clientMetricsAnswer() map[string]interface{} {
	return map[string]interface{}{
		"ty":                   "clientmetrics",
		"webdriver":            false,
		"bot_detection_result": map[string]interface{}{"bot_detected": false, "bot_kind": nil},
		"browser_metrics":      map[string]interface{}{"client_data": "{}", "error_trace": nil},
		"detector_results":     map[string]interface{}{},
		"v":                    2,
	}
}

// installChallengeCookies copies the earned cookies into the control
// plane's jar for BOTH the API root and the site URL (cookie Domain=
// firefox.com covers api.accounts.firefox.com; fastly.go:387-412).
func installChallengeCookies(solverJar http.CookieJar, pageURL string, targetJar http.CookieJar, apiRoot, siteRoot string) error {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return err
	}
	cookies := solverJar.Cookies(parsed)
	if len(cookies) == 0 {
		return errors.New("fxvpn: challenge completed but no cookies were issued")
	}
	if targetJar == nil {
		return errors.New("fxvpn: control plane has no cookie jar")
	}
	apiURL, err := url.Parse(apiRoot)
	if err != nil {
		return err
	}
	targetJar.SetCookies(apiURL, cookies)
	siteURL, err := url.Parse(siteRoot)
	if err != nil {
		return err
	}
	targetJar.SetCookies(siteURL, cookies)
	return nil
}

// minBudgetContext guarantees at least d of deadline while preserving the
// parent's cancellation (reference contextWithMinDeadline, fastly.go:418-435):
// callers' shorter timeouts must not kill mid-solve flows.
func minBudgetContext(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) >= d {
		return ctx, func() {}
	}
	extended, cancel := context.WithTimeout(context.WithoutCancel(ctx), d)
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-watcherDone:
		}
	}()
	stop := func() {
		close(watcherDone)
		cancel()
	}
	return extended, stop
}

func truncateForLog(s string) string {
	const n = 512
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// readAllLimited drains a response body up to the error-body cap.
func readAllLimited(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, errorBodyLimit))
	return b
}

// baseOrigin derives the Origin header value from a "/_fs-ch-..." URL
// (fastly.go:446-451).
func baseOrigin(prefixURL string) string {
	if idx := strings.Index(prefixURL, "/_fs-ch-"); idx > 0 {
		return prefixURL[:idx]
	}
	return prefixURL
}
