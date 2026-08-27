// Cloudflare registration API client (design §5; addendum v1.2 §9).
//
// Wire contract verified against the pinned references:
//   - base path https://api.cloudflareclient.com/v0a4471/reg; the path
//     version suffix MUST equal the build suffix of CF-Client-Version
//     ("a-6.35-4471"), otherwise the edge rejects the request
//     (warp-reg-gw registration.go:40-42);
//   - headers: User-Agent "WARP for Android", CF-Client-Version as above;
//   - POST /reg body carries a throwaway curve25519 placeholder key, a
//     random serial/model/locale fingerprint and a TOS timestamp in layout
//     2006-01-02T15:04:05.000-07:00; the access token is returned ONLY by
//     this response (usque api/cloudflare.go);
//   - MASQUE is enabled exclusively through two-step PATCH: key_type
//     secp256r1 + tunnel_type masque with Bearer auth (direct POST of a
//     masque device is rejected by the API);
//   - GET /reg/{id} returns config.peers[0].public_key (endpoint pin) and
//     interface addresses;
//   - responses are TOP-LEVEL objects without a result wrapper; errors are
//     {"success":false,"errors":[{"code":N,"message":"..."}]}, known code
//     1001 = InvalidPublicKey.
//
// Refuse-vs-throttle discipline (Aether account.rs:262-273, design §5):
//   - 401/404/410 -> identity dead -> auto-reprovision allowed;
//   - 403/429/5xx -> rate limit / network -> NEVER re-register on this class
//     (burning device slots is irreversible); 429 Retry-After is honored
//     with a hard cap of 30s;
//   - transient failures (network errors, 5xx) are retried inside one
//     transaction: 900ms * 2^n with jitter ±1/3, cap 15s (Aether numbers).
//
// The transport is injected (HTTP field): production wires our bypass-path
// dialer there (design enrollment ladder), tests wire httptest. No live
// Cloudflare traffic may ever originate from unit tests (consent rule).
package transportwarp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Protocol constants (research "Сводные константы").
const (
	DefaultAPIBase     = "https://api.cloudflareclient.com/v0a4471"
	apiVersionBuild    = "4471"
	clientUA           = "WARP for Android"
	clientVersionHdr   = "a-6.35-" + apiVersionBuild
	tosLayout          = "2006-01-02T15:04:05.000-07:00"
	defaultHTTPTimeout = 15 * time.Second
	// MaxRetryAfterCaps caps the server-provided Retry-After (design §5).
	MaxRetryAfterCap = 30 * time.Second
)

// Outcome classes map HTTP/transport results onto the refuse-vs-throttle
// taxonomy. Structural codes only — no string matching on messages.
type Outcome int

const (
	OutcomeOK Outcome = iota
	// OutcomeRefused: 401/404/410 — identity dead, reprovision allowed.
	OutcomeRefused
	// OutcomeThrottled: 403/429/5xx — never reprovision automatically.
	OutcomeThrottled
	// OutcomeNetwork: transport-level failure (after internal retries).
	OutcomeNetwork
	// OutcomeInvalidKey: API code 1001 InvalidPublicKey — our payload bug.
	OutcomeInvalidKey
	// OutcomeRequestError: any other 4xx — permanent request defect.
	OutcomeRequestError
	// OutcomeInvalidResponse: the API answered 2xx but the body is malformed
	// (BLOCKER B-1): e.g. a v6/4-in-6 string in interface.addresses.v4 that
	// fails family validation. Registration is rolled back, never committed.
	OutcomeInvalidResponse
)

// ClassifyHTTPStatus implements the refuse-vs-throttle table.
func ClassifyHTTPStatus(code int) Outcome {
	switch code {
	case http.StatusUnauthorized, http.StatusNotFound, http.StatusGone:
		return OutcomeRefused
	case http.StatusForbidden, http.StatusTooManyRequests:
		return OutcomeThrottled
	}
	if code >= 500 {
		return OutcomeThrottled
	}
	if code >= 400 {
		return OutcomeRequestError
	}
	return OutcomeOK
}

// HTTPFailure carries the structured result of a failed API exchange.
type HTTPFailure struct {
	Status     int
	Outcome    Outcome
	RetryAfter time.Duration // parsed from 429, already capped
	APICode    int           // from errors[0].code when present
	Message    string
}

func (e *HTTPFailure) Error() string {
	return fmt.Sprintf("cloudflare api: status %d outcome %d code %d: %s", e.Status, e.Outcome, e.APICode, e.Message)
}

// apiErrorBody mirrors the documented error envelope.
type apiErrorBody struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// Account is the /reg/{id}/account projection used for revalidation.
type Account struct {
	ID          string `json:"id"`
	License     string `json:"license"`
	AccountType string `json:"account_type"`
}

// EnrollClient talks to the registration API over an injected transport.
type EnrollClient struct {
	// BaseURL overrides DefaultAPIBase (tests point it at a fake server).
	BaseURL string
	// HTTP is the explicit enrollment transport (proxy-env free). nil ->
	// plain client with a timeout (usque's timeout-less client criticized
	// in research).
	HTTP *http.Client
	// Retry tuning (Aether numbers): MaxAttempts total tries per step,
	// BackoffBase*2^n with jitter ±1/3 capped at BackoffCap.
	MaxAttempts int
	BackoffBase time.Duration
	BackoffCap  time.Duration
	// Sleep is called between retries; tests record instead of waiting.
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter source; nil -> global math/rand/v2.
	Jitter *mrand.Rand
	Now    func() time.Time
}

func (c *EnrollClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *EnrollClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (c *EnrollClient) maxAttempts() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return 5
}

func (c *EnrollClient) backoffBase() time.Duration {
	if c.BackoffBase > 0 {
		return c.BackoffBase
	}
	return 900 * time.Millisecond
}

func (c *EnrollClient) backoffCap() time.Duration {
	if c.BackoffCap > 0 {
		return c.BackoffCap
	}
	return 15 * time.Second
}

func (c *EnrollClient) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// backoff computes 900ms*2^attempt with ±⅓ jitter, capped.
func (c *EnrollClient) backoff(attempt int) time.Duration {
	d := time.Duration(float64(c.backoffBase()) * math.Pow(2, float64(attempt)))
	if d > c.backoffCap() {
		d = c.backoffCap()
	}
	j := 1.0 / 3.0
	f := 1 - j + 2*j*mrand.Float64()
	if c.Jitter != nil {
		f = 1 - j + 2*j*c.Jitter.Float64()
	}
	out := time.Duration(float64(d) * f)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// fingerprint is the random device fingerprint of one registration.
type fingerprint struct {
	SerialNumber string
	Model        string
	Locale       string
}

func newFingerprint() (fingerprint, error) {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return fingerprint{}, err
	}
	return fingerprint{
		SerialNumber: hex.EncodeToString(raw),
		Model:        "PC",
		Locale:       "en_US",
	}, nil
}

// placeholderKey generates the throwaway curve25519 registration key
// (base64, 32 bytes) that PATCH later replaces with our real ECDSA P-256.
func placeholderKey() (string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), nil
}

// postRegistrationBody matches the official-client registration payload.
type postRegistrationBody struct {
	Key          string `json:"key"` // curve25519 placeholder b64
	InstallID    string `json:"install_id"`
	FCMToken     string `json:"fcm_token"`
	TOS          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Locale       string `json:"locale"`
}

// patchKeyBody switches the device onto our real ECDSA key + masque.
type patchKeyBody struct {
	Key        string `json:"key"` // base64(PKIX-DER)
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
}

// registrationResponse is the top-level POST /reg object (NO wrapper).
type registrationResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License     string `json:"license"`
		AccountType string `json:"account_type"`
	} `json:"account"`
}

// deviceResponse is the full GET /reg/{id} object.
type deviceResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License     string `json:"license"`
		AccountType string `json:"account_type"`
	} `json:"account"`
	Config struct {
		ClientID  string      `json:"client_id"`
		Peers     []peerEntry `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

type peerEntry struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4 string `json:"v4"`
		V6 string `json:"v6"`
	} `json:"endpoint"`
}

// Enroll runs one full registration transaction: POST -> PATCH -> GET,
// returning a validated candidate Identity. On failure the candidate is
// discarded; nothing has touched local state at any point.
func (c *EnrollClient) Enroll(ctx context.Context) (*Identity, Outcome, error) {
	fp, err := newFingerprint()
	if err != nil {
		return nil, OutcomeNetwork, fmt.Errorf("fingerprint: %w", err)
	}
	placeholder, err := placeholderKey()
	if err != nil {
		return nil, OutcomeNetwork, fmt.Errorf("placeholder key: %w", err)
	}
	privB64, pubPKIX, err := GenerateClientKey()
	if err != nil {
		return nil, OutcomeNetwork, fmt.Errorf("client key: %w", err)
	}

	postBody, err := json.Marshal(postRegistrationBody{
		Key:          placeholder,
		TOS:          c.now().UTC().Format(tosLayout),
		Model:        fp.Model,
		SerialNumber: fp.SerialNumber,
		Locale:       fp.Locale,
	})
	if err != nil {
		return nil, OutcomeNetwork, err
	}
	var reg registrationResponse
	if out := c.do(ctx, http.MethodPost, "/reg", "", postBody, &reg); out.err != nil {
		return nil, out.outcome, out.err
	}
	if reg.ID == "" || reg.Token == "" {
		return nil, OutcomeRequestError, fmt.Errorf("%w: registration response missing id/token (wrapper-object API?)", ErrIdentityInvalid)
	}

	patchBody, err := json.Marshal(patchKeyBody{
		Key:        base64.StdEncoding.EncodeToString(pubPKIX),
		KeyType:    "secp256r1",
		TunnelType: "masque",
	})
	if err != nil {
		return nil, OutcomeNetwork, err
	}
	if out := c.do(ctx, http.MethodPatch, "/reg/"+reg.ID, reg.Token, patchBody, nil); out.err != nil {
		return nil, out.outcome, fmt.Errorf("patch %s: %w", redactID(reg.ID), out.err)
	}

	var dev deviceResponse
	if out := c.do(ctx, http.MethodGet, "/reg/"+reg.ID, reg.Token, nil, &dev); out.err != nil {
		return nil, out.outcome, fmt.Errorf("get %s: %w", redactID(reg.ID), out.err)
	}
	if len(dev.Config.Peers) == 0 || dev.Config.Peers[0].PublicKey == "" {
		return nil, OutcomeRequestError, fmt.Errorf("%w: device config without peers[0].public_key", ErrIdentityInvalid)
	}
	// BLOCKER B-1 intake (decision D1): same family-safe check as
	// Identity.Validate, applied to the raw CF API string BEFORE it is written
	// into an Identity. A v6 literal or 4-in-6 form is an anomalous response —
	// fail-closed with OutcomeInvalidResponse, the registration is rolled back.
	if v4, err := netip.ParseAddr(dev.Config.Interface.Addresses.V4); err != nil || !v4.IsValid() || !v4.Is4() {
		return nil, OutcomeInvalidResponse, fmt.Errorf("%w: device config interface v4 %q", ErrIdentityInvalid, dev.Config.Interface.Addresses.V4)
	}

	ident := &Identity{
		Format:       IdentityFormatVersion,
		ID:           reg.ID,
		Token:        reg.Token,
		AccountType:  firstNonEmpty(dev.Account.AccountType, reg.Account.AccountType),
		License:      firstNonEmpty(dev.Account.License, reg.Account.License),
		PrivateKey:   privB64,
		PinPEM:       dev.Config.Peers[0].PublicKey,
		AssignedV4:   dev.Config.Interface.Addresses.V4,
		AssignedV6:   dev.Config.Interface.Addresses.V6,
		ClientID:     dev.Config.ClientID,
		EndpointHint: dev.Config.Peers[0].Endpoint.V4,
		CreatedAt:    c.now(),
	}
	_, digest, err := ParsePublicKeyPEM(ident.PinPEM)
	if err != nil {
		return nil, OutcomeRequestError, fmt.Errorf("%w: pin parse: %v", ErrIdentityInvalid, err)
	}
	ident.PinDigest = digest
	if err := ident.Validate(); err != nil {
		return nil, OutcomeRequestError, err
	}
	return ident, OutcomeOK, nil
}

// RevalidateAccount performs GET /reg/{id}/account — the periodic identity
// liveness check (design: every start + every 24h).
func (c *EnrollClient) RevalidateAccount(ctx context.Context, id, token string) (Account, Outcome, error) {
	var acct Account
	if out := c.do(ctx, http.MethodGet, "/reg/"+id+"/account", token, nil, &acct); out.err != nil {
		return Account{}, out.outcome, out.err
	}
	return acct, OutcomeOK, nil
}

// Delete removes a device (success = 200 or 204; warp-reg-gw invariant).
// Used after committed renewals so replaced devices do not burn license
// slots (caps <=10 discipline).
func (c *EnrollClient) Delete(ctx context.Context, id, token string) error {
	out := c.do(ctx, http.MethodDelete, "/reg/"+id, token, nil, nil)
	return out.err
}

// doOut is the internal step result.
type doOut struct {
	outcome Outcome
	err     error
}

// do executes one API step with transient-retry semantics: network errors
// and 5xx are retried up to MaxAttempts with exponential backoff+jitter;
// refused/request-error outcomes abort immediately; 429 aborts honoring
// Retry-After (capped).
func (c *EnrollClient) do(ctx context.Context, method, path, token string, body []byte, out any) doOut {
	url := strings.TrimRight(c.baseURL(), "/") + path
	attempts := c.maxAttempts()
	var last doOut
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, c.backoff(attempt-1)); err != nil {
				return doOut{OutcomeNetwork, err}
			}
		}
		req, err := c.newRequest(ctx, method, url, token, body)
		if err != nil {
			return doOut{OutcomeRequestError, err}
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			last = doOut{OutcomeNetwork, err}
			continue // transient: retry with backoff
		}
		return c.consume(resp, out)
	}
	if last.err == nil {
		last.err = fmt.Errorf("api step %s %s exhausted %d attempts", method, path, attempts)
	}
	return last
}

func (c *EnrollClient) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultAPIBase
}

func (c *EnrollClient) newRequest(ctx context.Context, method, url, token string, body []byte) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("CF-Client-Version", clientVersionHdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func (c *EnrollClient) consume(resp *http.Response, out any) doOut {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return doOut{OutcomeNetwork, err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return doOut{OutcomeRequestError, fmt.Errorf("%w: decode %T: %v", ErrIdentityInvalid, out, err)}
			}
		}
		return doOut{OutcomeOK, nil}
	}

	fail := &HTTPFailure{Status: resp.StatusCode, Outcome: ClassifyHTTPStatus(resp.StatusCode)}
	var apiErr apiErrorBody
	if json.Unmarshal(raw, &apiErr) == nil && len(apiErr.Errors) > 0 {
		fail.APICode = apiErr.Errors[0].Code
		fail.Message = apiErr.Errors[0].Message
	}
	if fail.APICode == 1001 {
		fail.Outcome = OutcomeInvalidKey
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		fail.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return doOut{fail.Outcome, fail}
}

// parseRetryAfter reads seconds-form Retry-After, capped at MaxRetryAfterCap.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var sec int
	if _, err := fmt.Sscanf(v, "%d", &sec); err != nil || sec < 0 {
		return 0
	}
	d := time.Duration(sec) * time.Second
	if d > MaxRetryAfterCap {
		d = MaxRetryAfterCap
	}
	return d
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// redactID keeps trace output useful without printing full identifiers.
func redactID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// Retry semantics note: only genuine transport errors (connection refused,
// reset, timeout before a response) are retried inside one step. HTTP-level
// failures — including 5xx — abort the transaction immediately as
// throttled-class: completing an in-flight registration against a flapping
// edge must surface quickly, and pacing belongs to supervisor cooldowns,
// not to silent in-transaction retry storms.
