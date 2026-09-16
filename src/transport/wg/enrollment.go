// Cloudflare registration API client for the WG/AWG transport (tunnels panel
// stage 2: the AWG-WARP daemon assembly).
//
// The MASQUE client (transport/warp/enrollment.go) registers a device and
// PATCHes it onto secp256r1+masque; the WG transport needs the OTHER shape —
// the classic WARP enrollment where the client-generated curve25519 public
// key is pinned by the registration POST itself (warp-reg-gw registration
// lineage):
//
//   - POST /v0a4471/reg body carries the REAL curve25519 public key (not a
//     placeholder): the WG device key is bound at creation, no PATCH step;
//   - GET /reg/{id} (Bearer) returns config.peers[0].public_key (the edge
//     curve25519 pin), config.client_id and interface.addresses — exactly
//     the fields the wg.Identity projection consumes;
//   - headers / TOS layout / error envelope / refuse-vs-throttle discipline
//     are identical to the MASQUE client (same API, same build suffix).
//
// client_id bridge: the API returns client_id as a HEX string (warp-socks /
// usque lineage), while wg.Identity stores it as base64 of its first <=3
// bytes (ReservedFromClientID contract). The bridge decodes hex, truncates
// to 3 bytes and re-encodes as base64 — the reserved routing bytes on the
// wire stay exactly the API's first three client_id bytes.
//
// Renewal honesty (documented boundary): the WG device registration has no
// expirable credential on the free tier; this client therefore exposes no
// PATCH/refresh path. Re-provisioning is the owner action "delete the
// identity file and restart" (CLI/honest note), never an automatic loop.
package transportwg

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

// Protocol constants mirror the MASQUE client (transport/warp: same API,
// same version pin — the suffix MUST equal the CF-Client-Version build).
const (
	EnrollAPIBase   = "https://api.cloudflareclient.com/v0a4471"
	enrollBuild     = "4471"
	enrollUA        = "WARP for Android"
	enrollVersion   = "a-6.35-" + enrollBuild
	enrollTOSLayout = "2006-01-02T15:04:05.000-07:00"
	enrollTimeout   = 15 * time.Second
)

// EnrollOutcome classes (structural, no message parsing) — the same
// refuse-vs-throttle taxonomy as the MASQUE client.
type EnrollOutcome int

const (
	EnrollOK EnrollOutcome = iota
	// EnrollRefused: 401/404/410 — slot dead, reprovision allowed.
	EnrollRefused
	// EnrollThrottled: 403/429/5xx — never reprovision automatically.
	EnrollThrottled
	// EnrollNetwork: transport-level failure (after internal retries).
	EnrollNetwork
	// EnrollInvalidKey: API code 1001 InvalidPublicKey — our payload bug.
	EnrollInvalidKey
	// EnrollRequestError: any other 4xx — permanent request defect.
	EnrollRequestError
	// EnrollInvalidResponse: 2xx with a malformed body — registration is
	// rolled back, never committed to the store.
	EnrollInvalidResponse
)

// ClassifyEnrollStatus implements the refuse-vs-throttle table (MASQUE parity).
func ClassifyEnrollStatus(code int) EnrollOutcome {
	switch code {
	case http.StatusUnauthorized, http.StatusNotFound, http.StatusGone:
		return EnrollRefused
	case http.StatusForbidden, http.StatusTooManyRequests:
		return EnrollThrottled
	}
	if code >= 500 {
		return EnrollThrottled
	}
	if code >= 400 {
		return EnrollRequestError
	}
	return EnrollOK
}

// EnrollFailure carries the structured result of a failed API exchange.
type EnrollFailure struct {
	Status  int
	Outcome EnrollOutcome
	APICode int
	Message string
}

func (e *EnrollFailure) Error() string {
	return fmt.Sprintf("cloudflare wg api: status %d outcome %d code %d: %s",
		e.Status, e.Outcome, e.APICode, e.Message)
}

// EnrollClient registers WG devices over an injected transport. The HTTP
// field is the enrollment escape hatch (SNI-filtered networks route it
// through the bypass path); no live Cloudflare traffic may ever originate
// from unit tests (consent rule).
type EnrollClient struct {
	// BaseURL overrides EnrollAPIBase (tests point it at a fake server).
	BaseURL string
	// HTTP is the explicit enrollment transport; nil -> plain client.
	HTTP *http.Client
	// Retry tuning: MaxAttempts total tries per step, BackoffBase*2^n with
	// jitter, capped at BackoffCap.
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
	return &http.Client{Timeout: enrollTimeout}
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

// enrollPostBody matches the official-client registration payload (the key
// field carries the REAL client public key — the WG device pin).
type enrollPostBody struct {
	Key          string `json:"key"` // base64 raw 32-byte curve25519 public key
	InstallID    string `json:"install_id"`
	FCMToken     string `json:"fcm_token"`
	TOS          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Locale       string `json:"locale"`
}

// enrollRegResponse is the top-level POST /reg object (no wrapper).
type enrollRegResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License     string `json:"license"`
		AccountType string `json:"account_type"`
	} `json:"account"`
}

// enrollDeviceResponse is the full GET /reg/{id} object.
type enrollDeviceResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID  string            `json:"client_id"`
		Peers     []enrollPeerEntry `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

type enrollPeerEntry struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4 string `json:"v4"`
		V6 string `json:"v6"`
	} `json:"endpoint"`
}

// Enroll registers one WG device and returns the validated identity.
// Exactly one registration transaction: POST (pin the real key) -> GET
// (fetch the edge config). On any failure nothing touches local state.
func (c *EnrollClient) Enroll(ctx context.Context) (*Identity, EnrollOutcome, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, EnrollNetwork, fmt.Errorf("wg enroll: client key: %w", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	serial := make([]byte, 4)
	if _, err := rand.Read(serial); err != nil {
		return nil, EnrollNetwork, fmt.Errorf("wg enroll: fingerprint: %w", err)
	}
	postBody, err := json.Marshal(enrollPostBody{
		Key:          pubB64,
		TOS:          c.now().UTC().Format(enrollTOSLayout),
		Model:        "PC",
		SerialNumber: hex.EncodeToString(serial),
		Locale:       "en_US",
	})
	if err != nil {
		return nil, EnrollNetwork, err
	}
	var reg enrollRegResponse
	if out := c.do(ctx, http.MethodPost, "/reg", "", postBody, &reg); out.err != nil {
		return nil, out.outcome, out.err
	}
	if reg.ID == "" || reg.Token == "" {
		return nil, EnrollRequestError, fmt.Errorf("%w: registration response missing id/token (wrapper-object API?)", ErrIdentityInvalid)
	}

	var dev enrollDeviceResponse
	if out := c.do(ctx, http.MethodGet, "/reg/"+reg.ID, reg.Token, nil, &dev); out.err != nil {
		return nil, out.outcome, out.err
	}
	if len(dev.Config.Peers) == 0 || dev.Config.Peers[0].PublicKey == "" {
		return nil, EnrollRequestError, fmt.Errorf("%w: device config without peers[0].public_key", ErrIdentityInvalid)
	}
	clientID, err := bridgeClientID(dev.Config.ClientID)
	if err != nil {
		return nil, EnrollInvalidResponse, err
	}
	// Family-safe intake (MASQUE BLOCKER B-1 parity): the v4 string must be
	// a literal v4 before it enters an Identity.
	if v4, perr := netip.ParseAddr(dev.Config.Interface.Addresses.V4); perr != nil || !v4.IsValid() || !v4.Is4() {
		return nil, EnrollInvalidResponse, fmt.Errorf("%w: device config interface v4 %q", ErrIdentityInvalid, dev.Config.Interface.Addresses.V4)
	}
	ident, err := NewIdentity(privB64, dev.Config.Peers[0].PublicKey, clientID,
		dev.Config.Interface.Addresses.V4, dev.Config.Interface.Addresses.V6, true)
	if err != nil {
		return nil, EnrollRequestError, err
	}
	ident.EndpointHint = dev.Config.Peers[0].Endpoint.V4
	return ident, EnrollOK, nil
}

// bridgeClientID converts the API's hex client_id into the base64 form the
// wg.Identity store expects: first <=3 bytes, zero-filled (ReservedFromClientID
// contract; the wire reserved bytes equal the API's first three client_id bytes).
func bridgeClientID(apiClientID string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(apiClientID))
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("%w: wg enroll: client_id %q is not decodable hex", ErrIdentityInvalid, apiClientID)
	}
	if len(raw) > 3 {
		raw = raw[:3]
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// enrollDoOut is the internal step result.
type enrollDoOut struct {
	outcome EnrollOutcome
	err     error
}

// do executes one API step with transient-retry semantics (network errors
// retried with backoff+jitter; HTTP failures abort immediately — pacing
// belongs to supervisor cooldowns, not in-transaction retry storms).
func (c *EnrollClient) do(ctx context.Context, method, path, token string, body []byte, out any) enrollDoOut {
	url := strings.TrimRight(c.baseURL(), "/") + path
	attempts := c.maxAttempts()
	var last enrollDoOut
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, c.backoff(attempt-1)); err != nil {
				return enrollDoOut{EnrollNetwork, err}
			}
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return enrollDoOut{EnrollRequestError, err}
		}
		req.Header.Set("User-Agent", enrollUA)
		req.Header.Set("CF-Client-Version", enrollVersion)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			last = enrollDoOut{EnrollNetwork, err}
			continue // transient: retry with backoff
		}
		return c.consume(resp, out)
	}
	if last.err == nil {
		last.err = fmt.Errorf("wg api step %s %s exhausted %d attempts", method, path, attempts)
	}
	return last
}

func (c *EnrollClient) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return EnrollAPIBase
}

// backoff computes base*2^attempt with ±1/3 jitter, capped.
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

func (c *EnrollClient) consume(resp *http.Response, out any) enrollDoOut {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return enrollDoOut{EnrollNetwork, err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return enrollDoOut{EnrollRequestError, fmt.Errorf("%w: decode %T: %v", ErrIdentityInvalid, out, err)}
			}
		}
		return enrollDoOut{EnrollOK, nil}
	}
	fail := &EnrollFailure{
		Status:  resp.StatusCode,
		Outcome: ClassifyEnrollStatus(resp.StatusCode),
	}
	var apiErr struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &apiErr) == nil && len(apiErr.Errors) > 0 {
		fail.APICode = apiErr.Errors[0].Code
		fail.Message = apiErr.Errors[0].Message
	}
	if fail.APICode == 1001 {
		fail.Outcome = EnrollInvalidKey
	}
	return enrollDoOut{fail.Outcome, fail}
}
