// Native SurfEasy (Opera VPN) control-channel client — design:
// .ag/research/opera-reserve-design.md §1. Protocol facts are mirrored from
// two independent Go references in D:\b4x\opera (canonical Alexey71/
// opera-proxy2 v1.29.0 seclient package); deviations from upstream are
// deliberate and marked:
//
//   - Digest auth is in-house (digest.go) instead of go-http-digest-auth-client;
//   - the InsecureSkipVerify hole on the API channel is replaced by TOFU SPKI
//     pinning (pin.go, design §3);
//   - the identity persists in a slot so device registration happens at most
//     once per boot (design §7 red line #3);
//   - regions are whitelisted to EU/AS/AM (design §5; RU never participates).
package opera

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/publicsuffix"
)

// ---------------------------------------------------------------------------
// Public protocol constants (identical across every Opera client build).
// They are protocol facts, not user secrets — but design §7.6 still forbids
// logging them.
// ---------------------------------------------------------------------------

const (
	DefaultAPILogin    = "se0316"
	DefaultAPIPassword = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II"

	anonEmailLocalpartBytes       = 32
	deviceIDBytes                 = 20
	readLimit               int64 = 128 * 1024

	// DefaultOperaIdentityPath mirrors the warp/wg slot layout for OP4 wiring.
	DefaultOperaIdentityPath = "/opt/etc/b4/opera/identity.json"

	clientHardTimeout = 90 * time.Second
)

// SEEndpoints lists the v4 SurfEasy RPC endpoints.
type SEEndpoints struct {
	RegisterSubscriber     string
	SubscriberLogin        string
	RegisterDevice         string
	DeviceGeneratePassword string
	GeoList                string
	Discover               string
}

// DefaultSEEndpoints is the production endpoint set.
var DefaultSEEndpoints = SEEndpoints{
	RegisterSubscriber:     "https://api2.sec-tunnel.com/v4/register_subscriber",
	SubscriberLogin:        "https://api2.sec-tunnel.com/v4/subscriber_login",
	RegisterDevice:         "https://api2.sec-tunnel.com/v4/register_device",
	DeviceGeneratePassword: "https://api2.sec-tunnel.com/v4/device_generate_password",
	GeoList:                "https://api2.sec-tunnel.com/v4/geo_list",
	Discover:               "https://api2.sec-tunnel.com/v4/discover",
}

// SESettings carries the browser-masquerade headers (design §1.1).
type SESettings struct {
	ClientVersion   string
	ClientType      string
	DeviceName      string
	OperatingSystem string
	UserAgent       string
}

// DefaultSESettings matches the reference client byte-for-byte.
var DefaultSESettings = SESettings{
	ClientVersion:   "Stable 114.0.5282.21",
	ClientType:      "se0316",
	DeviceName:      "Opera-Browser-Client",
	OperatingSystem: "Windows",
	UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
}

// Regions served by discover (design §1.2). The whitelist is a red line:
// the reserve never participates in RU-region scenarios (§7 red line 4/OP4).
const (
	RegionEU = "EU"
	RegionAS = "AS"
	RegionAM = "AM"
)

// NormalizeRegion uppercases and validates against the megaregion whitelist.
func NormalizeRegion(region string) (string, error) {
	r := strings.ToUpper(strings.TrimSpace(region))
	switch r {
	case RegionEU, RegionAS, RegionAM:
		return r, nil
	default:
		return "", fmt.Errorf("region %q outside megaregion whitelist (EU/AS/AM)", region)
	}
}

// RegionArtifact renders the SurfEasy CVS artifact the API expects:
// requested_geo = "\"EU\",," (design §1.2 — reproduce exactly).
func RegionArtifact(region string) string {
	return fmt.Sprintf("%q,,", region)
}

// Options configures a Client; zero values fall back to defaults.
type Options struct {
	APILogin    string
	APIPassword string
	Settings    SESettings
	Endpoints   SEEndpoints
	// DialContext is the base TCP dialer (bootstrap-DNS / carrier chains
	// plug in here at OP4). Nil => plain net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Slot persists the device identity (nil disables persistence — tests).
	Slot *IdentityStore
	// Masquerade carries the anti-DPI settings for the CONTROL channel
	// (review §7.4.5): SNI discipline (the TOFU pin is SNI-independent),
	// fingerprint knobs, ALPN, resumption. Zero value = plain Go TLS with
	// suppressed SNI (historical behavior).
	Masquerade MasqueradeSettings
}

// ---------------------------------------------------------------------------
// API message shapes (mirror of reference messages.go, incl. the quirky
// return_code encoding: {"<code>": "<message>"} single-key object).
// ---------------------------------------------------------------------------

const seStatusOK int64 = 0

// APIError is a structured SurfEasy business error.
type APIError struct {
	Code    int64
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API responded with error message: code=%d, msg=%q", e.Code, e.Message)
}

// SEStatusPair decodes {"0":"OK"}-shaped return_code fields.
type SEStatusPair struct {
	Code    int64
	Message string
}

func (p *SEStatusPair) UnmarshalJSON(b []byte) error {
	var tmp map[string]string
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	if len(tmp) != 1 {
		return errors.New("ambiguous status")
	}
	var strCode, strStatus string
	for k, v := range tmp {
		strCode, strStatus = k, v
	}
	code, err := strconv.ParseInt(strCode, 10, 64)
	if err != nil {
		return err
	}
	p.Code, p.Message = code, strStatus
	return nil
}

// statusCarrier lets rpc() inspect any envelope's return_code uniformly.
type statusCarrier interface{ seStatus() *SEStatusPair }

type SERegisterSubscriberResponse struct {
	Data   json.RawMessage `json:"data"`
	Status SEStatusPair    `json:"return_code"`
}

func (r *SERegisterSubscriberResponse) seStatus() *SEStatusPair { return &r.Status }

type SESubscriberLoginResponse SERegisterSubscriberResponse

func (r *SESubscriberLoginResponse) seStatus() *SEStatusPair { return &r.Status }

type SERegisterDeviceData struct {
	ClientType     string `json:"client_type"`
	DeviceID       string `json:"device_id"`
	DevicePassword string `json:"device_password"`
}

type SERegisterDeviceResponse struct {
	Data   SERegisterDeviceData `json:"data"`
	Status SEStatusPair         `json:"return_code"`
}

func (r *SERegisterDeviceResponse) seStatus() *SEStatusPair { return &r.Status }

type SEDeviceGeneratePasswordData struct {
	DevicePassword string `json:"device_password"`
}

type SEDeviceGeneratePasswordResponse struct {
	Data   SEDeviceGeneratePasswordData `json:"data"`
	Status SEStatusPair                 `json:"return_code"`
}

func (r *SEDeviceGeneratePasswordResponse) seStatus() *SEStatusPair { return &r.Status }

type SEGeoEntry struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code"`
}

type SEGeoListResponse struct {
	Data struct {
		Geos []SEGeoEntry `json:"geos"`
	} `json:"data"`
	Status SEStatusPair `json:"return_code"`
}

func (r *SEGeoListResponse) seStatus() *SEStatusPair { return &r.Status }

type SEIPEntry struct {
	Geo   SEGeoEntry `json:"geo"`
	Host  string     `json:"host,omitempty"`
	IP    string     `json:"ip"`
	Ports []uint16   `json:"ports"`
}

// NetAddr picks ports[0] with the 443 fallback (reference semantics).
func (e SEIPEntry) NetAddr() string {
	if len(e.Ports) == 0 {
		return net.JoinHostPort(e.IP, "443")
	}
	return net.JoinHostPort(e.IP, strconv.Itoa(int(e.Ports[0])))
}

// TLSServerName resolves the CONNECT TLS name: explicit host wins, otherwise
// <geo>0.sec-tunnel.com (main.go proxyTLSServerName parity; OP2 consumes it).
func (e SEIPEntry) TLSServerName() string {
	if h := strings.TrimSpace(e.Host); h != "" {
		return h
	}
	return fmt.Sprintf("%s0.%s", strings.ToLower(e.Geo.CountryCode), "sec-tunnel.com")
}

type SEDiscoverResponse struct {
	Data struct {
		IPs []SEIPEntry `json:"ips"`
	} `json:"data"`
	Status SEStatusPair `json:"return_code"`
}

func (r *SEDiscoverResponse) seStatus() *SEStatusPair { return &r.Status }

// ---------------------------------------------------------------------------
// Cookie jar with race-clean reset (upstream swapped the client jar pointer
// under concurrent Do; we swap an inner jar behind a lock instead).
// ---------------------------------------------------------------------------

type swappableJar struct {
	mu  sync.RWMutex
	jar http.CookieJar
}

func newSwappableJar() (*swappableJar, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	return &swappableJar{jar: jar}, nil
}

func (w *swappableJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.jar.SetCookies(u, cookies)
}

func (w *swappableJar) Cookies(u *url.URL) []*http.Cookie {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.jar.Cookies(u)
}

// Reset drops all stored cookies (register/login cycle discipline).
func (w *swappableJar) Reset() error {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.jar = jar
	w.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// Client.
// ---------------------------------------------------------------------------

// Client speaks the SurfEasy control channel. All exported methods serialize
// on one mutex: registration is single-flight by design (red line #3) and
// Digest nc counters must advance monotonically.
type Client struct {
	opts   Options
	pins   *pinStore
	http   *http.Client
	digest *digestTransport
	jar    *swappableJar

	sessionCache  tls.ClientSessionCache  // §7.4.4 resumption (plain-Go stack)
	uSessionCache utls.ClientSessionCache // §7.4.4 resumption (uTLS fingerprint stack)
	h2pool        *h2Pool                 // OP-M2: per-node h2 CONNECT sessions
	mqBox         *MasqueradeBox          // OP-M4: ladder-driven dynamic masquerade

	mu          sync.Mutex
	deviceRaw   string // per-boot device_hash sent as register_device input
	email       string
	subPass     string
	deviceID    string // assigned device_id (raw, used by generate_password)
	deviceHash  string // capitalHexSHA1(device_id) — proxy login
	jwt         string // device_password JWT — proxy password
	hasIdentity bool
	created     time.Time
}

// New constructs a client with resolved defaults.
func New(opts Options) (*Client, error) {
	resolveStr := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}
	if opts.APILogin == "" {
		opts.APILogin = DefaultAPILogin
	}
	if opts.APIPassword == "" {
		opts.APIPassword = DefaultAPIPassword
	}
	opts.Endpoints = resolveEndpoints(opts.Endpoints)
	opts.Settings.ClientVersion = resolveStr(opts.Settings.ClientVersion, DefaultSESettings.ClientVersion)
	opts.Settings.ClientType = resolveStr(opts.Settings.ClientType, DefaultSESettings.ClientType)
	opts.Settings.DeviceName = resolveStr(opts.Settings.DeviceName, DefaultSESettings.DeviceName)
	opts.Settings.OperatingSystem = resolveStr(opts.Settings.OperatingSystem, DefaultSESettings.OperatingSystem)
	opts.Settings.UserAgent = resolveStr(opts.Settings.UserAgent, DefaultSESettings.UserAgent)

	deviceRaw, err := randomCapitalHexString(deviceIDBytes)
	if err != nil {
		return nil, err
	}
	jar, err := newSwappableJar()
	if err != nil {
		return nil, err
	}
	pins := newPinStore(nil)
	sessionCache := tls.NewLRUClientSessionCache(8)
	uSessionCache := utls.NewLRUClientSessionCache(8)
	mqBox := &MasqueradeBox{m: opts.Masquerade}
	transport := buildAPITransport(opts, pins, sessionCache, uSessionCache, mqBox)
	h2pool := &h2Pool{}
	digestT := newDigestTransport(opts.APILogin, opts.APIPassword, transport)
	return &Client{
		opts:          opts,
		pins:          pins,
		digest:        digestT,
		jar:           jar,
		http:          &http.Client{Transport: digestT, Jar: jar, Timeout: clientHardTimeout},
		deviceRaw:     deviceRaw,
		sessionCache:  sessionCache,
		uSessionCache: uSessionCache,
		h2pool:        h2pool,
		mqBox:         mqBox,
	}, nil
}

func resolveEndpoints(e SEEndpoints) SEEndpoints {
	fill := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}
	return SEEndpoints{
		RegisterSubscriber:     fill(e.RegisterSubscriber, DefaultSEEndpoints.RegisterSubscriber),
		SubscriberLogin:        fill(e.SubscriberLogin, DefaultSEEndpoints.SubscriberLogin),
		RegisterDevice:         fill(e.RegisterDevice, DefaultSEEndpoints.RegisterDevice),
		DeviceGeneratePassword: fill(e.DeviceGeneratePassword, DefaultSEEndpoints.DeviceGeneratePassword),
		GeoList:                fill(e.GeoList, DefaultSEEndpoints.GeoList),
		Discover:               fill(e.Discover, DefaultSEEndpoints.Discover),
	}
}

// buildAPITransport mirrors the upstream buildAPITransport tuning plus our
// TOFU-pinned TLS layer. SNI discipline follows the masquerade settings
// (review §7.4.5): the REAL api host name by default — the TOFU SPKI pin
// is host-keyed and SNI-INDEPENDENT, so a pool name is equally safe;
// suppression stays an explicit ladder rung. Fingerprint knobs and session
// resumption match the data plane (one browser-shaped client, not two).
func buildAPITransport(opts Options, pins *pinStore, sessionCache tls.ClientSessionCache, uSessionCache utls.ClientSessionCache, mqBox *MasqueradeBox) *http.Transport {
	dialCtx := opts.DialContext
	if dialCtx == nil {
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		dialCtx = d.DialContext
	}
	return &http.Transport{
		DialContext:           dialCtx,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialCtx(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			mq := mqBox.Get()
			sni := mq.EffectiveAPISNI(host)
			// Fingerprint layer (review OP-M1, §7.4.5): the control channel
			// uses the same Chrome ClientHello; the TOFU pin is host-keyed
			// and SNI-independent, so the trust model does not move.
			if mq.FingerprintActive() {
				verify := func(cs utls.ConnectionState) error {
					return pins.verify(host, cs.PeerCertificates)
				}
				uconn, uerr := dialUTLSClient(ctx, raw, sni, mq, uSessionCache, verify)
				if uerr != nil {
					_ = raw.Close()
					return nil, uerr
				}
				return uconn, nil
			}
			cfg := &tls.Config{
				// Self-signed upstream cert (design §3): standard verification
				// is impossible; channel integrity comes exclusively from the
				// TOFU SPKI pin checked below, fail-closed on mismatch. The
				// pin is keyed by HOST — SNI masquerading cannot weaken it.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				ServerName:         sni,
				VerifyConnection: func(cs tls.ConnectionState) error {
					return pins.verify(host, cs.PeerCertificates)
				},
			}
			mq.applyMasquerade(cfg, sessionCache)
			conn := tls.Client(raw, cfg)
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
}

// ---------------------------------------------------------------------------
// Lifecycle: EnsureSession -> RefreshCredentials (OP3 owns the 4h cadence).
// ---------------------------------------------------------------------------

// EnsureSession adopts a persisted identity when present (at most one device
// registration per boot — design red line #3) or performs the full anonymous
// registration flow: register_subscriber -> register_device.
func (c *Client) EnsureSession(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasIdentity && c.opts.Slot != nil {
		id, err := c.opts.Slot.Load()
		switch {
		case err == nil:
			c.adoptLocked(id)
		case errors.Is(err, ErrIdentityAbsent):
			// fresh boot — register below
		default:
			// corrupt/tampered slot already quarantined by Load; recover by
			// registering a fresh anonymous device instead of wedging.
		}
	}
	if !c.hasIdentity {
		return c.registerNewLocked(ctx)
	}
	return nil
}

// RegisterNew forces a fresh anonymous device registration, replacing any
// adopted identity. Health-layer recovery path (OP3): the supervisor calls
// it under its restart cap when the server rejected stored credentials.
func (c *Client) RegisterNew(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registerNewLocked(ctx)
}

// RefreshCredentials runs subscriber_login + device_generate_password and
// rotates the data-plane JWT without touching established connections.
func (c *Client) RefreshCredentials(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasIdentity {
		return fmt.Errorf("%w: no session (call EnsureSession first)", ErrIdentityInvalid)
	}
	if err := c.jar.Reset(); err != nil {
		return err
	}
	loginRes := &SESubscriberLoginResponse{}
	if err := c.rpc(ctx, c.opts.Endpoints.SubscriberLogin, url.Values{
		"login":       {c.email},
		"password":    {c.subPass},
		"client_type": {c.opts.Settings.ClientType},
	}, loginRes); err != nil {
		return err
	}
	genRes := &SEDeviceGeneratePasswordResponse{}
	if err := c.rpc(ctx, c.opts.Endpoints.DeviceGeneratePassword, url.Values{
		"device_id": {c.deviceID}, // raw id, NOT the hash (reference parity)
	}, genRes); err != nil {
		return err
	}
	c.jwt = genRes.Data.DevicePassword
	return c.persistLocked(c.now())
}

// GeoList returns available geo entries for the registered device.
func (c *Client) GeoList(ctx context.Context) ([]SEGeoEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasIdentity {
		return nil, fmt.Errorf("%w: no session", ErrIdentityInvalid)
	}
	res := &SEGeoListResponse{}
	err := c.rpc(ctx, c.opts.Endpoints.GeoList, url.Values{
		"device_id": {c.deviceHash},
	}, res)
	if err != nil {
		return nil, err
	}
	return res.Data.Geos, nil
}

// Discover requests proxy nodes for a megaregion. The requested_geo CVS
// artifact is built internally; code=801 maps to ClassDiscoverRegionUnavailable.
func (c *Client) Discover(ctx context.Context, region string) ([]SEIPEntry, error) {
	r, err := NormalizeRegion(region)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasIdentity {
		return nil, fmt.Errorf("%w: no session", ErrIdentityInvalid)
	}
	res := &SEDiscoverResponse{}
	rpcErr := c.rpc(ctx, c.opts.Endpoints.Discover, url.Values{
		"serial_no":     {c.deviceHash},
		"requested_geo": {RegionArtifact(r)},
	}, res)
	var apiErr *APIError
	if errors.As(rpcErr, &apiErr) && apiErr.Code == 801 {
		return nil, newFailure(ClassDiscoverRegionUnavailable,
			fmt.Sprintf("region %s unavailable", r), apiErr)
	}
	if rpcErr != nil {
		return nil, rpcErr
	}
	return res.Data.IPs, nil
}

// ProxyCredentials returns the data-plane Basic-auth pair:
// login = capital-hex SHA1(device_id), password = device JWT (design §1.1).
func (c *Client) ProxyCredentials() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deviceHash, c.jwt
}

// Snapshot returns a deep-enough copy of the current identity for inspection
// (use Redacted() before exposing anywhere log-shaped).
func (c *Client) Snapshot() (*Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.identityLocked(c.now())
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}

// Close releases idle pooled connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// ---------------------------------------------------------------------------
// Internals (caller holds c.mu).
// ---------------------------------------------------------------------------

func (c *Client) now() time.Time { return time.Now().UTC() }

func (c *Client) adoptLocked(id *Identity) {
	c.email = id.SubscriberEmail
	c.subPass = id.SubscriberPassword
	c.deviceID = id.DeviceID
	c.deviceHash = id.DeviceIDHash
	c.jwt = id.DevicePassword
	c.created = id.CreatedAt
	c.hasIdentity = true
	c.pins.load(id.Pins)
}

func (c *Client) registerNewLocked(ctx context.Context) error {
	if err := c.jar.Reset(); err != nil {
		return err
	}
	// Review L4: every FRESH registration draws a NEW device_hash. Reusing
	// the per-boot value made a recovery re-registration semantically
	// identical to the old device (the server could answer with the same
	// device_id, defeating the point of the recovery).
	deviceRaw, err := randomCapitalHexString(deviceIDBytes)
	if err != nil {
		return err
	}
	c.deviceRaw = deviceRaw
	localPart, err := randomEmailLocalPart(anonEmailLocalpartBytes)
	if err != nil {
		return err
	}
	c.email = fmt.Sprintf("%s@%s.best.vpn", localPart, c.opts.Settings.ClientType)
	c.subPass = capitalHexSHA1(c.email)

	regRes := &SERegisterSubscriberResponse{}
	if err := c.rpc(ctx, c.opts.Endpoints.RegisterSubscriber, url.Values{
		"email":    {c.email},
		"password": {c.subPass},
	}, regRes); err != nil {
		return err
	}

	devRes := &SERegisterDeviceResponse{}
	if err := c.rpc(ctx, c.opts.Endpoints.RegisterDevice, url.Values{
		"client_type": {c.opts.Settings.ClientType},
		"device_hash": {c.deviceRaw},
		"device_name": {c.opts.Settings.DeviceName},
	}, devRes); err != nil {
		return err
	}

	c.deviceID = devRes.Data.DeviceID
	c.jwt = devRes.Data.DevicePassword
	c.deviceHash = capitalHexSHA1(devRes.Data.DeviceID)
	c.created = c.now()
	c.hasIdentity = true
	return c.persistLocked(c.created)
}

func (c *Client) identityLocked(updated time.Time) *Identity {
	pins := c.pins.snapshot()
	if len(pins) == 0 {
		pins = nil
	}
	return &Identity{
		Format:             identityFormatVersion,
		SubscriberEmail:    c.email,
		SubscriberPassword: c.subPass,
		DeviceID:           c.deviceID,
		DeviceIDHash:       c.deviceHash,
		DevicePassword:     c.jwt,
		Pins:               pins,
		CreatedAt:          c.created,
		UpdatedAt:          updated,
	}
}

// persistLocked saves the slot when configured. Called after registration,
// JWT rotation, and TOFU pin commits.
func (c *Client) persistLocked(updated time.Time) error {
	if c.opts.Slot == nil || !c.hasIdentity {
		return nil
	}
	return c.opts.Slot.Save(c.identityLocked(updated))
}

// rpc executes one authenticated POST and decodes the envelope. The TOFU pin
// commit happens right after a successful decode: a parseable SurfEasy reply
// through this TLS channel proves the pending fingerprint genuine.
func (c *Client) rpc(ctx context.Context, endpoint string, params url.Values, res any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	h := req.Header
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Accept", "application/json")
	h.Set("SE-Client-Version", c.opts.Settings.ClientVersion)
	h.Set("SE-Operating-System", c.opts.Settings.OperatingSystem)
	h.Set("User-Agent", c.opts.Settings.UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		// ClassAPIPinMismatch surfaces from inside the handshake here.
		return err
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		drainResp(resp, readLimit)
		return newFailure(ClassAPIThrottled, "surfeasy api rate limit", nil)
	case http.StatusUnauthorized:
		drainResp(resp, readLimit)
		return newFailure(ClassAPIAuthRefused, "digest credentials rejected", nil)
	case http.StatusOK:
		// continue
	default:
		serr := fmt.Errorf("bad http status: %s", resp.Status)
		drainResp(resp, readLimit)
		return serr
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, readLimit)).Decode(res); err != nil {
		drainResp(resp, readLimit)
		return fmt.Errorf("decode surfeasy reply: %w", err)
	}
	drainResp(resp, readLimit)

	if u, uerr := url.Parse(endpoint); uerr == nil {
		if c.pins.commit(u.Hostname()) && c.hasIdentity && c.opts.Slot != nil {
			if perr := c.persistLocked(c.now()); perr != nil {
				return fmt.Errorf("persist identity after pin commit: %w", perr)
			}
		}
	}
	if carrier, ok := res.(statusCarrier); ok {
		st := carrier.seStatus()
		if st.Code != seStatusOK {
			return &APIError{Code: st.Code, Message: st.Message}
		}
	}
	return nil
}

func drainResp(resp *http.Response, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	_ = resp.Body.Close()
}

// ---------------------------------------------------------------------------
// Random helpers (reference randutils.go parity, crypto/rand direct).
// ---------------------------------------------------------------------------

func randomEmailLocalPart(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func randomCapitalHexString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}
