// Firefox Accounts client (protocol facts from the working reference
// firefox-vpn-client fxa.go, file:line noted where non-obvious):
//   - authPW = HKDF(PBKDF2-SHA256(password, "…quickStretch:"+email, 1000), info "…authPW")
//     (fxa.go:94-106); derived here with Go 1.24+ stdlib crypto/pbkdf2 and
//     crypto/hkdf instead of x/crypto — identical RFC algorithms, zero deps.
//   - session-token calls authenticate with Hawk (fxa.go:108-175).
//   - login requests verificationMethod "email-2fa" so FxA emails a code we
//     can submit programmatically; deployments answering errno 107 get a
//     plain-login fallback (fxa.go:41-52, 207-217).
package fxvpn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/hkdf"
	"crypto/pbkdf2"
)

const (
	firefoxClientID            = "5882386c6d801776"
	oauthScope                 = "profile https://identity.mozilla.com/apps/vpn"
	fxaProtocolVersion         = "identity.mozilla.com/picl/v1/"
	pbkdf2Rounds               = 1000
	stretchedPWLen             = 32
	hkdfLen                    = 32
	hawkCredLen                = 96 // id(32) + key(32) + reserved(32), fxa.go:115-119
	maxChallengeAttempts       = 5  // fxa.go:34
	fxaCallMinBudget           = 90 * time.Second
	verificationMethodEmail2FA = "email-2fa"
	fxaErrnoInvalidParameter   = 107
)

// FXA is the account client bound to one ControlPlane.
type FXA struct {
	CP *ControlPlane
}

// LoginResponse is /account/login.
type LoginResponse struct {
	SessionToken       string `json:"sessionToken"`
	UID                string `json:"uid"`
	Verified           bool   `json:"verified"`
	AuthAt             int64  `json:"authAt"`
	VerificationMethod string `json:"verificationMethod"`
	VerificationReason string `json:"verificationReason"`
}

// TokenResponse is /oauth/token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// deriveAuthPW computes the login proof (fxa.go:94-106).
func deriveAuthPW(email, password string) ([]byte, error) {
	salt := []byte(fxaProtocolVersion + "quickStretch:" + email)
	quickStretchedPW, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Rounds, stretchedPWLen)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: pbkdf2 authPW: %w", err)
	}
	out, err := hkdf.Key(sha256.New, quickStretchedPW, []byte{0x00}, fxaProtocolVersion+"authPW", hkdfLen)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: hkdf authPW: %w", err)
	}
	return out, nil
}

// deriveHawkCredentials splits an FxA token into Hawk id/key (fxa.go:108-120).
func deriveHawkCredentials(tokenHex, context string) (string, []byte, error) {
	tokenBytes, err := hex.DecodeString(tokenHex)
	if err != nil {
		return "", nil, fmt.Errorf("fxvpn: invalid token hex: %w", err)
	}
	out, err := hkdf.Key(sha256.New, tokenBytes, nil, fxaProtocolVersion+context, hawkCredLen)
	if err != nil {
		return "", nil, fmt.Errorf("fxvpn: hkdf hawk credentials: %w", err)
	}
	return hex.EncodeToString(out[:32]), out[32:64], nil
}

// hawkHeader builds the Hawk authorization header (fxa.go:122-175).
func hawkHeader(method, rawURL, hawkID string, hawkKey []byte, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("fxvpn: hawk url: %w", err)
	}
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("fxvpn: hawk nonce: %w", err)
	}
	nonceStr := hex.EncodeToString(nonce)
	ts := fmt.Sprintf("%d", time.Now().Unix())

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	var payloadHash string
	if payload != "" {
		h := sha256.New()
		h.Write([]byte("hawk.1.payload\napplication/json\n"))
		h.Write([]byte(payload))
		h.Write([]byte("\n"))
		payloadHash = hex.EncodeToString(h.Sum(nil))
	}

	normalized := strings.Join([]string{
		"hawk.1.header",
		ts,
		nonceStr,
		strings.ToUpper(method),
		u.RequestURI(),
		u.Hostname(),
		port,
		payloadHash,
		"",
		"",
	}, "\n")

	mac := hmac.New(sha256.New, hawkKey)
	mac.Write([]byte(normalized))
	macStr := hex.EncodeToString(mac.Sum(nil))

	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, hawkID, ts, nonceStr, macStr)
	if payloadHash != "" {
		header += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}
	return header, nil
}

// do issues an FxA API request, transparently solving the Fastly anti-bot
// challenge when the edge answers HTTP 406 (empty body, no FxA error
// payload; fxa.go:181-205). The factory is re-invoked after each solve
// because request bodies are single-use readers.
func (f *FXA) do(ctx context.Context, op string, newRequest func() (*http.Request, error)) (*http.Response, error) {
	ctx, cancel := minBudgetContext(ctx, fxaCallMinBudget)
	defer cancel()

	for attempt := 1; attempt <= maxChallengeAttempts; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		resp, err := f.CP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusNotAcceptable {
			return resp, nil
		}
		_ = readErrBody(resp) // drain+close; 406 bodies are empty by contract
		if serr := f.CP.SolveFastlyChallenge(ctx); serr != nil {
			return nil, fmt.Errorf("%w: solving after HTTP 406 on %s: %v", ErrChallenge, op, serr)
		}
	}
	return nil, fmt.Errorf("%w: still failing after %d attempts (HTTP 406) on %s",
		ErrChallenge, maxChallengeAttempts, op)
}

// Login performs /account/login with the email-2fa preference and the
// errno-107 plain-login fallback (fxa.go:207-260).
func (f *FXA) Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	resp, err := f.loginAttempt(ctx, email, password, verificationMethodEmail2FA)
	if err != nil {
		var apiErr *FxAError
		if errors.As(err, &apiErr) && apiErr.Errno == fxaErrnoInvalidParameter {
			return f.loginAttempt(ctx, email, password, "")
		}
		return nil, err
	}
	return resp, nil
}

func (f *FXA) loginAttempt(ctx context.Context, email, password, verificationMethod string) (*LoginResponse, error) {
	authPW, err := deriveAuthPW(email, password)
	if err != nil {
		return nil, fmt.Errorf("deriving authPW: %w", err)
	}

	body := map[string]string{
		"email":  email,
		"authPW": hex.EncodeToString(authPW),
	}
	if verificationMethod != "" {
		body["verificationMethod"] = verificationMethod
	}
	bodyJSON, _ := json.Marshal(body)

	loginURL := strings.TrimRight(f.CP.EP.FxAAPI, "/") + "/account/login"

	resp, err := f.do(ctx, "login", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, fmt.Errorf("creating login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		applyMozillaHeaders(req)
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError("login", resp.StatusCode, data)
	}

	var out LoginResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing login response: %w", err)
	}
	return &out, nil
}

// VerifySession submits the emailed confirmation code for an unverified
// session (fxa.go:265-299).
func (f *FXA) VerifySession(ctx context.Context, sessionToken, code string) error {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return fmt.Errorf("deriving hawk credentials: %w", err)
	}

	body := map[string]string{"code": code}
	bodyJSON, _ := json.Marshal(body)
	verifyURL := strings.TrimRight(f.CP.EP.FxAAPI, "/") + "/session/verify_code"

	resp, err := f.do(ctx, "verify_code", func() (*http.Request, error) {
		authHeader, err := hawkHeader("POST", verifyURL, hawkID, hawkKey, string(bodyJSON))
		if err != nil {
			return nil, fmt.Errorf("generating hawk header: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authHeader)
		applyMozillaHeaders(req)
		return req, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verification failed (HTTP %d): %s", resp.StatusCode, truncateForLog(string(data)))
	}
	return nil
}

// OAuthToken mints access+refresh tokens from a session token via
// grant_type fxa-credentials, offline access (fxa.go:301-349).
func (f *FXA) OAuthToken(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, fmt.Errorf("deriving hawk credentials: %w", err)
	}

	body := map[string]interface{}{
		"client_id":   firefoxClientID,
		"grant_type":  "fxa-credentials",
		"scope":       oauthScope,
		"access_type": "offline",
	}
	bodyJSON, _ := json.Marshal(body)

	tokenURL := strings.TrimRight(f.CP.EP.FxAAPI, "/") + "/oauth/token"

	resp, err := f.do(ctx, "oauth_token", func() (*http.Request, error) {
		authHeader, err := hawkHeader("POST", tokenURL, hawkID, hawkKey, string(bodyJSON))
		if err != nil {
			return nil, fmt.Errorf("generating hawk header: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authHeader)
		applyMozillaHeaders(req)
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError("oauth_token", resp.StatusCode, readAllLimited(resp.Body))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	var out TokenResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	return &out, nil
}

// RefreshToken rotates the access token via grant_type refresh_token. The
// response may omit a new refresh_token — keep the old one (fxa.go:388-391).
func (f *FXA) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body := map[string]interface{}{
		"client_id":     firefoxClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"scope":         oauthScope,
	}
	bodyJSON, _ := json.Marshal(body)

	tokenURL := strings.TrimRight(f.CP.EP.FxAAPI, "/") + "/oauth/token"

	resp, err := f.do(ctx, "refresh_token", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		applyMozillaHeaders(req)
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError("refresh_token", resp.StatusCode, readAllLimited(resp.Body))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}
	var out TokenResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	return &out, nil
}

func newFxaAPIError(op string, status int, body []byte) *FxAError {
	var parsed struct {
		Errno int `json:"errno"`
	}
	_ = json.Unmarshal(body, &parsed)
	return &FxAError{Operation: op, Status: status, Errno: parsed.Errno, Body: truncateForLog(string(body))}
}
