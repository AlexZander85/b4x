package fxvpn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- fake Guardian stand ----------------------------------------------------

type guardianStand struct {
	srv *httptest.Server
	cp  *ControlPlane
	g   *Guardian

	tokenReqs int
	lastUA    string
}

func newGuardianStand(t *testing.T, tokenStatus int, tokenBody string, extraHeaders map[string]string) *guardianStand {
	t.Helper()
	st := &guardianStand{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		st.tokenReqs++
		st.lastUA = r.UserAgent()
		if r.Header.Get("Authorization") != "Bearer access-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(tokenStatus)
		_, _ = io.WriteString(w, tokenBody)
	})
	mux.HandleFunc("/api/v1/fpn/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"subscribed":true,"uid":42,"maxBytes":"53687091200","limited_bandwidth":true}`)
	})
	mux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"subscribed":true,"uid":42,"maxBytes":"53687091200"}`)
	})

	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)

	st.cp = newTestCP(t, "")
	st.cp.EP.Guardian = st.srv.URL
	st.g = &Guardian{CP: st.cp}
	return st
}

func TestGuardianFetchProxyPassHappy(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute).Unix()
	jwt := makeJWT(t, ProxyPassClaims{Sub: "sub-1", Aud: "fpn", Iat: time.Now().Unix(), Nbf: time.Now().Add(-time.Second).Unix(), Exp: exp, Iss: "https://guardian"})
	st := newGuardianStand(t, http.StatusOK, `{"token":"`+jwt+`"}`, map[string]string{
		quotaHeaderMax:   "53687091200",
		quotaHeaderLeft:  "10737418240",
		quotaHeaderReset: "2026-09-01T00:00:00Z",
	})

	info, err := st.g.FetchProxyPass(context.Background(), "access-1")
	if err != nil {
		t.Fatalf("FetchProxyPass: %v", err)
	}
	if info.RawToken != jwt || info.Claims.Sub != "sub-1" || info.Claims.Exp != exp {
		t.Fatalf("claims mismatch: %+v", info.Claims)
	}
	if info.QuotaMax != "53687091200" || info.QuotaLeft != "10737418240" || info.QuotaReset != "2026-09-01T00:00:00Z" {
		t.Fatalf("quota headers not captured: %+v", info)
	}
	if !strings.HasPrefix(info.BearerToken(), "Bearer ") {
		t.Fatal("BearerToken malformed")
	}
	if st.lastUA != mozillaVPNUserAgent {
		t.Fatalf("UA = %q, want %q", st.lastUA, mozillaVPNUserAgent)
	}
	if got := info.ExpiresAt(); absDuration(time.Until(got)-30*time.Minute) > 5*time.Second {
		t.Fatalf("ExpiresAt off: %v", got)
	}
}

func TestGuardianQuota429WithRetryAfter(t *testing.T) {
	st := newGuardianStand(t, http.StatusTooManyRequests, `{"code":429}`, map[string]string{retryAfterHeader: "120"})
	_, err := st.g.FetchProxyPass(context.Background(), "access-1")
	var qe *QuotaError
	if !errors.As(err, &qe) {
		t.Fatalf("want QuotaError, got %v", err)
	}
	if !qe.HasRetryAfter || qe.RetryAfter != 2*time.Minute {
		t.Fatalf("retry-after not parsed: %+v", qe)
	}
	if Classify(err) != ClassQuotaExhausted {
		t.Fatalf("class = %q", Classify(err))
	}

	// Date form and absence form.
	st2 := newGuardianStand(t, http.StatusTooManyRequests, `x`, map[string]string{
		retryAfterHeader: time.Now().Add(45 * time.Second).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"),
	})
	if _, err := st2.g.FetchProxyPass(context.Background(), "access-1"); err == nil {
		t.Fatal("expected quota error (date form)")
	}
	st3 := newGuardianStand(t, http.StatusTooManyRequests, `x`, nil)
	if _, err := st3.g.FetchProxyPass(context.Background(), "access-1"); err == nil {
		t.Fatal("expected quota error (no header)")
	} else {
		var q3 *QuotaError
		if !errors.As(err, &q3) || q3.HasRetryAfter {
			t.Fatalf("absence must keep HasRetryAfter=false: %+v", q3)
		}
	}
}

func TestGuardianAuthRejected401And403(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		st := newGuardianStand(t, status, `{"code":"no-subscription"}`, nil)
		_, err := st.g.FetchProxyPass(context.Background(), "access-1")
		var ti *TokenInvalidError
		if !errors.As(err, &ti) {
			t.Fatalf("status %d: want TokenInvalidError, got %v", status, err)
		}
		if ti.Status != status || Classify(err) != ClassAuthRejected {
			t.Fatalf("status %d classification failed", status)
		}
	}
}

func TestGuardianOtherStatusesAndBadPayloads(t *testing.T) {
	st := newGuardianStand(t, http.StatusInternalServerError, `boom`, nil)
	if _, err := st.g.FetchProxyPass(context.Background(), "access-1"); err == nil || Classify(err) != "" {
		t.Fatalf("500 should stay unclassified GuardianHTTPError, got %v", err)
	}

	st2 := newGuardianStand(t, http.StatusOK, `{"token":""}`, nil)
	if _, err := st2.g.FetchProxyPass(context.Background(), "access-1"); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("empty token: %v", err)
	}

	st3 := newGuardianStand(t, http.StatusOK, `{"token":"garbage"}`, nil)
	if _, err := st3.g.FetchProxyPass(context.Background(), "access-1"); err == nil || !strings.Contains(err.Error(), "JWT") {
		t.Fatalf("malformed JWT: %v", err)
	}
}

func TestGuardianWrongBearerIs401NotClassifiedQuota(t *testing.T) {
	// The stand itself answers 401 when the bearer mismatches; this pins
	// that our client actually sends the header we asked for.
	st := newGuardianStand(t, http.StatusOK, "{}", nil)
	_, err := st.g.FetchProxyPass(context.Background(), "wrong-token")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("bearer mismatch should surface as token-invalid, got %v", err)
	}
}

func TestGuardianStatusAndActivate(t *testing.T) {
	st := newGuardianStand(t, http.StatusOK, `{}`, nil)

	ent, err := st.g.FetchUserInfo(context.Background(), "access-1")
	if err != nil || !ent.Subscribed || ent.UID != 42 || ent.MaxBytes != "53687091200" || !ent.LimitedBandwidth {
		t.Fatalf("status: %+v err=%v", ent, err)
	}

	ent2, err := st.g.Activate(context.Background(), "access-1")
	if err != nil || !ent2.Subscribed {
		t.Fatalf("activate: %+v err=%v", ent2, err)
	}
}

// ---- fake FxA stand (login/oauth/refresh/verify) ------------------------------

type fxaStand struct {
	srv *httptest.Server
	cp  *ControlPlane
	fxa *FXA

	loginBodies []map[string]interface{}
	oauthBodies []map[string]interface{}
	verifyAuth  []string
}

func newFxAStand(t *testing.T) *fxaStand {
	t.Helper()
	st := &fxaStand{}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/account/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		st.loginBodies = append(st.loginBodies, body)

		if body["authPW"] == "" || len(body["authPW"].(string)) != 64 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errno":103,"message":"Incorrect email or password"}`)
			return
		}
		if vm, _ := body["verificationMethod"].(string); vm != "" && vm != verificationMethodEmail2FA {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errno":107,"message":"Invalid parameter"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sessionToken":"736573732d746f6b2d313233","uid":"uid-7","verified":false,"authAt":1756000000,"verificationMethod":"email-2fa","verificationReason":"login"}`)
	})

	mux.HandleFunc("/v1/session/verify_code", func(w http.ResponseWriter, r *http.Request) {
		st.verifyAuth = append(st.verifyAuth, r.Header.Get("Authorization"))
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body["code"] != "654321" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errno":105,"message":"Invalid verification code"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	})

	mux.HandleFunc("/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		st.oauthBodies = append(st.oauthBodies, body)

		if gt, _ := body["grant_type"].(string); gt == "fxa-credentials" && r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"access_token": "at-new",
			"expires_in":   1209600,
			"scope":        oauthScope,
			"token_type":   "bearer",
		}
		if rt, ok := body["refresh_token"]; ok {
			resp["refresh_token"] = rt // echo old on refresh
		} else {
			resp["refresh_token"] = "rt-fresh"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)

	st.cp = newTestCP(t, "")
	st.cp.EP.FxAAPI = st.srv.URL + "/v1"
	st.fxa = &FXA{CP: st.cp}
	return st
}

func TestFxaLoginHappyWithVerificationPreference(t *testing.T) {
	st := newFxAStand(t)

	resp, err := st.fxa.Login(context.Background(), "user@example.com", "hunter2")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.SessionToken != "736573732d746f6b2d313233" || resp.UID != "uid-7" || resp.Verified {
		t.Fatalf("login response mismatch: %+v", resp)
	}
	if len(st.loginBodies) != 1 {
		t.Fatalf("login attempts = %d", len(st.loginBodies))
	}
	body := st.loginBodies[0]
	if body["email"] != "user@example.com" {
		t.Fatalf("email = %v", body["email"])
	}
	if vm, _ := body["verificationMethod"].(string); vm != verificationMethodEmail2FA {
		t.Fatalf("verificationMethod = %v, want email-2fa", vm)
	}
	if pw, ok := body["password"]; ok || pw != nil {
		t.Fatalf("raw password leaked into login body: %v", pw)
	}
}

func TestFxaLoginErrno107FallbackDropsVerificationMethod(t *testing.T) {
	// The real fallback path: a deployment answering errno 107 for the
	// email-2fa preference gets one plain retry (fxa.go:48-52, 207-217).
	st := newFxAStand107(t)
	resp, err := st.fxa.Login(context.Background(), "user@example.com", "pw")
	if err != nil {
		t.Fatalf("fallback login: %v", err)
	}
	if len(st.loginBodies) != 2 {
		t.Fatalf("attempts = %d, want 2 (email-2fa then plain)", len(st.loginBodies))
	}
	if vm, _ := st.loginBodies[0]["verificationMethod"].(string); vm != verificationMethodEmail2FA {
		t.Fatal("first attempt lost email-2fa")
	}
	if vm, present := st.loginBodies[1]["verificationMethod"]; present {
		t.Fatalf("second attempt still has verificationMethod=%v", vm)
	}
	if resp.SessionToken == "" {
		t.Fatal("fallback returned empty session")
	}

	// Unit-level: plain loginAttempt never carries verificationMethod.
	happy := newFxAStand(t)
	if _, err := happy.fxa.loginAttempt(context.Background(), "user@example.com", "hunter2", ""); err != nil {
		t.Fatalf("plain attempt: %v", err)
	}
	if vm, present := happy.loginBodies[0]["verificationMethod"]; present {
		t.Fatalf("plain attempt carried verificationMethod=%v", vm)
	}
}

// fxaStand variant whose first login (with any verificationMethod) fails
// with errno 107 — the documented deployment shape from fxa.go:48-52.
func newFxAStand107(t *testing.T) *fxaStand {
	t.Helper()
	st := &fxaStand{}
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/account/login", func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		st.loginBodies = append(st.loginBodies, body)
		if calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errno":107,"message":"Invalid parameter in request body"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sessionToken":"sess-after-fallback","uid":"uid-7","verified":true}`)
	})
	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)
	st.cp = newTestCP(t, "")
	st.cp.EP.FxAAPI = st.srv.URL + "/v1"
	st.fxa = &FXA{CP: st.cp}
	return st
}

func TestFxaVerifyCodeSendsHawkAndCode(t *testing.T) {
	st := newFxAStand(t)
	if err := st.fxa.VerifySession(context.Background(), "deadbeefcafe", "654321"); err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if len(st.verifyAuth) != 1 || !strings.HasPrefix(st.verifyAuth[0], `Hawk id="`) {
		t.Fatalf("hawk header missing/malformed: %q", st.verifyAuth)
	}

	err := st.fxa.VerifySession(context.Background(), "deadbeefcafe", "000000")
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("bad code must surface verification failure, got %v", err)
	}
}

func TestFxaOAuthAndRefreshKeepsOldRefresh(t *testing.T) {
	st := newFxAStand(t)

	tok, err := st.fxa.OAuthToken(context.Background(), "736573732d746f6b2d313233")
	if err != nil {
		t.Fatalf("OAuthToken: %v", err)
	}
	ob := st.oauthBodies[len(st.oauthBodies)-1]
	if ob["client_id"] != firefoxClientID || ob["grant_type"] != "fxa-credentials" || ob["access_type"] != "offline" {
		t.Fatalf("oauth body mismatch: %+v", ob)
	}
	if tok.RefreshToken != "rt-fresh" || tok.AccessToken != "at-new" {
		t.Fatalf("token response mismatch: %+v", tok)
	}

	// Refresh WITHOUT a new refresh_token in response keeps the old one
	// (fxa.go:388-391).
	rt := newFxAStandNoNewRT(t)
	tok2, err := rt.fxa.RefreshToken(context.Background(), "rt-old")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if tok2.AccessToken != "at-new" || tok2.RefreshToken != "rt-old" {
		t.Fatalf("refresh kept-token contract broken: %+v", tok2)
	}
	rb := rt.oauthBodies[0]
	if rb["grant_type"] != "refresh_token" || rb["refresh_token"] != "rt-old" || rb["client_id"] != firefoxClientID {
		t.Fatalf("refresh body mismatch: %+v", rb)
	}
}

func newFxAStandNoNewRT(t *testing.T) *fxaStand {
	t.Helper()
	st := &fxaStand{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		st.oauthBodies = append(st.oauthBodies, body)
		_, _ = io.WriteString(w, `{"access_token":"at-new","expires_in":1209600,"token_type":"bearer"}`) // NO refresh_token
	})
	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)
	st.cp = newTestCP(t, "")
	st.cp.EP.FxAAPI = st.srv.URL + "/v1"
	st.fxa = &FXA{CP: st.cp}
	return st
}

func TestDeriveAuthPWKnownShape(t *testing.T) {
	pw, err := deriveAuthPW("user@example.com", "hunter2")
	if err != nil {
		t.Fatalf("deriveAuthPW: %v", err)
	}
	if len(pw) != 32 {
		t.Fatalf("authPW length = %d, want 32", len(pw))
	}
	pw2, _ := deriveAuthPW("user@example.com", "hunter2")
	if string(pw) != string(pw2) {
		t.Fatal("authPW derivation not deterministic")
	}
	pw3, _ := deriveAuthPW("other@example.com", "hunter2")
	if string(pw) == string(pw3) {
		t.Fatal("salt must depend on email")
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
