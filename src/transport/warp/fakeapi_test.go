package transportwarp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI implements the registration-API contract offline (consent rule:
// zero live Cloudflare traffic). It reproduces the protocol invariants the
// client must satisfy and RECORDS violations instead of failing from a
// server goroutine:
//   - path version suffix must pair with CF-Client-Version build suffix;
//   - User-Agent "WARP for Android";
//   - Bearer token required on every device-scoped route;
//   - POST body carries a 32-byte curve25519 placeholder + fingerprint;
//   - PATCH switches key_type secp256r1 / tunnel_type masque;
//   - responses are top-level objects, errors use {success,errors[{code}]}.
type fakeAPI struct {
	t *testing.T

	mu      sync.Mutex
	devices map[string]*fakeDevice
	seq     int

	key    *ecdsa.PrivateKey
	pinPEM string

	// behavior matrix: per-call status queues consumed FIFO, then defaults.
	postStatuses    []int
	postStatusDef   int // 0 = success; else every POST fails with it
	patchStatus     int // 0 = success
	patchBody       string
	accountStatuses []int
	accountStatDef  int
	retryAfter      string
	deleteStatus    int // 0 = 204 success

	postCount, patchCount, getCount, accountCount, deleteCount int

	// assignedV4Override, when non-empty, replaces the fixed 172.16.0.2
	// interface v4 in the GET /reg/{id} response. Used by the BLOCKER B-1
	// v6-intake test to prove a malformed family yields OutcomeInvalidResponse.
	assignedV4Override string

	violations []string
}

type fakeDevice struct {
	id      string
	token   string
	patched bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, devices: map[string]*fakeDevice{}}
	privB64, pubPKIX, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	f.key = priv
	if _, err := x509.ParsePKIXPublicKey(pubPKIX); err != nil {
		t.Fatal(err)
	}
	f.pinPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX}))
	return f
}

func (f *fakeAPI) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	f.t.Cleanup(srv.Close)
	return srv
}

// violate records a protocol violation. Caller MUST hold f.mu (all routes
// run under it); taking the lock here would self-deadlock (non-reentrant).
func (f *fakeAPI) violate(format string, args ...any) {
	f.violations = append(f.violations, fmt.Sprintf(format, args...))
}

func (f *fakeAPI) counters() (post, patch, get, account, del int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.postCount, f.patchCount, f.getCount, f.accountCount, f.deleteCount
}

func (f *fakeAPI) failedProtocol() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.violations...)
}

func (f *fakeAPI) popLocked(q *[]int) int {
	if len(*q) == 0 {
		return 0
	}
	v := (*q)[0]
	*q = (*q)[1:]
	return v
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !strings.HasPrefix(r.URL.Path, "/v0a4471/") {
		f.violate("path %q outside versioned API base", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if got := r.Header.Get("CF-Client-Version"); !strings.HasSuffix(got, "-"+apiVersionBuild) {
		f.violate("CF-Client-Version %q does not pair with path build %s", got, apiVersionBuild)
	}
	if got := r.Header.Get("User-Agent"); got != clientUA {
		f.violate("User-Agent %q", got)
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v0a4471/reg":
		f.handlePost(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v0a4471/reg/"):
		f.handlePatch(w, r, strings.TrimPrefix(r.URL.Path, "/v0a4471/reg/"))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/account") &&
		strings.HasPrefix(r.URL.Path, "/v0a4471/reg/"):
		f.handleAccount(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v0a4471/reg/"), "/account"))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v0a4471/reg/"):
		f.handleGet(w, r, strings.TrimPrefix(r.URL.Path, "/v0a4471/reg/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v0a4471/reg/"):
		f.handleDelete(w, r, strings.TrimPrefix(r.URL.Path, "/v0a4471/reg/"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, apiErrorBody{Success: false, Errors: []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{{Code: code, Message: msg}}})
}

func (f *fakeAPI) handlePost(w http.ResponseWriter, r *http.Request) {
	f.postCount++
	if st := f.popLocked(&f.postStatuses); st != 0 {
		if f.retryAfter != "" && st == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		writeErr(w, st, 1000, "queued failure")
		return
	}
	if f.postStatusDef != 0 {
		if f.retryAfter != "" && f.postStatusDef == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		writeErr(w, f.postStatusDef, 1000, "default failure")
		return
	}
	var body postRegistrationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, 1002, "bad json")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.Key)
	if err != nil || len(raw) != 32 {
		f.violate("POST key is not a 32-byte placeholder (len=%d err=%v)", len(raw), err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(body.SerialNumber) {
		f.violate("POST serial_number %q not hex8", body.SerialNumber)
	}
	if _, err := time.Parse(tosLayout, body.TOS); err != nil {
		f.violate("POST tos %q wrong layout: %v", body.TOS, err)
	}
	if body.Model == "" || body.Locale == "" {
		f.violate("POST model/locale fingerprint empty")
	}
	f.seq++
	dev := &fakeDevice{id: fmt.Sprintf("dev-%08x", f.seq), token: fmt.Sprintf("tok-%08x", f.seq)}
	f.devices[dev.id] = dev
	writeJSON(w, http.StatusOK, map[string]any{
		"id":    dev.id,
		"token": dev.token,
		"account": map[string]string{
			"license":      "",
			"account_type": "free",
		},
	})
}

func (f *fakeAPI) authed(dev *fakeDevice, r *http.Request) bool {
	want := "Bearer " + dev.token
	if r.Header.Get("Authorization") != want {
		f.violate("bearer mismatch on %s", r.URL.Path)
		return false
	}
	return true
}

func (f *fakeAPI) handlePatch(w http.ResponseWriter, r *http.Request, id string) {
	f.patchCount++
	dev, ok := f.devices[id]
	if !ok {
		writeErr(w, http.StatusNotFound, 1003, "no such device")
		return
	}
	if !f.authed(dev, r) {
		writeErr(w, http.StatusUnauthorized, 1004, "bad token")
		return
	}
	if f.patchStatus != 0 {
		if f.patchBody != "" {
			w.WriteHeader(f.patchStatus)
			_, _ = w.Write([]byte(f.patchBody))
			return
		}
		writeErr(w, f.patchStatus, 1005, "patch failure")
		return
	}
	var body patchKeyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, 1002, "bad json")
		return
	}
	if body.KeyType != "secp256r1" || body.TunnelType != "masque" {
		f.violate("PATCH key_type/tunnel_type = %q/%q", body.KeyType, body.TunnelType)
	}
	der, err := base64.StdEncoding.DecodeString(body.Key)
	if err == nil {
		if _, err := x509.ParsePKIXPublicKey(der); err != nil {
			f.violate("PATCH key not PKIX DER: %v", err)
		}
	} else {
		f.violate("PATCH key not base64: %v", err)
	}
	dev.patched = true
	writeJSON(w, http.StatusOK, map[string]any{"id": dev.id, "token": dev.token})
}

func (f *fakeAPI) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	f.getCount++
	dev, ok := f.devices[id]
	if !ok {
		writeErr(w, http.StatusNotFound, 1003, "no such device")
		return
	}
	if !f.authed(dev, r) {
		writeErr(w, http.StatusUnauthorized, 1004, "bad token")
		return
	}
	clientID := make([]byte, 3)
	_, _ = hex.Decode(clientID, []byte(dev.id[4:10]))
	out := deviceResponse{}
	out.ID = dev.id
	out.Token = dev.token
	out.Account.License = ""
	out.Account.AccountType = "free"
	out.Config.ClientID = base64.StdEncoding.EncodeToString(clientID)
	out.Config.Peers = []peerEntry{{
		PublicKey: f.pinPEM,
	}}
	out.Config.Peers[0].Endpoint.V4 = "engage.cloudflareclient.com:2408"
	v4 := "172.16.0.2"
	if f.assignedV4Override != "" {
		v4 = f.assignedV4Override
	}
	out.Config.Interface.Addresses.V4 = v4
	out.Config.Interface.Addresses.V6 = "2606:4700:110:8b41::1"
	writeJSON(w, http.StatusOK, out)
}

func (f *fakeAPI) handleAccount(w http.ResponseWriter, r *http.Request, id string) {
	f.accountCount++
	dev, ok := f.devices[id]
	if !ok {
		writeErr(w, http.StatusNotFound, 1003, "no such device")
		return
	}
	if !f.authed(dev, r) {
		writeErr(w, http.StatusUnauthorized, 1004, "bad token")
		return
	}
	st := f.popLocked(&f.accountStatuses)
	if st == 0 {
		st = f.accountStatDef
	}
	if st != 0 {
		if f.retryAfter != "" && st == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		writeErr(w, st, 1007, "account check refused")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":           dev.id,
		"license":      "",
		"account_type": "free",
	})
}

func (f *fakeAPI) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	f.deleteCount++
	dev, ok := f.devices[id]
	if !ok {
		writeErr(w, http.StatusNotFound, 1003, "no such device")
		return
	}
	if !f.authed(dev, r) {
		writeErr(w, http.StatusUnauthorized, 1004, "bad token")
		return
	}
	if f.deleteStatus != 0 {
		writeErr(w, f.deleteStatus, 1008, "delete failure")
		return
	}
	delete(f.devices, id)
	w.WriteHeader(http.StatusNoContent)
}
