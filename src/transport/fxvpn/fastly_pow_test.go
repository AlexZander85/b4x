package fxvpn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---- shared helpers -------------------------------------------------------

// makeJWT builds an unsigned three-part JWT with unpadded base64url parts,
// mirroring what Guardian returns (signature intentionally bogus: we never
// verify it, pinning replaces signature trust).
func makeJWT(t *testing.T, claims ProxyPassClaims) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2lnbmF0dXJl"
}

// newTestCP builds a ControlPlane against fake stands (plain HTTP, no
// persistence, no pins unless a path is given).
func newTestCP(t *testing.T, pinPath string) *ControlPlane {
	t.Helper()
	cp, err := NewControlPlane(pinPath)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	return cp
}

type epMutator func(*Endpoints)

func newStandCP(t *testing.T, mutators ...epMutator) (*ControlPlane, *Endpoints) {
	t.Helper()
	cp := newTestCP(t, "")
	mutators[0](&cp.EP)
	for _, m := range mutators[1:] {
		m(&cp.EP)
	}
	return cp, &cp.EP
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

// ---- minBudgetContext -----------------------------------------------------

func TestMinBudgetContextExtendsShortParent(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	ctx, stop := minBudgetContext(parent, time.Second)
	defer stop()

	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < 900*time.Millisecond {
		t.Fatalf("expected extended deadline, got %v (ok=%v)", deadline, ok)
	}

	// Parent cancellation must still propagate through the watcher.
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not propagate")
	}
}

func TestMinBudgetContextKeepsLongParent(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wantDeadline, _ := parent.Deadline()
	ctx, stop := minBudgetContext(parent, time.Second)
	defer stop()

	gotDeadline, ok := ctx.Deadline()
	if !ok || !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("parent deadline changed: want %v got %v", wantDeadline, gotDeadline)
	}
}

// ---- PoW golden vectors ----------------------------------------------------

func TestSolvePowGoldenVector(t *testing.T) {
	// Known solution: SHA256("abcaZ") — solver must recover exactly this
	// two-character suffix out of the 62^2 space.
	sum := sha256.Sum256([]byte("abcaZ"))
	got, ok := solvePow("abc", hexSum(sum[:]))
	if !ok {
		t.Fatal("golden vector reported unsolvable")
	}
	if got != "aZ" {
		t.Fatalf("suffix = %q, want %q", got, "aZ")
	}
}

func TestSolvePowCaseSensitiveAlphabet(t *testing.T) {
	// 'A' vs 'a' produce different hashes; ensure uppercase is searched.
	sum := sha256.Sum256([]byte("xyA0"))
	got, ok := solvePow("xy", hexSum(sum[:]))
	if !ok || got != "A0" {
		t.Fatalf("got %q ok=%v, want A0", got, ok)
	}
}

func TestSolvePowUnsolvableAndMalformed(t *testing.T) {
	zeros := make([]byte, sha256.Size)
	if _, ok := solvePow("abc", hexSum(zeros)); ok {
		t.Fatal("zero target must not solve")
	}
	if _, ok := solvePow("abc", "not-hex"); ok {
		t.Fatal("non-hex target must not solve")
	}
	if _, ok := solvePow("abc", "aabb"); ok {
		t.Fatal("short target must not solve")
	}
}

func hexSum(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	const digits = "0123456789abcdef"
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0xf])
	}
	return string(out)
}

// ---- PAT / clientmetrics answers -------------------------------------------

func TestAnswerChallengePATFallbackOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ch := fastlyChallenge{Ty: "pat"}
	ans, err := answerChallenge(context.Background(), srv.Client(), srv.URL+"/_fs-ch-t", "tok", ch)
	if err != nil {
		t.Fatalf("PAT 401 should yield empty-auth fallback, got %v", err)
	}
	m := ans.(map[string]interface{})
	if m["ty"] != "pat" || m["auth"] != "" {
		t.Fatalf("unexpected pat answer %+v", m)
	}
}

func TestAnswerChallengeClientMetrics(t *testing.T) {
	ch := fastlyChallenge{Ty: "clientmetrics"}
	ans, err := answerChallenge(context.Background(), http.DefaultClient, "http://unused", "tok", ch)
	if err != nil {
		t.Fatalf("clientmetrics: %v", err)
	}
	m := ans.(map[string]interface{})
	if m["ty"] != "clientmetrics" {
		t.Fatalf("unexpected metrics answer %+v", m)
	}
}

func TestAnswerChallengeUnknownTypeIsHardError(t *testing.T) {
	ch := fastlyChallenge{Ty: "captcha"}
	if _, err := answerChallenge(context.Background(), http.DefaultClient, "http://unused", "tok", ch); err == nil {
		t.Fatal("unknown/captcha challenge must be a hard error")
	}
}

// ---- parseChallengeInit ------------------------------------------------------

func TestParseChallengeInitTakesLastCall(t *testing.T) {
	script := `first init([{"ty":"clientmetrics"}],"old-token","/_fs-ch-old"); later init([{"ty":"pow","data":{"base":"b"}}],"new-token","/_fs-ch-new")`
	challenges, tok, err := parseChallengeInit(script)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok != "new-token" {
		t.Fatalf("token = %q, want new-token (last call wins)", tok)
	}
	if len(challenges) != 1 || challenges[0].Ty != "pow" {
		t.Fatalf("challenges = %+v", challenges)
	}
}

func TestParseChallengeInitGarbage(t *testing.T) {
	if _, _, err := parseChallengeInit("no init here"); err == nil {
		t.Fatal("missing init must error")
	}
	if _, _, err := parseChallengeInit(`init([],"tok","p")`); err == nil {
		t.Fatal("empty challenge list must error")
	}
}
