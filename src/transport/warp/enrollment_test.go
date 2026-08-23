package transportwarp

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---- harness ----

const baseTestTime = "2026-08-23T12:00:00Z"

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type harness struct {
	fake   *fakeAPI
	cli    *EnrollClient
	rec    *Reconciler
	store  *IdentityStore
	clock  *testClock
	sleeps *[]time.Duration
}

func newHarness(t *testing.T, minInterval time.Duration) *harness {
	t.Helper()
	base, err := time.Parse(time.RFC3339, baseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		fake:   newFakeAPI(t),
		clock:  &testClock{now: base},
		sleeps: &[]time.Duration{},
	}
	srv := h.fake.start()
	dir := t.TempDir()
	h.store = &IdentityStore{Path: filepath.Join(dir, "identity.json")}
	statePath := h.store.Path + ".state"
	h.cli = &EnrollClient{
		// BaseURL fully replaces DefaultAPIBase including the versioned
		// segment (same contract production uses for transport injection).
		BaseURL:     srv.URL + "/v0a4471",
		MaxAttempts: 3,
		Jitter:      mrand.New(mrand.NewPCG(42, 1)),
		Sleep: func(_ context.Context, d time.Duration) error {
			*h.sleeps = append(*h.sleeps, d)
			return nil
		},
		Now: h.clock.Now,
	}
	h.rec = &Reconciler{
		API:               h.cli,
		Store:             h.store,
		StatePath:         statePath,
		MinEnrollInterval: minInterval,
		Now:               h.clock.Now,
	}
	return h
}

func (h *harness) ensure(t *testing.T) EnsureResult {
	t.Helper()
	res, err := h.rec.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return res
}

func assertNoProtocolViolations(t *testing.T, f *fakeAPI) {
	t.Helper()
	if v := f.failedProtocol(); len(v) > 0 {
		t.Fatalf("fake API protocol violations: %v", v)
	}
}

// ---- scenarios (design E2 verification matrix) ----

// Happy path: empty store -> provision -> second call keeps valid identity
// without touching the registration endpoint again.
func TestEnsureProvisionsAndKeepsValid(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)

	res := h.ensure(t)
	if res.Action != ActionProvisioned || res.Identity == nil {
		t.Fatalf("want provisioned, got %+v", res)
	}
	id := res.Identity
	if !strings.HasPrefix(id.ID, "dev-") || !strings.HasPrefix(id.Token, "tok-") {
		t.Fatalf("bad identity ids: %s", id.ID)
	}
	wantDigest := PinDigest(&h.fake.key.PublicKey)
	if id.PinDigest != wantDigest {
		t.Fatalf("pin digest mismatch: %s != %s", id.PinDigest, wantDigest)
	}
	if id.AssignedV4 != "172.16.0.2" || id.AssignedV6 == "" || id.ClientID == "" {
		t.Fatalf("assigned addresses not captured: %+v", id)
	}
	post, _, get, account, del := h.fake.counters()
	if post != 1 || get != 1 || account != 0 || del != 0 {
		t.Fatalf("unexpected counters post=%d get=%d account=%d del=%d", post, get, account, del)
	}

	// Committed file is 0600 where the OS supports POSIX modes.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(h.store.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("identity file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	res2 := h.ensure(t)
	if res2.Action != ActionKeptValid || res2.Identity.ID != id.ID {
		t.Fatalf("want kept-valid of same identity, got %+v", res2)
	}
	post2, _, _, account2, _ := h.fake.counters()
	if post2 != 1 {
		t.Fatalf("revalidation must not re-register (post=%d)", post2)
	}
	if account2 != 1 {
		t.Fatalf("revalidation GET account expected once, got %d", account2)
	}
	assertNoProtocolViolations(t, h.fake)
}

// API code 1001 InvalidPublicKey aborts the transaction: no commit, no retry.
func TestEnrollInvalidKey1001Aborts(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.fake.patchStatus = http.StatusBadRequest
	h.fake.patchBody = `{"success":false,"errors":[{"code":1001,"message":"device.key: Invalid public key"}]}`

	res, err := h.rec.Ensure(context.Background())
	if err == nil {
		t.Fatal("want error on 1001")
	}
	if res.FailureClass != ClassEnrollmentInvalidK {
		t.Fatalf("failure class = %q, want %q", res.FailureClass, ClassEnrollmentInvalidK)
	}
	post, patch, _, _, _ := h.fake.counters()
	if post != 1 || patch != 1 {
		t.Fatalf("no retries expected after permanent key error: post=%d patch=%d", post, patch)
	}
	if _, lerr := h.store.Load(); !errors.Is(lerr, ErrIdentityAbsent) {
		t.Fatalf("nothing must be committed on failed transaction, load=%v", lerr)
	}
}

// 401/404/410 = dead identity -> automatic reprovision.
func TestRefused401TriggersReprovision(t *testing.T) {
	h := newHarness(t, time.Millisecond)

	first := h.ensure(t)
	if first.Action != ActionProvisioned {
		t.Fatalf("setup: %+v", first)
	}
	h.fake.accountStatuses = []int{http.StatusUnauthorized}
	h.clock.Advance(time.Second)

	second := h.ensure(t)
	if second.Action != ActionProvisioned {
		t.Fatalf("refused identity must be re-provisioned, got %+v", second)
	}
	if second.Identity.ID == first.Identity.ID {
		t.Fatal("reprovision must mint a NEW device id")
	}
	post, _, _, _, del := h.fake.counters()
	if post != 2 {
		t.Fatalf("post=%d, want exactly one extra registration", post)
	}
	if del != 0 {
		t.Fatalf("dead device must not be DELETEd (already refused): %d", del)
	}
	assertNoProtocolViolations(t, h.fake)
}

// 403/429 = throttle class: NEVER re-register; Retry-After honored with cap.
func TestThrottled429NeverReregisters(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)

	first := h.ensure(t)
	h.fake.accountStatDef = http.StatusTooManyRequests
	h.fake.retryAfter = "120" // server asks 120s; cap is 30s
	h.clock.Advance(time.Minute)

	blocked := h.ensure(t)
	if blocked.Action != ActionBlockedThrottle {
		t.Fatalf("want blocked-throttle, got %+v", blocked)
	}
	if blocked.Identity == nil || blocked.Identity.ID != first.Identity.ID {
		t.Fatal("throttle must keep the live identity untouched")
	}
	// Enrollment floor (600s) dominates: Retry-After cap (30s) can extend a
	// short configured floor but never shortens the default one.
	until := blocked.ThrottleUntil.Sub(h.clock.Now())
	if until != DefaultMinEnrollInterval {
		t.Fatalf("cooldown floor violated: until in %v", until)
	}
	post1, _, _, _, _ := h.fake.counters()

	h.clock.Advance(5 * time.Second)
	again := h.ensure(t)
	if again.Action != ActionBlockedThrottle {
		t.Fatalf("still throttled, got %+v", again)
	}
	post2, _, _, account2, _ := h.fake.counters()
	if post1 != 1 || post2 != 1 {
		t.Fatalf("throttle class must never register: post=%d then %d", post1, post2)
	}
	if account2 < 2 {
		t.Fatal("revalidation GETs are cheap and must continue (enrollment alone is gated)")
	}
}

// Corrupt store file is quarantined as *.corrupt and reprovisioned over.
func TestCorruptQuarantineAndReprovision(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)

	first := h.ensure(t)
	if err := os.WriteFile(h.store.Path, []byte("{\"format\":1,\"id\":\"tru"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(DefaultMinEnrollInterval + time.Second) // leave cooldown

	res := h.ensure(t)
	if !res.Quarantined || res.Action != ActionProvisioned {
		t.Fatalf("want quarantine+provision, got %+v", res)
	}
	if _, err := os.Stat(h.store.Path + ".corrupt"); err != nil {
		t.Fatalf("quarantine evidence missing: %v", err)
	}
	loaded, err := h.store.Load()
	if err != nil || loaded.ID == first.Identity.ID {
		t.Fatalf("fresh usable identity expected, got %v %+v", err, loaded)
	}
}

// Renewal window: due identity is replaced via full transaction; a failing
// API keeps the old generation intact (keep-old-on-failure).
func TestRenewalCommitAndKeepOldOnFailure(t *testing.T) {
	// A: successful renewal commits and frees the old device slot.
	h := newHarness(t, DefaultMinEnrollInterval)
	first := h.ensure(t)
	due, err := h.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	due.ExpiresAt = h.clock.Now().Add(3 * 24 * time.Hour) // inside 7-day window
	if err := h.store.Save(due); err != nil {
		t.Fatal(err)
	}
	// Leave the provisioning cooldown window before the renewal attempt.
	h.clock.Advance(DefaultMinEnrollInterval + time.Second)

	renewed := h.ensure(t)
	if renewed.Action != ActionRenewed {
		t.Fatalf("want renewed, got %+v", renewed)
	}
	if renewed.Identity.ID == first.Identity.ID {
		t.Fatal("renewal must mint a new device")
	}
	if _, _, _, _, del := h.fake.counters(); del != 1 {
		t.Fatalf("replaced device must be deleted best-effort, del=%d", del)
	}
	stored, err := h.store.Load()
	if err != nil || stored.ID != renewed.Identity.ID {
		t.Fatalf("committed renewal not on disk: %v %+v", err, stored)
	}

	// B: failing API during renewal keeps the previous generation.
	h2 := newHarness(t, DefaultMinEnrollInterval)
	base := h2.ensure(t)
	due2, err := h2.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	due2.ExpiresAt = h2.clock.Now().Add(24 * time.Hour)
	if err := h2.store.Save(due2); err != nil {
		t.Fatal(err)
	}
	h2.fake.postStatusDef = http.StatusInternalServerError
	h2.clock.Advance(DefaultMinEnrollInterval + time.Second)

	resB, err := h2.rec.Ensure(context.Background())
	if err == nil {
		t.Fatal("want enrollment failure")
	}
	if resB.FailureClass != ClassIdentityThrottled {
		t.Fatalf("5xx is throttled-class, got %q", resB.FailureClass)
	}
	if resB.Action != ActionBlockedThrottle || resB.Identity == nil || resB.Identity.ID != base.Identity.ID {
		t.Fatalf("old identity must survive: %+v", resB)
	}
	onDisk, lerr := h2.store.Load()
	if lerr != nil || onDisk.ID != base.Identity.ID {
		t.Fatalf("keep-old-on-failure violated on disk: %v %+v", lerr, onDisk)
	}
}

// Only transport errors are retried inside one step, with backoff+jitter.
func TestBackoffOnTransportError(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	rt := &flakyRoundTripper{inner: http.DefaultTransport, failsRemaining: 1}
	h.cli.HTTP = &http.Client{Transport: rt}
	h.cli.BackoffBase = 900 * time.Millisecond
	h.cli.BackoffCap = 15 * time.Second

	res, out, err := h.cli.Enroll(context.Background())
	if err != nil || out != OutcomeOK {
		t.Fatalf("enroll should recover after one transient failure: %v %v", out, err)
	}
	if res.ID == "" {
		t.Fatal("no identity returned")
	}
	if len(*h.sleeps) != 1 {
		t.Fatalf("one backoff sleep expected, got %d", len(*h.sleeps))
	}
	d := (*h.sleeps)[0]
	lo := time.Duration(float64(900*time.Millisecond) * (2.0 / 3.0))
	hi := time.Duration(float64(900*time.Millisecond) * (4.0 / 3.0))
	if d < lo || d > hi {
		t.Fatalf("backoff %v outside jitter band [%v,%v]", d, lo, hi)
	}
}

type flakyRoundTripper struct {
	inner          http.RoundTripper
	failsRemaining int
}

func (rt *flakyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.failsRemaining--
	if rt.failsRemaining >= 0 {
		return nil, fmt.Errorf("connection reset by peer (fixture)")
	}
	return rt.inner.RoundTrip(req)
}

// 429 during enrollment extends the cooldown stamp up to the Retry-After cap.
func TestEnrollment429ExtendsCooldown(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.fake.postStatuses = []int{http.StatusTooManyRequests}
	h.fake.retryAfter = "25"

	res, err := h.rec.Ensure(context.Background())
	if err == nil || res.FailureClass != ClassIdentityThrottled {
		t.Fatalf("want throttled failure, got %+v err=%v", res, err)
	}
	until := res.ThrottleUntil.Sub(h.clock.Now())
	if until < 20*time.Second || until > MaxRetryAfterCap+time.Second {
		t.Fatalf("cooldown not extended to Retry-After cap: %v", until)
	}

	// Immediate retry performs zero network calls; cooldown is a STRUCTURED
	// outcome for the supervisor (E3), not an error condition.
	before, _, _, _, _ := h.fake.counters()
	blocked, err := h.rec.Ensure(context.Background())
	if err != nil {
		t.Fatalf("cooldown block must be structured, not an error: %v", err)
	}
	if blocked.Action != ActionBlockedCooldown || blocked.FailureClass != ClassEnrollmentCooldown {
		t.Fatalf("want cooldown block, got %+v", blocked)
	}
	after, _, _, _, _ := h.fake.counters()
	if before != after {
		t.Fatalf("cooldown block must make zero requests (%d -> %d)", before, after)
	}
}

// A stamp from the future (skewed clock) is reset instead of honored.
func TestStampFutureReset(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	futureState := fmt.Sprintf(`{"next_allowed":%q}`, h.clock.Now().Add(48*time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(h.rec.StatePath, []byte(futureState), 0o600); err != nil {
		t.Fatal(err)
	}

	res := h.ensure(t)
	if res.Action != ActionProvisioned {
		t.Fatalf("future stamp must reset, got %+v", res)
	}
	if post, _, _, _, _ := h.fake.counters(); post != 1 {
		t.Fatalf("post=%d after future-stamp reset", post)
	}
}

// Unwritable intent stamp means "do not do it" (fail closed).
func TestIntentStampUnwritableBlocksAction(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	if err := os.MkdirAll(h.rec.StatePath, 0o700); err != nil { // state path becomes a directory
		t.Fatal(err)
	}

	res, err := h.rec.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stamp") {
		t.Fatalf("want stamp-unwritable error, got %+v err=%v", res, err)
	}
	if post, _, _, _, _ := h.fake.counters(); post != 0 {
		t.Fatalf("no enrollment may happen without writable stamps, post=%d", post)
	}
}

// ---- pure-function tables ----

func TestClassifyHTTPStatusTable(t *testing.T) {
	cases := []struct {
		code int
		want Outcome
	}{
		{200, OutcomeOK}, {201, OutcomeOK}, {204, OutcomeOK},
		{401, OutcomeRefused}, {404, OutcomeRefused}, {410, OutcomeRefused},
		{403, OutcomeThrottled}, {429, OutcomeThrottled},
		{500, OutcomeThrottled}, {502, OutcomeThrottled}, {503, OutcomeThrottled},
		{400, OutcomeRequestError}, {412, OutcomeRequestError}, {422, OutcomeRequestError},
	}
	for _, c := range cases {
		if got := ClassifyHTTPStatus(c.code); got != c.want {
			t.Errorf("%d -> %v, want %v", c.code, got, c.want)
		}
	}
}

func TestParseRetryAfterCap(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0}, {"5", 5 * time.Second}, {"120", MaxRetryAfterCap},
		{"abc", 0}, {"-1", 0}, {" 10 ", 10 * time.Second},
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in); got != c.want {
			t.Errorf("%q -> %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIdentityNeedsRenewalBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	id := &Identity{}
	if id.NeedsRenewal(now, DefaultRenewWindow) {
		t.Fatal("zero expiry never renews")
	}
	id.ExpiresAt = now.Add(DefaultRenewWindow - time.Hour)
	if !id.NeedsRenewal(now, DefaultRenewWindow) {
		t.Fatal("inside window must renew")
	}
	id.ExpiresAt = now.Add(DefaultRenewWindow + 24*time.Hour)
	if id.NeedsRenewal(now, DefaultRenewWindow) {
		t.Fatal("outside window must not renew")
	}
}
