package fxvpn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ---- JWT claims parser ------------------------------------------------------

func TestParseJWTClaimsValid(t *testing.T) {
	want := ProxyPassClaims{Sub: "acct-1", Aud: "fpn", Iat: 1700000000, Nbf: 1700000000, Exp: 1700003600, Iss: "guardian"}
	token := makeJWT(t, want)
	got, err := ParseJWTClaims(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *got != want {
		t.Fatalf("claims = %+v, want %+v", *got, want)
	}
}

func TestParseJWTClaimsMalformed(t *testing.T) {
	brokenJSON := "aaa." + base64.RawURLEncoding.EncodeToString([]byte("{not-json")) + ".sig"
	badBase64 := "aaa.!!!bad-base64!!!.sig"
	for i, tok := range []string{"", "onlyone", "a.b", "a.b.c.d", badBase64, brokenJSON} {
		if _, err := ParseJWTClaims(tok); err == nil {
			t.Fatalf("case %d (%q): expected error", i, tok)
		}
	}
}

// ---- claim-time offset detection ---------------------------------------------

func TestClaimOffsetFreshTokenZero(t *testing.T) {
	now := time.Now()
	claims := ProxyPassClaims{Nbf: now.Add(-time.Minute).Unix(), Exp: now.Add(5 * time.Minute).Unix()}
	if got := DetectProxyPassClaimTimeOffset(claims, now); got != 0 {
		t.Fatalf("fresh window offset = %v, want 0", got)
	}
}

func TestClaimOffsetDetectsGridShift(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	shift := 45 * time.Minute // member of the 15-minute candidate grid
	claims := ProxyPassClaims{
		Nbf: now.Add(-time.Minute - shift).Unix(),
		Exp: now.Add(5*time.Minute - shift).Unix(),
	}
	got := DetectProxyPassClaimTimeOffset(claims, now)
	if got != shift {
		t.Fatalf("offset = %v, want %v", got, shift)
	}
}

func TestClaimOffsetBeyondGridZero(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	shift := 20 * time.Hour // outside the -12h..+14h grid and any TZ offset
	claims := ProxyPassClaims{
		Nbf: now.Add(-21 * time.Hour).Add(-shift).Unix(),
		Exp: now.Add(-20 * time.Hour).Add(-shift).Unix(),
	}
	if got := DetectProxyPassClaimTimeOffset(claims, now); got != 0 {
		t.Fatalf("offset = %v, want 0 for unmatchable skew", got)
	}
}

func TestClaimOffsetZeroExp(t *testing.T) {
	if got := DetectProxyPassClaimTimeOffset(ProxyPassClaims{}, time.Now()); got != 0 {
		t.Fatalf("zero exp must short-circuit, got %v", got)
	}
}

// ---- Retry-After parsing -------------------------------------------------------

func TestParseRetryAfterSecondsAndDateAndGarbage(t *testing.T) {
	if d, ok := parseRetryAfter("120"); !ok || d != 2*time.Minute {
		t.Fatalf("seconds form: %v %v", d, ok)
	}
	future := time.Now().Add(90 * time.Second).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	d, ok := parseRetryAfter(future)
	if !ok || d <= 0 || d > 2*time.Minute {
		t.Fatalf("http-date form: %v %v", d, ok)
	}
	if d, ok := parseRetryAfter(""); ok {
		t.Fatalf("empty must be absent, got %v", d)
	}
	if _, ok := parseRetryAfter("soon-ish"); ok {
		t.Fatal("garbage must be absent")
	}
	past, ok := parseRetryAfter("Mon, 02 Jan 2006 15:04:05 GMT")
	if !ok || past != 0 {
		t.Fatalf("past date must clamp to 0, got %v %v", past, ok)
	}
}

// ---- error classification --------------------------------------------------------

func TestClassifyWrappers(t *testing.T) {
	qe := &QuotaError{RetryAfter: 30 * time.Second, HasRetryAfter: true, Status: 429}
	if !errors.Is(qe, ErrQuotaExceeded) || Classify(qe) != ClassQuotaExhausted {
		t.Fatalf("quota classification failed: %v", qe)
	}
	ti := &TokenInvalidError{Status: 403}
	if !errors.Is(ti, ErrTokenInvalid) || Classify(ti) != ClassAuthRejected {
		t.Fatalf("token-invalid classification failed")
	}
	pm := fmt.Errorf("wrap: %w", ErrPinMismatch)
	if !errors.Is(pm, ErrPinMismatch) || Classify(pm) != ClassAPIPinMismatch {
		t.Fatalf("pin classification failed")
	}
	ch := fmt.Errorf("wrap: %w", ErrChallenge)
	if !errors.Is(ch, ErrChallenge) || Classify(ch) != ClassChallengeFailed {
		t.Fatalf("challenge classification failed")
	}
	if Classify(errors.New("random")) != "" {
		t.Fatal("unknown error must classify empty")
	}
}
