package fxvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- ladder -----------------------------------------------------------------

func TestLadderPreferH3OffNeverPicksH3(t *testing.T) {
	l := NewLadder(LadderConfig{PreferH3: false})
	if got := l.Preferred(); got != CarrierH2 {
		t.Fatalf("preferred = %s, want h2", got)
	}
	_, switched := l.ObserveDialFailure(CarrierH3, fmt.Errorf("wrap %w", errUDPEgressBlocked))
	if switched {
		t.Fatal("h3 failure with prefer=off must not switch anything")
	}
	if got := l.Preferred(); got != CarrierH2 {
		t.Fatalf("after failure preferred = %s", got)
	}
}

func TestLadderConfirmedFailureSwitchesOnceAndCooldownReturns(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewLadder(LadderConfig{PreferH3: true, Now: func() time.Time { return now }})

	if got := l.Preferred(); got != CarrierH3 {
		t.Fatalf("initial preferred = %s, want h3", got)
	}

	switchTo, switched := l.ObserveDialFailure(CarrierH3, fmt.Errorf("dial: %w", errUDPEgressBlocked))
	if !switched || switchTo != CarrierH2 {
		t.Fatalf("switch = %v/%s, want true/h2", switched, switchTo)
	}
	if l.Switches() != 1 {
		t.Fatalf("switches = %d, want 1", l.Switches())
	}

	// Cooldown window: every tick goes to H2 silently (5 x 50s < 300s).
	for i := 0; i < 5; i++ {
		now = now.Add(50 * time.Second)
		if got := l.Preferred(); got != CarrierH2 {
			t.Fatalf("tick %d during cooldown preferred = %s", i, got)
		}
		switchTo, switched = l.ObserveDialFailure(CarrierH3, fmt.Errorf("x %w", errUDPEgressBlocked))
		if switched {
			t.Fatalf("tick %d produced a second switch (oscillation)", i)
		}
	}
	if l.Switches() != 1 {
		t.Fatalf("switches after cooldown ticks = %d, want exactly 1", l.Switches())
	}

	// After cooldown expiry H3 is allowed again.
	now = now.Add(DefaultH3ReturnCooldown + time.Minute)
	if got := l.Preferred(); got != CarrierH3 {
		t.Fatalf("post-cooldown preferred = %s, want h3", got)
	}
}

func TestLadderNegotiationFailedAlsoSwitches(t *testing.T) {
	l := NewLadder(LadderConfig{PreferH3: true})
	_, switched := l.ObserveDialFailure(CarrierH3, fmt.Errorf("wrap %w", errH3NegotiationFailed))
	if !switched {
		t.Fatal("h3-negotiation-failed is a confirmed switch class")
	}
}

func TestLadderAccountLevelFailuresDoNotSwitch(t *testing.T) {
	l := NewLadder(LadderConfig{PreferH3: true})
	cases := []error{
		&ConnectRejectedError{StatusCode: 407},
		&ConnectRejectedError{StatusCode: 429},
		&ConnectRejectedError{StatusCode: 502},
		errors.New("random transport hiccup"),
	}
	for _, err := range cases {
		if _, switched := l.ObserveDialFailure(CarrierH3, err); switched {
			t.Fatalf("%v must not switch carriers", err)
		}
	}
	if l.Switches() != 0 {
		t.Fatal("no switches expected")
	}
}

func TestLadderSuccessSticks(t *testing.T) {
	l := NewLadder(LadderConfig{PreferH3: true})
	l.ObserveDialSuccess(CarrierH3)
	if l.Switches() != 0 || l.Preferred() != CarrierH3 {
		t.Fatal("h3 success must stick")
	}
}

func TestClassifyDialErrorTable(t *testing.T) {
	cases := []struct {
		want string
		err  error
	}{
		{"udp-egress-blocked", fmt.Errorf("outer: %w", errUDPEgressBlocked)},
		{"h3-negotiation-failed", fmt.Errorf("outer: %w", errH3NegotiationFailed)},
		{"h2-unavailable", fmt.Errorf("outer: %w", errH2Unavailable)},
		{"", errors.New("misc")},
		{"", context.Canceled},
	}
	for _, tc := range cases {
		if got := ClassifyDialError(tc.err); got != tc.want {
			t.Fatalf("ClassifyDialError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// ---- exit probe through the tunnel -------------------------------------------

const cannedTrace = "ip=203.0.113.7\nloc=DE\ncolo=FRA\n"

func TestExitProbeMatchAndMismatch(t *testing.T) {
	e := newFakeH2Edge(t)
	e.mu.Lock()
	e.tracePayload = cannedTrace
	e.mu.Unlock()
	s := dialH2Test(t, e, "jwt-1")

	info, err := VerifyExitTLS(context.Background(), s, testTLSBase(), "DE")
	if err != nil {
		t.Fatalf("VerifyExit match: %v", err)
	}
	if info.Country != "DE" || info.IP != "203.0.113.7" {
		t.Fatalf("trace parse broken: %+v", info)
	}

	_, err = VerifyExitTLS(context.Background(), s, testTLSBase(), "US")
	var mm *ExitMismatchError
	if !errors.As(err, &mm) || mm.Got != "DE" || mm.Want != "US" {
		t.Fatalf("want ExitMismatchError DE!=US, got %v", err)
	}
	if Classify(err) != ClassExitMismatch {
		t.Fatalf("class = %q, want %q", Classify(err), ClassExitMismatch)
	}

	// Empty configured country disables the check.
	if _, err := VerifyExitTLS(context.Background(), s, testTLSBase(), ""); err != nil {
		t.Fatalf("auto mode must not verify: %v", err)
	}
}

func TestExitProbeConnectFailureSurfaces(t *testing.T) {
	e := newFakeH2Edge(t)
	e.setBehavior("", http.StatusBadGateway, "")
	s := dialH2Test(t, e, "jwt-1")

	if _, err := ProbeExit(context.Background(), s); err == nil {
		t.Fatal("probe through dead edge must fail")
	}
}

// ---- DialPolicy fail-closed ----------------------------------------------------

func TestListenUDPZeroPolicyWorks(t *testing.T) {
	policy := DialPolicy{}
	uc, err := policy.ListenUDP(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unconstrained ListenUDP: %v", err)
	}
	defer uc.Close()

	// Local UDP round trip proves the socket functional.
	server, err := policy.ListenUDP(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	srvAddr := server.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 16)
		n, _, rerr := server.ReadFrom(buf)
		if rerr == nil {
			_, _ = server.WriteTo(buf[:n], uc.LocalAddr().(*net.UDPAddr))
		}
	}()

	if _, err := uc.WriteTo([]byte("ping"), srvAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := uc.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
}

func TestListenUDPRequireMarkWithoutMarkFailsClosed(t *testing.T) {
	policy := DialPolicy{RequireMark: true} // mark required but none set
	if _, err := policy.ListenUDP(context.Background(), "udp", "127.0.0.1:0"); err == nil {
		t.Fatal("RequireMark without FwMark must fail closed")
	}
}

func TestListenUDPWithMarkFunctionalOrSkipped(t *testing.T) {
	policy := DialPolicy{FwMark: 0x42, RequireMark: true}
	uc, err := policy.ListenUDP(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("SO_MARK not permitted in this environment")
		}
		t.Fatalf("marked ListenUDP failed unexpectedly: %v", err)
	}
	defer uc.Close()
	if uc.LocalAddr() == nil {
		t.Fatal("socket not bound")
	}
}

// ---- UpdateToken validation ------------------------------------------------------

func TestUpdateTokenRejectsEmpty(t *testing.T) {
	e := newFakeH2Edge(t)
	s := dialH2Test(t, e, "jwt-1")
	if err := s.UpdateToken("   "); err == nil {
		t.Fatal("empty token must be rejected")
	}
	if s.bearerToken() != "jwt-1" {
		t.Fatal("failed renew must keep the old token")
	}
}
