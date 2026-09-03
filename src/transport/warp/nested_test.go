package transportwarp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// ---- harness ----

type nestedHarness struct {
	api     *fakeAPI
	srvURL  string
	mqBase  *fakeServer
	mqInner *fakeServer
	tmpl    SessionConfig
}

func newNestedHarness(t *testing.T) *nestedHarness {
	t.Helper()
	h := &nestedHarness{api: newFakeAPI(t)}
	srv := h.api.start()
	h.srvURL = srv.URL
	h.mqBase = newFakeServerWithKey(t, h.api.key)
	h.mqInner = newFakeServerWithKey(t, h.api.key)

	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	h.tmpl = SessionConfig{
		SNI:             DefaultSNI,
		ConnectURI:      DefaultConnectURI,
		ClientKey:       clientPriv,
		Pin:             &h.api.key.PublicKey,
		LocalV4:         [4]byte{172, 16, 0, 2},
		ValidateWindow:  200 * time.Millisecond,
		ProbeInterval:   5 * time.Millisecond,
		HandshakeBudget: 3 * time.Second,
	}
	return h
}

// factory builds one supervisor wired to its own endpoint, its own store
// (independent identities per layer) and the given pacing function.
func (h *nestedHarness) factory(t *testing.T, fs *fakeServer, mtu int, pace func(context.Context, time.Duration) error) SupervisorFactory {
	t.Helper()
	return func(ctx context.Context) (*Supervisor, error) {
		store := &IdentityStore{Path: t.TempDir() + "/identity.json"}
		cli := &EnrollClient{
			BaseURL: h.srvURL + "/v0a4471",
			Sleep:   func(context.Context, time.Duration) error { return nil },
		}
		rec := &Reconciler{API: cli, Store: store, MinEnrollInterval: time.Millisecond}
		tmpl := h.tmpl
		tmpl.Endpoint = fs.addr()
		tmpl.MTU = mtu
		return NewSupervisor(SupervisorConfig{
			Template:       tmpl,
			Reconciler:     rec,
			Sleep:          pace,
			HealthInterval: time.Hour,
		})
	}
}

// ---- config-plane hard rules (design §6) ----

func validNestedConfig() *NestedConfig {
	return &NestedConfig{
		BaseTemplate:  SessionConfig{Endpoint: netip.MustParseAddrPort("162.159.198.2:443"), MTU: 1280},
		InnerTemplate: SessionConfig{Endpoint: netip.MustParseAddrPort("162.159.199.7:443"), MTU: 1200},
		BaseIdentity:  &Identity{ID: "dev-base", AssignedV4: "172.16.0.2"},
		InnerIdentity: &Identity{ID: "dev-inner", AssignedV4: "172.16.1.2"},
		Backend:       BackendANetns,
		BaseInterface: "warp-base",
	}
}

func TestNestedConfigRejectsViolations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*NestedConfig)
		want   error
	}{
		{"positive", func(*NestedConfig) {}, nil},
		{"identical identity", func(c *NestedConfig) { c.InnerIdentity.ID = c.BaseIdentity.ID }, ErrIdenticalIdentity},
		{"address conflict", func(c *NestedConfig) { c.InnerIdentity.AssignedV4 = c.BaseIdentity.AssignedV4 }, ErrAddressConflict},
		{"same edge ip", func(c *NestedConfig) {
			c.InnerTemplate.Endpoint = netip.MustParseAddrPort("162.159.198.2:500") // same addr, other port
		}, ErrSameEdge},
		{"mtu gradient", func(c *NestedConfig) { c.InnerTemplate.MTU = 1280 }, ErrMTUGradient},
		{"unconstrained inner", func(c *NestedConfig) { c.BaseInterface = "" }, ErrUnconstrainedInner},
		{"tests-only unconstrained allowed", func(c *NestedConfig) {
			c.BaseInterface = ""
			c.AllowUnconstrainedInner = true
		}, nil},
		{"backend b without carrier", func(c *NestedConfig) {
			c.BaseInterface = ""
			c.Backend = BackendBProxy
			// DialFunc stays nil: no base-tunnel carrier attached.
		}, ErrBlockedCarrier},
		{"backend b with carrier skips policy gate", func(c *NestedConfig) {
			c.BaseInterface = ""
			c.Backend = BackendBProxy
			c.InnerTemplate.DialFunc = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("stub") }
		}, nil},
	}
	for _, tc := range cases {
		cfg := validNestedConfig()
		tc.mutate(cfg)
		err := cfg.Validate()
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := NewNestedRuntime(*validNestedConfig(), nil, nil); err == nil {
		t.Error("nil factories must be rejected")
	}
}

// ---- parent-link lifecycle ----

// Parent reconnect invalidates the child immediately; when the base route is
// held again, the child restarts REVALIDATED against the new generation.
func TestNestedParentReconnectInvalidatesChild(t *testing.T) {
	h := newNestedHarness(t)
	cfg := NestedConfig{
		BaseTemplate:  h.tmpl,
		InnerTemplate: h.tmpl,
		BaseIdentity:  &Identity{ID: "dev-base", AssignedV4: "172.16.0.2"},
		InnerIdentity: &Identity{ID: "dev-inner", AssignedV4: "172.16.1.2"},
		// Loopback fixture: no kernel policy applies; the documented
		// tests-only escape (NOT Backend-B, which now demands a real
		// base-tunnel carrier at config time).
		Backend:                 BackendANetns,
		PollInterval:            10 * time.Millisecond,
		AllowUnconstrainedInner: true,
	}
	rt, err := NewNestedRuntime(cfg,
		// Base reconnects with a REAL 300ms pause so the down-window is wide
		// enough for the controller poll to observe the invalidation
		// deterministically (an instant virtual sleep makes the dip shorter
		// than one poll tick — racy by construction).
		h.factory(t, h.mqBase, 1280, func(_ context.Context, d time.Duration) error {
			time.Sleep(d)
			return nil
		}),
		h.factory(t, h.mqInner, 1200, func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if rt.Start(context.Background()) != nil {
		t.Fatal("start")
	}

	waitFor(t, 5*time.Second, "link up + child running", func() bool {
		st := rt.Status()
		return st.Link == LinkUp && st.InnerRunning && st.ParentSessionGen == 1 && st.ChildRevalidated
	})
	waitFor(t, 5*time.Second, "both layers dialed", func() bool {
		bc, _ := h.mqBase.counters()
		ic := innerCount(h.mqInner)
		return bc > 0 && ic > 0
	})
	innerConns1 := innerCount(h.mqInner)

	// Bounce the PARENT session; the child must be invalidated at once.
	if err := rt.Base().Restart(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "child invalidated after parent loss", func() bool {
		st := rt.Status()
		return st.Link == LinkChildInvalidated && !st.InnerRunning && !st.ChildRevalidated
	})

	// Base reconnects on its own (virtual pacing); child revalidates on gen 2.
	waitFor(t, 8*time.Second, "child revalidated on generation 2", func() bool {
		st := rt.Status()
		return st.Link == LinkUp && st.ParentSessionGen == 2 && st.ChildRevalidated && st.InnerRunning
	})
	waitFor(t, 5*time.Second, "inner re-dialed against new generation", func() bool {
		return innerCount(h.mqInner) > innerConns1
	})
	innerConns2 := innerCount(h.mqInner)
	if innerConns2 <= innerConns1 {
		t.Fatalf("inner must dial again after revalidation: %d -> %d", innerConns1, innerConns2)
	}
	rt.Stop()
}

// innerCount reads the connect counter of one fixture server.
func innerCount(fs *fakeServer) int {
	c, _ := fs.counters()
	return c
}

// Telemetry: per-layer cf-warp-colo surfaces through Status (H-NONRU-1 prep).
func TestNestedTelemetryColo(t *testing.T) {
	h := newNestedHarness(t)
	h.mqBase.colo = "BASECOLO"
	h.mqInner.colo = "INNERCOLO"

	cfg := NestedConfig{
		BaseTemplate:  h.tmpl,
		InnerTemplate: h.tmpl,
		BaseIdentity:  &Identity{ID: "dev-base", AssignedV4: "172.16.0.2"},
		InnerIdentity: &Identity{ID: "dev-inner", AssignedV4: "172.16.1.2"},
		// Loopback fixture: tests-only unconstrained escape (Backend-B now
		// demands a real base-tunnel carrier at config time).
		Backend:                 BackendANetns,
		PollInterval:            10 * time.Millisecond,
		AllowUnconstrainedInner: true,
	}
	rt, err := NewNestedRuntime(cfg,
		h.factory(t, h.mqBase, 1280, func(context.Context, time.Duration) error { return nil }),
		h.factory(t, h.mqInner, 1200, func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	rt.Start(context.Background())
	waitFor(t, 5*time.Second, "both layers up with colo", func() bool {
		st := rt.Status()
		return st.Link == LinkUp && st.InnerRunning && st.InnerColo != "" && st.BaseColo != ""
	})
	st := rt.Status()
	if st.BaseColo != "BASECOLO" || st.InnerColo != "INNERCOLO" {
		t.Fatalf("colo telemetry missing: %+v", st)
	}
	rt.Stop()
}
