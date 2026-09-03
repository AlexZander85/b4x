// guardandloop_test.go: supervisor guard/anti-loop/telemetry fixes of the
// E-FXVPN review (F6, F10, L1). Runs fully offline: the fake session keeps
// ensureSession off the network, the serverlist rides a seeded cache file
// (fresh TTL — no Remote Settings contact), and the guard checks assert
// events and refusal classes without dialing.
package fxvpservice

import (
        "context"
        "encoding/json"
        "errors"
        "net"
        "net/netip"
        "os"
        "path/filepath"
        "testing"
        "time"
)

// ipStub resolves every name to one IP (the F6 node-IP guard seam).
type ipStub struct{ ip net.IP }

func (s ipStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
        return []net.IPAddr{{IP: s.ip}}, nil
}

// seedServerlist writes a fresh (TTL-valid) cache file next to the accounts
// store so resolveLocation never contacts Remote Settings offline.
func seedServerlist(t *testing.T, accountsPath string, fetchedAt time.Time, servers ...map[string]interface{}) {
        t.Helper()
        if len(servers) == 0 {
                servers = []map[string]interface{}{
                        // Loopback on a closed port: the admin path in
                        // TestGuardCap... reaches dialSession and fails FAST
                        // (connection refused) instead of timing out on DNS.
                        {"hostname": "127.0.0.1", "port": 1},
                }
        }
        body := map[string]interface{}{
                "version":    1,
                "fetched_at": fetchedAt.UTC().Format(time.RFC3339Nano),
                "countries": []map[string]interface{}{{
                        "code": "US", "name": "United States",
                        "cities": []map[string]interface{}{{
                                "code": "nyc", "name": "New York",
                                "servers": servers,
                        }},
                }},
        }
        blob, err := json.Marshal(body)
        if err != nil {
                t.Fatalf("marshal serverlist: %v", err)
        }
        if err := os.WriteFile(siblingPath(accountsPath, "serverlist.json"), blob, 0600); err != nil {
                t.Fatalf("seed serverlist: %v", err)
        }
}

// TestGuardCapEmitsEventAndAdminBypasses pins review F10: when the
// automatic rebuild cap refuses a supervisor-driven rebuild, the runtime
// emits fxvpn_restart_capped (the GUI sees WHY nothing happens); an
// administrative rebuild (SetLocation) bypasses the cap entirely.
func TestGuardCapEmitsEventAndAdminBypasses(t *testing.T) {
        fx := newLiveFixture(t, 15)
        ctx := context.Background()

        // Dead session forces ensureSession down the rebuild path.
        dead := newFakeSession()
        _ = dead.Close()
        fx.rt.session = dead
        fx.rt.sessionHost = "atn1.m1.fastly-masque.net:2499"

        // Exhaust the restart budget.
        for i := 0; i < MaxRestartsPerHour; i++ {
                fx.rt.guard.stamp()
        }
        if fx.rt.guard.allowed() {
                t.Fatal("guard must be capped")
        }
        // Seed the offline serverlist so the ADMIN tick below fails fast at the
        // dial instead of hanging on DNS (the guard refusal in part 1 fires
        // before resolveLocation either way).
        seedServerlist(t, fx.rt.cfg.AccountsPath, time.Now())
        fx.rt.sl = nil
        fx.rt.tick(ctx)
        st := fx.rt.Status()
        capped := false
        for _, ev := range st.Events {
                if ev.Type == "fxvpn_restart_capped" {
                        capped = true
                }
        }
        if !capped {
                t.Fatalf("cap refusal must emit fxvpn_restart_capped: %+v", st.Events)
        }

        // Administrative rebuild bypasses the cap: SetLocation marks admin, and
        // the tick proceeds PAST the guard (it may fail later on the offline
        // dial — the point is the refusal event must not reappear).
        before := len(fx.rt.Status().Events)
        fx.rt.SetLocation(fx.rt.cfg.Location)
        stampsBefore := len(fx.rt.guard.stamps)
        fx.rt.tick(ctx)
        st = fx.rt.Status()
        for _, ev := range st.Events[before:] {
                if ev.Type == "fxvpn_restart_capped" {
                        t.Fatalf("admin rebuild must bypass the cap: %+v", st.Events[before:])
                }
        }
        if stampsNow := len(fx.rt.guard.stamps); stampsNow != stampsBefore {
                t.Fatalf("admin rebuild must not consume the restart budget: stamps %d -> %d", stampsBefore, stampsNow)
        }
}

// TestDialStreamNodeIPGuard pins review F6: DialStream receives a resolved
// IP, so the self-loop guard compares it against the ACTIVE node's resolved
// IPs (cached per session) — the hostname comparison alone was dead code.
func TestDialStreamNodeIPGuard(t *testing.T) {
        fx := newLiveFixture(t, 15)

        live := newFakeSession()
        fx.rt.session = live
        fx.rt.sessionHost = "atn1.m1.fastly-masque.net:2499"
        nodeIP := netip.MustParseAddr("203.0.113.7")
        fx.rt.nodeIPs = []netip.Addr{nodeIP}

        // Dialing the node's IP is a self-loop.
        _, err := fx.rt.DialStream(context.Background(), netip.AddrPortFrom(nodeIP, 443))
        if !errors.Is(err, ErrFxvpnSelfLoop) {
                t.Fatalf("node-IP dial must be refused, got %v", err)
        }

        // Any other IP passes the guard and reaches the session opener.
        _, err = fx.rt.DialStream(context.Background(), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.5"), 443))
        if errors.Is(err, ErrFxvpnSelfLoop) {
                t.Fatalf("unrelated IP must not be flagged as self-loop: %v", err)
        }

        // The cache itself comes from resolveNodeIPs (best-effort).
        fx.rt.resolver = ipStub{ip: net.ParseIP("203.0.113.9")}
        ips := fx.rt.resolveNodeIPs(context.Background(), "atn1.m1.fastly-masque.net")
        if len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9") {
                t.Fatalf("resolveNodeIPs = %v", ips)
        }
}

// TestLocationsFetchedAtFilled pins review L1: LocationsView.FetchedAt is
// served from the cache snapshot (not a hardcoded zero assignment).
func TestLocationsFetchedAtFilled(t *testing.T) {
        dir := t.TempDir()
        accountsPath := filepath.Join(dir, "accounts.json")
        stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
        seedServerlist(t, accountsPath, stamp)

        fx := newLiveFixture(t, 15)
        // Point the runtime at the seeded cache directory.
        fx.rt.cfg.AccountsPath = accountsPath
        fx.rt.sl = nil // force the lazy getter to rebuild from the seeded path

        view, err := fx.rt.Locations(context.Background())
        if err != nil {
                t.Fatalf("locations from seeded cache: %v", err)
        }
        if !view.FetchedAt.Equal(stamp) {
                t.Fatalf("FetchedAt = %v, want %v", view.FetchedAt, stamp)
        }
        if len(view.Countries) == 0 || view.Countries[0].Code != "US" {
                t.Fatalf("countries = %+v", view.Countries)
        }
}

// TestNodeStrikesRotateCandidates pins review F8: two consecutive dial
// failures on cands[0] rotate the candidate selection to the next server;
// a success clears the streak and the original node returns.
func TestNodeStrikesRotateCandidates(t *testing.T) {
        dir := t.TempDir()
        accountsPath := filepath.Join(dir, "accounts.json")
        seedServerlist(t, accountsPath, time.Now(),
                map[string]interface{}{"hostname": "127.0.0.1", "port": 1},
                map[string]interface{}{"hostname": "127.0.0.1", "port": 2},
        )
        fx := newLiveFixture(t, 15)
        fx.rt.cfg.AccountsPath = accountsPath
        fx.rt.sl = nil
        ctx := context.Background()

        host, port, err := fx.rt.resolveLocation(ctx)
        if err != nil || port != 1 {
                t.Fatalf("first pick = %s:%d err=%v", host, port, err)
        }

        // One strike: below the threshold, same node (anti-flap).
        fx.rt.strikeNode("127.0.0.1:1")
        if _, port, _ = fx.rt.resolveLocation(ctx); port != 1 {
                t.Fatalf("one strike must not rotate, picked :%d", port)
        }

        // Second strike: the candidate rotates.
        fx.rt.strikeNode("127.0.0.1:1")
        host, port, err = fx.rt.resolveLocation(ctx)
        if err != nil || port != 2 {
                t.Fatalf("two strikes must rotate to the next candidate, got %s:%d err=%v", host, port, err)
        }
        var degraded bool
        for _, ev := range fx.rt.Status().Events {
                if ev.Type == "fxvpn_node_degraded" {
                        degraded = true
                }
        }
        if !degraded {
                t.Fatal("fxvpn_node_degraded event missing")
        }
}

// TestNodeStrikesClearedOnSuccess keeps the F8 contract symmetric: a
// successful dial forgets the streak, so the node re-enters rotation.
func TestNodeStrikesClearedOnSuccess(t *testing.T) {
        fx := newLiveFixture(t, 15)
        fx.rt.strikeNode("127.0.0.1:1")
        fx.rt.strikeNode("127.0.0.1:1")
        fx.rt.clearNodeStrikes("127.0.0.1:1")
        if got := fx.rt.nodeStrikes["127.0.0.1:1"]; got != 0 {
                t.Fatalf("streak not cleared: %d", got)
        }
}
