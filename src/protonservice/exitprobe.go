// Exit verification probe (E-PROTON design §5, review P1): after the
// trust gate closes (OnEstablished), fetch the Cloudflare trace endpoint
// THROUGH the live session's netstack data plane and compare the exit
// country against the requested location. A mismatch is a verified
// proton_exit_mismatch verdict: the node takes a strike, the session is
// retired and the supervisor re-seeks INSIDE the location on the next
// tick (Proton sometimes serves a node of a different country under
// load-balancing — exactly the case the class exists for).
//
// The probe rides the WG data plane itself (the same netstack the trust
// gate dialed its DNS probe through) and resolves the trace host with the
// tunnel's own resolver — the system DNS is never involved, so the
// anti-loop bypass rules are trivially satisfied.
package protonservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/transport/proton"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

const (
	exitProbeHost    = "www.cloudflare.com"
	exitProbePath    = "/cdn-cgi/trace"
	exitProbeTimeout = 10 * time.Second
)

// exitDialFunc is the probe transport seam: production dials through the
// live session's netstack (DNS included, inside the tunnel); tests
// substitute a fake edge with a known country (review §6).
type exitDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// netstackExitDialer adapts the live WG tunnel's netstack onto the probe
// seam. Returns nil when the tunnel carries no userspace stack (kernel-TUN
// sessions get no exit probe at this stage — review P2 step (в), the
// kernel path is a separate stage).
func netstackExitDialer(t *twg.Tunnel) exitDialFunc {
	if t == nil || t.Netstack == nil {
		return nil
	}
	ns := t.Netstack
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return ns.DialContext(ctx, network, addr)
	}
}

// ExitInfo is what the trace probe observed on the far side of the tunnel.
type ExitInfo struct {
	IP      string
	Country string // ISO code from loc=
}

// probeExit speaks TLS + HTTP/1.1 to the Cloudflare trace endpoint through
// the supplied dialer (fxvpn.ProbeExit canon, WG data-plane edition).
func probeExit(ctx context.Context, dial exitDialFunc) (ExitInfo, error) {
	return probeExitTLS(ctx, dial, nil)
}

// probeExitTLS is the seam variant with an explicit TLS base (tests point
// it at a fake edge's certificate; production passes nil and gets the
// default config pinned to the trace host).
func probeExitTLS(ctx context.Context, dial exitDialFunc, tlsBase *tls.Config) (ExitInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, exitProbeTimeout)
	defer cancel()

	if dial == nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe dial unavailable (no netstack)")
	}
	conn, err := dial(ctx, "tcp", exitProbeHost+":443")
	if err != nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe connect: %w", err)
	}
	defer conn.Close()

	tlsCfg := &tls.Config{ServerName: exitProbeHost}
	if tlsBase != nil {
		tlsCfg = tlsBase.Clone()
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = exitProbeHost
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe tls: %w", err)
	}
	defer tlsConn.Close()

	req := "GET " + exitProbePath + " HTTP/1.1\r\n" +
		"Host: " + exitProbeHost + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ExitInfo{}, fmt.Errorf("proton: exit probe HTTP %d", resp.StatusCode)
	}

	info := ExitInfo{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			info.IP = v
		case "loc":
			info.Country = v
		}
	}
	if err := sc.Err(); err != nil {
		return ExitInfo{}, fmt.Errorf("proton: exit probe body: %w", err)
	}
	if info.Country == "" {
		return ExitInfo{}, fmt.Errorf("proton: exit probe trace has no loc")
	}
	return info, nil
}

// verifyExit runs the design §5 probe against the live session and stores
// the verdict in r.exit (the GUI VerifiedExit field — never empty again).
// It runs OFF the session callbacks (the caller spawns it in a goroutine):
// every SessionCallback must stay non-blocking.
func (r *Runtime) verifyExit(node proton.Node, prof proton.ProtonProfile, sess *twg.Session) {
	if sess == nil || sess.State() == twg.StateClosed {
		return
	}
	r.runExitProbe(node, prof, sess, netstackExitDialer(sess.Tunnel()))
}

// runExitProbe is the verifyExit core with the transport as an explicit
// seam (tests substitute a fake edge with a known country, review §6).
//
// Mismatch handling (review P1): EventExitMismatch + node strike (a single
// VERIFIED geo verdict cools the node down — unlike the jail heuristic,
// this needs no second confirmation) + session retirement — the next
// ensure re-seeks inside the location, skipping the struck endpoint.
func (r *Runtime) runExitProbe(node proton.Node, prof proton.ProtonProfile, sess *twg.Session, dial exitDialFunc) {
	r.mu.Lock()
	if r.exitProbing { // one probe at a time across generations
		r.mu.Unlock()
		return
	}
	r.exitProbing = true
	want := r.desiredExitCountryLocked(node)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.exitProbing = false
		r.mu.Unlock()
	}()

	if dial == nil {
		// Kernel-TUN mode (review P2 stage в): no userspace stack to dial
		// through — the probe is SKIPPED honestly (the exit view stays
		// empty), not failed; the netstack mode keeps the full check.
		r.appendEvent(proton.Event{Name: "proton_exit_probe_skipped",
			Detail: "kernel tunnel mode: no userspace data plane"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tlsBase *tls.Config
	if b, ok := r.opts.ExitProbeTLS.(*tls.Config); ok {
		tlsBase = b
	}
	info, err := probeExitTLS(ctx, dial, tlsBase)
	r.mu.Lock()
	r.exit = ExitView{
		IP:        info.IP,
		Country:   info.Country,
		CheckedAt: r.now(),
		OK:        err == nil,
	}
	if err != nil {
		r.exit.Error = err.Error()
	}
	mismatch := err == nil && want != "" && !strings.EqualFold(info.Country, want)
	r.mu.Unlock()

	if err != nil {
		r.appendEvent(proton.Event{Name: "proton_exit_probe_failed", Detail: err.Error()})
		return
	}
	if mismatch {
		r.noteFailure(proton.ClassExitMismatch)
		r.appendEvent(proton.Event{Name: proton.EventExitMismatch,
			Class:  proton.ClassExitMismatch,
			Detail: node.Name + " got " + info.Country + " want " + want})
		// Strike the node (one verified verdict => cooldown) and retire the
		// session: the next tick re-seeks within the location; the restart
		// caps bound the loop (no unbounded churn).
		r.strikes.Strike(prof.AddrPort(), r.now(), 1, RestartCooldown)
		r.mu.Lock()
		if r.sess == sess {
			r.sess = nil
			r.state = StateBackoff
		}
		r.mu.Unlock()
		return
	}
	r.appendEvent(proton.Event{Name: "proton_exit_verified",
		Detail: node.Name + " " + info.Country})
}

// desiredExitCountryLocked resolves the expected exit country under r.mu:
// country mode -> the configured ISO code; host mode -> the node's declared
// country; auto -> "" (any free exit serves, nothing to compare).
func (r *Runtime) desiredExitCountryLocked(node proton.Node) string {
	switch r.location.Mode {
	case "country":
		return strings.ToUpper(strings.TrimSpace(r.location.Country))
	case "host":
		return strings.ToUpper(strings.TrimSpace(node.Country))
	default:
		return ""
	}
}
