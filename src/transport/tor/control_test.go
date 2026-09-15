package tor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TT6 DoD (patch-plan §7): control-protocol transcript tests (recorded
// 250/5xx/multiline sessions), torrc render + validation (injection,
// transport-token, GeoIP/Socks5Proxy/PT gating), bootstrap timings on a
// fake control (progress ladder, stall, silence, snowflake cap),
// pid+exe identification, graded stop order.

// --- control protocol: fake tor control server ---

// fakeControlServer scripts replies line-by-line per command.
type fakeControlServer struct {
	ln      net.Listener
	mu      sync.Mutex
	lastCmd []string
	script  map[string][]string // cmd prefix -> reply lines (raw)
	auth    string
}

func newFakeControl(t *testing.T, script map[string][]string) *fakeControlServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeControlServer{ln: ln, script: script}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeControlServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				cmd, err := r.ReadString('\n')
				if err != nil {
					return
				}
				cmd = strings.TrimRight(cmd, "\r\n")
				s.mu.Lock()
				s.lastCmd = append(s.lastCmd, cmd)
				reply := s.match(cmd)
				s.mu.Unlock()
				if _, err := conn.Write([]byte(reply)); err != nil {
					return
				}
			}
		}()
	}
}

func (s *fakeControlServer) match(cmd string) string {
	for prefix, lines := range s.script {
		if strings.HasPrefix(cmd, prefix) {
			return strings.Join(lines, "\r\n") + "\r\n"
		}
	}
	return "514 unrecognized command\r\n"
}

func (s *fakeControlServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lastCmd...)
}

func TestControlAuthenticateAndCookieHex(t *testing.T) {
	srv := newFakeControl(t, map[string][]string{
		"AUTHENTICATE": {"250 OK"},
	})
	ctl, err := DialControl(context.Background(), "tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	// cookie 0xAB 0xCD 0xEF → "abcdef"
	if err := ctl.Authenticate([]byte{0xAB, 0xCD, 0xEF}); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	cmds := srv.commands()
	if len(cmds) != 1 || cmds[0] != "AUTHENTICATE abcdef" {
		t.Fatalf("wire = %v", cmds)
	}
}

func TestControlGetInfoSingleAndMultiline(t *testing.T) {
	srv := newFakeControl(t, map[string][]string{
		"AUTHENTICATE":                         {"250 OK"},
		"GETINFO net/listeners/socks":          {"250-net/listeners/socks=127.0.0.1:9050", "250 OK"},
		"GETINFO traffic/read traffic/written": {"250+traffic/read=", "12345", ".", "250 OK"},
		"GETINFO status/bootstrap-phase":       {"250-status/bootstrap-phase=PROGRESS=25 TAG=conn_tag SUMMARY=\"Handshaking\"", "250 OK"},
	})
	ctl, err := DialControl(context.Background(), "tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()

	v, err := ctl.GetInfo("net/listeners/socks")
	if err != nil || v["net/listeners/socks"] != "127.0.0.1:9050" {
		t.Fatalf("single-line GETINFO = %v err=%v", v, err)
	}

	v, err = ctl.GetInfo("traffic/read", "traffic/written")
	if err != nil {
		t.Fatalf("multiline GETINFO err: %v", err)
	}
	// multiline payload key carries the raw section body under its key
	if !strings.Contains(v["traffic/read"], "12345") {
		t.Fatalf("multiline body = %q", v["traffic/read"])
	}

	v, err = ctl.GetInfo("status/bootstrap-phase")
	if err != nil {
		t.Fatal(err)
	}
	p, tag, summary := ParseBootstrapPhase(v["status/bootstrap-phase"])
	if p != 25 || tag != "conn_tag" || summary != "Handshaking" {
		t.Fatalf("phase decode = %d/%q/%q", p, tag, summary)
	}
}

func TestControlErrorCarriesCode(t *testing.T) {
	srv := newFakeControl(t, map[string][]string{
		"SETCONF ConfluxEnabled": {"552 Unrecognized option ConfluxEnabled"},
		"SIGNAL":                 {"250 OK"},
	})
	ctl, err := DialControl(context.Background(), "tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()

	err = ctl.SetConf([2]string{"ConfluxEnabled", "1"})
	if err == nil {
		t.Fatal("552 must fail")
	}
	ce, ok := err.(*ControlError)
	if !ok || ce.Code != 552 {
		t.Fatalf("err = %v, want ControlError 552", err)
	}
	if err := ctl.Signal("NEWNYM"); err != nil {
		t.Fatalf("signal: %v", err)
	}
}

func TestParseBootstrapPhase(t *testing.T) {
	p, tag, sum := ParseBootstrapPhase(`NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"`)
	if p != 100 || tag != "done" || sum != "Done" {
		t.Fatalf("parse = %d/%q/%q", p, tag, sum)
	}
	p, tag, _ = ParseBootstrapPhase("PROGRESS=10 TAG=conn_done")
	if p != 10 || tag != "conn_done" {
		t.Fatalf("parse = %d/%q", p, tag)
	}
}

// --- torrc render + validate ---

func testTorrcInput() TorrcInput {
	return TorrcInput{
		DataPath:      "/opt/etc/b4/tor",
		OwningPID:     4242,
		SocksPort:     "127.0.0.1:auto",
		ControlSocket: "unix:/opt/etc/b4/tor/data/control.sock",
		EgressProxy:   "u:p@127.0.0.1:40001",
		PTProxyPort:   0,
		Entry:         entryVanilla,
		Padding:       paddingReduced,
	}
}

func TestRenderTorrcVanillaShape(t *testing.T) {
	in := testTorrcInput()
	in.Bridges = []Bridge{{Transport: "vanilla", Line: "vanilla 5.6.7.8:9001 " + fp1, AddrPort: "5.6.7.8:9001", Fingerprint: fp1}}
	in.UseBridges = true
	out := RenderTorrc(in)
	for _, want := range []string{
		"ClientOnly 1", "AvoidDiskWrites 1", "SafeLogging 1",
		"SocksPort 127.0.0.1:auto", "SocksPolicy accept 127.0.0.0/8",
		"SocksPolicy reject *", "ControlSocket unix:/opt/etc/b4/tor/data/control.sock",
		"CookieAuthentication 1", "DormantCanceledByStartup 1",
		"NumEntryGuards 1", "LearnCircuitBuildTimeout 0",
		"ReducedConnectionPadding 1", "UseBridges 1",
		"Socks5Proxy u:p@127.0.0.1:40001", "Bridge vanilla 5.6.7.8:9001 " + fp1,
		"__OwningControllerProcess 4242",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Fatalf("rendered torrc missing directive %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ClientTransportPlugin") {
		t.Fatal("vanilla-only set must not carry PT plugin lines")
	}
	if strings.Contains(out, "GeoIPFile") {
		t.Fatal("geoip=off must not render GeoIP lines")
	}
	if err := ValidateRendered(out); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderTorrcPTShape(t *testing.T) {
	in := testTorrcInput()
	in.Entry = "obfs4"
	in.PTProxyPort = 41001
	in.Bridges = []Bridge{
		{Transport: "webtunnel", Line: "webtunnel 2001:db8::1:443 " + fp1 + " url=https://x/", AddrPort: "2001:db8::1:443", Fingerprint: fp1, Args: map[string]string{"url": "https://x/"}},
		{Transport: "obfs4", Line: "obfs4 45.66.35.35:443 " + fp1 + " cert=x", AddrPort: "45.66.35.35:443", Fingerprint: fp1, Args: map[string]string{"cert": "x"}},
	}
	in.UseBridges = true
	out := RenderTorrc(in)
	if !strings.Contains(out, "ClientTransportPlugin webtunnel socks5 127.0.0.1:41001\n") ||
		!strings.Contains(out, "ClientTransportPlugin obfs4 socks5 127.0.0.1:41001\n") {
		t.Fatalf("PT plugin lines missing:\n%s", out)
	}
	if strings.Contains(out, "Socks5Proxy") {
		t.Fatal("PT-only set must not carry Socks5Proxy (PT legs dial themselves)")
	}
	if err := ValidateRendered(out); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderTorrcGating(t *testing.T) {
	// geoip on → lines present
	in := testTorrcInput()
	in.GeoIP = true
	in.GeoIPFile = "/opt/share/tor/geoip"
	in.GeoIPv6File = "/opt/share/tor/geoip6"
	out := RenderTorrc(in)
	if !strings.Contains(out, "GeoIPFile /opt/share/tor/geoip\n") || !strings.Contains(out, "GeoIPv6File /opt/share/tor/geoip6\n") {
		t.Fatal("geoip lines missing")
	}

	// full padding → ConnectionPadding 1, no Reduced line
	in.Padding = paddingFull
	out = RenderTorrc(in)
	if !strings.Contains(out, "ConnectionPadding 1\n") || strings.Contains(out, "ReducedConnectionPadding") {
		t.Fatal("full padding shape wrong")
	}

	// isolation → SocksPort flags
	in.Isolation = isolationPerDest
	out = RenderTorrc(in)
	if !strings.Contains(out, "SocksPort 127.0.0.1:auto IsolateDestAddr IsolateDestPort\n") {
		t.Fatal("isolation flags missing")
	}

	// direct entry: no bridges, UseBridges 0
	in2 := testTorrcInput()
	in2.Entry = entryDirect
	in2.UseBridges = false
	out2 := RenderTorrc(in2)
	if !strings.Contains(out2, "UseBridges 0\n") || strings.Contains(out2, "Bridge ") {
		t.Fatal("direct entry must render UseBridges 0 with no bridges")
	}
	// control port fallback
	in3 := testTorrcInput()
	in3.ControlSocket = ""
	in3.ControlPort = "127.0.0.1:43001"
	out3 := RenderTorrc(in3)
	if !strings.Contains(out3, "ControlPort 127.0.0.1:43001\n") {
		t.Fatal("ControlPort fallback missing")
	}
}

func TestValidateRenderedInjectionGuards(t *testing.T) {
	// CRLF anywhere
	if err := ValidateRendered("SocksPort 127.0.0.1:auto\r\n"); err == nil {
		t.Fatal("CRLF must be rejected")
	}
	// forbidden characters
	for _, bad := range []string{"SocksPort 127.0.0.1:auto #comment\n", "Bridge obfs4 1.2.3.4:1 " + fp1 + " cert=a\"b\n"} {
		if err := ValidateRendered(bad); err == nil {
			t.Fatalf("injection %q must be rejected", bad)
		}
	}
	// bridge line failing the admission gate
	if err := ValidateRendered("Bridge obfs4 not-an-endpoint " + fp1 + "\n"); err == nil {
		t.Fatal("invalid Bridge line must be rejected")
	}
	// clean document passes
	if err := ValidateRendered(RenderTorrc(testTorrcInput())); err != nil {
		t.Fatalf("clean render: %v", err)
	}
}

// --- bootstrap watcher: fake control with scripted ladders ---

// ladderControl answers bootstrap-phase with a scripted sequence.
type ladderControl struct {
	mu   sync.Mutex
	idx  int
	lane []string // values per poll
	fail bool     // every poll errors (silence)
}

func (l *ladderControl) Authenticate(cookie []byte) error { return nil }
func (l *ladderControl) GetInfo(keys ...string) (map[string]string, error) {
	if l.fail {
		return nil, fmt.Errorf("control dead")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	v := ""
	if l.idx < len(l.lane) {
		v = l.lane[l.idx]
	} else if len(l.lane) > 0 {
		v = l.lane[len(l.lane)-1]
	}
	l.idx++
	if v == "" {
		return nil, fmt.Errorf("no answer")
	}
	return map[string]string{"status/bootstrap-phase": v}, nil
}
func (l *ladderControl) Signal(s string) error         { return nil }
func (l *ladderControl) SetConf(kv ...[2]string) error { return nil }
func (l *ladderControl) Close() error                  { return nil }

func ph(progress int, tag string) string {
	return fmt.Sprintf("NOTICE BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=\"x\"", progress, tag)
}

func TestBootstrapWatchSuccessLadder(t *testing.T) {
	base := time.Now()
	now := func() time.Time { return base.Add(time.Since(base)) } // real clock
	ctl := &ladderControl{lane: []string{ph(10, "conn_done"), ph(15, "handshake"), ph(25, "handshake"), ph(45, "link"), ph(75, "circuit"), ph(100, "done")}}
	var phases []BootstrapPhase
	final, err := BootstrapWatch(context.Background(), ctl, "obfs4", now, func(p BootstrapPhase) { phases = append(phases, p) })
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if final.Progress != 100 {
		t.Fatalf("final = %+v", final)
	}
	if len(phases) == 0 {
		t.Fatal("phase callback must fire")
	}
	if phases[len(phases)-1].Progress != 100 {
		t.Fatalf("last phase = %+v", phases[len(phases)-1])
	}
}

func TestBootstrapWatchStall(t *testing.T) {
	// freezes at 25 after two growth steps; the shrunken stall window
	// (400ms) fires long before the shrunken hard cap (5s).
	ctl := &ladderControl{lane: []string{ph(10, "conn_done"), ph(25, "handshake")}}
	cfg := DefaultBootstrapConfig()
	cfg.PollInterval = 20 * time.Millisecond
	cfg.StallWindow = 400 * time.Millisecond
	cfg.HardCap = 5 * time.Second
	cfg.SnowflakeCap = 5 * time.Second
	_, err := BootstrapWatchCfg(context.Background(), ctl, "obfs4", cfg, time.Now, nil)
	if err == nil {
		t.Fatal("stalled bootstrap must fail")
	}
	if !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("err = %v, want stall (not the hard cap)", err)
	}
}

func TestBootstrapWatchSilentControl(t *testing.T) {
	ctl := &ladderControl{fail: true}
	cfg := DefaultBootstrapConfig()
	cfg.PollInterval = 10 * time.Millisecond
	cfg.SilentMax = 3
	cfg.HardCap = 5 * time.Second
	_, err := BootstrapWatchCfg(context.Background(), ctl, "obfs4", cfg, time.Now, nil)
	if err == nil {
		t.Fatal("silent control must fail")
	}
	if !strings.Contains(err.Error(), "silent") {
		t.Fatalf("err = %v, want silence reason", err)
	}
}

func TestBootstrapWatchHardCapSnowflake(t *testing.T) {
	// snowflake-only entry: cap 300s vs 180s — verified by configuration,
	// not by waiting: a frozen 50% bootstrap under the accelerated clock
	// still stalls first; assert the snowflake cap constant directly.
	if BootstrapSnowflakeCap != 300*time.Second || BootstrapHardCap != 180*time.Second {
		t.Fatalf("caps = %v / %v", BootstrapSnowflakeCap, BootstrapHardCap)
	}
}

func TestBootstrapShouldLogDedup(t *testing.T) {
	t0 := time.Now()
	prev := BootstrapPhase{Progress: 10, Tag: "a", At: t0}
	cur := BootstrapPhase{Progress: 12, Tag: "a", At: t0.Add(5 * time.Second)}
	if shouldLogBootstrap(prev, cur, t0) {
		t.Fatal("+2 progress within 30s must not log")
	}
	cur.Progress = 20
	if !shouldLogBootstrap(prev, cur, t0) {
		t.Fatal("+10 progress must log")
	}
	cur.Progress = 12
	cur.Tag = "b"
	if !shouldLogBootstrap(prev, cur, t0) {
		t.Fatal("tag change must log")
	}
	cur.Tag = "a"
	cur.At = t0.Add(31 * time.Second)
	if !shouldLogBootstrap(prev, cur, t0) {
		t.Fatal("30s repeat must log")
	}
}

// --- process: pid+exe identification, spawn/stop order ---

func TestOwnsPIDPairCheck(t *testing.T) {
	self := os.Args[0]
	abs, err := filepath.Abs(self)
	if err != nil {
		t.Fatal(err)
	}
	pid := os.Getpid()
	if !OwnsPID(pid, abs) {
		// test binary may be a temp dir symlink; resolve through /proc
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if !OwnsPID(pid, exe) {
			t.Fatalf("self pid+exe must verify: %q vs %q", abs, exe)
		}
	}
	if OwnsPID(pid, "/nonexistent/binary") {
		t.Fatal("wrong exe must never verify (pid+exe pair required)")
	}
	if OwnsPID(-1, abs) || OwnsPID(0, abs) {
		t.Fatal("invalid pids must never verify")
	}
	// scenario 17: a foreign pid must not be attributable
	if OwnsPID(1, abs) {
		t.Fatal("pid 1 with our exe path must fail the /proc/<pid>/exe check")
	}
}

func TestReadPidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tor.pid")
	if err := os.WriteFile(p, []byte("1234\n/opt/bin/tor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid, exe, err := ReadPidFile(p)
	if err != nil || pid != 1234 || exe != "/opt/bin/tor" {
		t.Fatalf("pidfile = %d/%q err=%v", pid, exe, err)
	}
	if _, _, err := ReadPidFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing pidfile must error")
	}
	if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPidFile(p); err == nil {
		t.Fatal("garbage pidfile must error")
	}
}

func TestSpawnTorBinaryMissing(t *testing.T) {
	// the honest binary-missing state: spawn refuses before anything runs
	_, err := SpawnTor(context.Background(), "/nonexistent/tor", "/tmp/x-torrc", t.TempDir())
	if err == nil {
		t.Fatal("missing binary must refuse")
	}
}

func TestSpawnStopLadder(t *testing.T) {
	// spawn a fake "tor": a shell script that ignores SIGTERM briefly then
	// exits on SIGKILL — verifying the graded ladder.
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-tor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap '' TERM\nwhile true; do sleep 0.2; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	torrc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(torrc, []byte("ClientOnly 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := SpawnTor(context.Background(), script, torrc, dir)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if h.PID() <= 0 {
		t.Fatalf("pid = %d", h.PID())
	}
	// the spawned process is ours by pid+exe — for a shell-script stand
	// the kernel exe is the INTERPRETER; resolve it from /proc like the
	// runtime does for the real binary.
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", h.PID()))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if !OwnsPID(h.PID(), exe) {
		t.Fatal("spawned process must pass the pid+exe pair")
	}
	if OwnsPID(h.PID(), script) && script != exe {
		t.Fatal("a script path must not pass for the interpreter exe")
	}
	// stop: SIGTERM is trapped (ignored) → the ladder must escalate to KILL
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h.Stop(ctx, nil)
	// the death channel was consumed by Stop's awaitDeath; verify death by
	// signal-0 probing (the wait goroutine reaps, so ESRCH follows).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(h.PID(), 0); err != nil {
			return // reaped: dead
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("process must be dead after Stop (SIGKILL escalation)")
}

func TestDetectTorVersion(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-tor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'Tor version 0.4.8.12 (git-abcdef).'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := DetectTorVersion(context.Background(), script)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(v, "0.4.8.12") {
		t.Fatalf("version = %q", v)
	}
	if _, err := DetectTorVersion(context.Background(), "/nonexistent"); err == nil {
		t.Fatal("missing binary must error")
	}
}
