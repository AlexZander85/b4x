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

type fakeControlServer struct {
	ln      net.Listener
	mu      sync.Mutex
	lastCmd []string
	script  map[string][]string
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
	srv := newFakeControl(t, map[string][]string{"AUTHENTICATE": {"250 OK"}})
	ctl, err := DialControl(context.Background(), "tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	if err := ctl.Authenticate([]byte{0xAB, 0xCD, 0xEF}); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	cmds := srv.commands()
	if len(cmds) != 1 || cmds[0] != "AUTHENTICATE abcdef" {
		t.Fatalf("wire = %v", cmds)
	}
}

func TestUnquoteControlValue(t *testing.T) {
	cases := map[string]string{
		`"127.0.0.1:9050"`:        "127.0.0.1:9050",
		`127.0.0.1:9050`:          "127.0.0.1:9050",
		`PROGRESS=25 SUMMARY="x"`: `PROGRESS=25 SUMMARY="x"`,
		`""`:                      "",
	}
	for in, want := range cases {
		if got := unquoteControlValue(in); got != want {
			t.Errorf("unquoteControlValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestControlGetInfoSingleAndMultiline(t *testing.T) {
	srv := newFakeControl(t, map[string][]string{
		"GETINFO net/listeners/socks": {"250-net/listeners/socks=\"127.0.0.1:9050\"", "250 OK"},
		"GETINFO traffic/read traffic/written": {
			"250+traffic/read=", "12345", ".", "250-traffic/written=67890", "250 OK",
		},
		"GETINFO status/bootstrap-phase": {"250-status/bootstrap-phase=PROGRESS=25 TAG=conn_tag SUMMARY=\"Handshaking\"", "250 OK"},
	})
	ctl, err := DialControl(context.Background(), "tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()

	v, err := ctl.GetInfo("net/listeners/socks")
	if err != nil || v["net/listeners/socks"] != "127.0.0.1:9050" {
		t.Fatalf("single GETINFO = %v err=%v", v, err)
	}
	v, err = ctl.GetInfo("traffic/read", "traffic/written")
	if err != nil {
		t.Fatal(err)
	}
	if v["traffic/read"] != "12345" || v["traffic/written"] != "67890" {
		t.Fatalf("multiline boundaries lost: %#v", v)
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
}

func testTorrcInput() TorrcInput {
	return TorrcInput{
		DataPath: "/opt/etc/b4/tor", OwningPID: 4242,
		SocksPort:       "127.0.0.1:auto",
		ControlSocket:   "/opt/etc/b4/tor/data/control.sock",
		EgressProxyAddr: "127.0.0.1:40001", EgressProxyUsername: "u", EgressProxyPassword: "p",
		Entry: entryVanilla, Padding: paddingReduced,
	}
}

func TestRenderTorrcVanillaShape(t *testing.T) {
	in := testTorrcInput()
	in.Bridges = []Bridge{{Transport: "vanilla", Line: "vanilla 5.6.7.8:9001 " + fp1, AddrPort: "5.6.7.8:9001", Fingerprint: fp1}}
	in.UseBridges = true
	out := RenderTorrc(in)
	for _, want := range []string{
		"ClientOnly 1", "AvoidDiskWrites 1", "SafeLogging 1",
		"SocksPort 127.0.0.1:auto", "SocksPolicy accept 127.0.0.0/8", "SocksPolicy reject *",
		"ControlSocket /opt/etc/b4/tor/data/control.sock", "CookieAuthentication 1",
		"ReducedConnectionPadding 1", "UseBridges 1",
		"Socks5Proxy 127.0.0.1:40001", "Socks5ProxyUsername u", "Socks5ProxyPassword p",
		"Bridge 5.6.7.8:9001 " + fp1, "__OwningControllerProcess 4242",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Fatalf("rendered torrc missing %q:\n%s", want, out)
		}
	}
	for _, forbidden := range []string{"ControlSocket unix:", "Socks5Proxy u:p@", "Bridge vanilla "} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("invalid legacy torrc form leaked: %q\n%s", forbidden, out)
		}
	}
	if err := ValidateRendered(out); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderTorrcLegacyProxyInputCanonicalized(t *testing.T) {
	in := testTorrcInput()
	in.EgressProxyAddr, in.EgressProxyUsername, in.EgressProxyPassword = "", "", ""
	in.EgressProxy = "legacy:secret@127.0.0.1:40123"
	in.ControlSocket = "unix:/tmp/tor-control.sock"
	out := RenderTorrc(in)
	for _, want := range []string{
		"ControlSocket /tmp/tor-control.sock\n",
		"Socks5Proxy 127.0.0.1:40123\n",
		"Socks5ProxyUsername legacy\n",
		"Socks5ProxyPassword secret\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("legacy input not canonicalized: want %q\n%s", want, out)
		}
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
		t.Fatal("PT-only set must not carry Socks5Proxy")
	}
	if err := ValidateRendered(out); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderTorrcGating(t *testing.T) {
	in := testTorrcInput()
	in.GeoIP = true
	in.GeoIPFile = "/opt/share/tor/geoip"
	in.GeoIPv6File = "/opt/share/tor/geoip6"
	out := RenderTorrc(in)
	if !strings.Contains(out, "GeoIPFile /opt/share/tor/geoip\n") || !strings.Contains(out, "GeoIPv6File /opt/share/tor/geoip6\n") {
		t.Fatal("geoip lines missing")
	}
	in.Padding = paddingFull
	out = RenderTorrc(in)
	if !strings.Contains(out, "ConnectionPadding 1\n") || strings.Contains(out, "ReducedConnectionPadding") {
		t.Fatal("full padding shape wrong")
	}
	in.Isolation = isolationPerDest
	out = RenderTorrc(in)
	if !strings.Contains(out, "SocksPort 127.0.0.1:auto IsolateDestAddr IsolateDestPort\n") {
		t.Fatal("isolation flags missing")
	}
	in2 := testTorrcInput()
	in2.Entry = entryDirect
	in2.UseBridges = false
	out2 := RenderTorrc(in2)
	if !strings.Contains(out2, "UseBridges 0\n") || strings.Contains(out2, "Bridge ") {
		t.Fatal("direct entry shape wrong")
	}
	in3 := testTorrcInput()
	in3.ControlSocket = ""
	in3.ControlPort = "127.0.0.1:43001"
	out3 := RenderTorrc(in3)
	if !strings.Contains(out3, "ControlPort 127.0.0.1:43001\n") {
		t.Fatal("ControlPort fallback missing")
	}
}

func TestValidateRenderedInjectionGuards(t *testing.T) {
	if err := ValidateRendered("SocksPort 127.0.0.1:auto\r\n"); err == nil {
		t.Fatal("CRLF must be rejected")
	}
	for _, bad := range []string{"SocksPort 127.0.0.1:auto #comment\n", "Bridge obfs4 1.2.3.4:1 " + fp1 + " cert=a\"b\n"} {
		if err := ValidateRendered(bad); err == nil {
			t.Fatalf("injection %q must be rejected", bad)
		}
	}
	if err := ValidateRendered("Bridge obfs4 not-an-endpoint " + fp1 + "\n"); err == nil {
		t.Fatal("invalid Bridge line must be rejected")
	}
	if err := ValidateRendered(RenderTorrc(testTorrcInput())); err != nil {
		t.Fatalf("clean render: %v", err)
	}
}

type ladderControl struct {
	mu   sync.Mutex
	idx  int
	lane []string
	fail bool
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
	now := func() time.Time { return base.Add(time.Since(base)) }
	ctl := &ladderControl{lane: []string{ph(10, "conn_done"), ph(15, "handshake"), ph(25, "handshake"), ph(45, "link"), ph(75, "circuit"), ph(100, "done")}}
	var phases []BootstrapPhase
	final, err := BootstrapWatch(context.Background(), ctl, "obfs4", now, func(p BootstrapPhase) { phases = append(phases, p) })
	if err != nil || final.Progress != 100 || len(phases) == 0 {
		t.Fatalf("watch final=%+v phases=%d err=%v", final, len(phases), err)
	}
}

func TestBootstrapWatchStall(t *testing.T) {
	ctl := &ladderControl{lane: []string{ph(10, "conn_done"), ph(25, "handshake")}}
	cfg := DefaultBootstrapConfig()
	cfg.PollInterval = 20 * time.Millisecond
	cfg.StallWindow = 400 * time.Millisecond
	cfg.HardCap = 5 * time.Second
	cfg.SnowflakeCap = 5 * time.Second
	_, err := BootstrapWatchCfg(context.Background(), ctl, "obfs4", cfg, time.Now, nil)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("want stalled, got %v", err)
	}
}

func TestBootstrapWatchSilentControl(t *testing.T) {
	ctl := &ladderControl{fail: true}
	cfg := DefaultBootstrapConfig()
	cfg.PollInterval = 10 * time.Millisecond
	cfg.SilentMax = 3
	cfg.HardCap = 5 * time.Second
	_, err := BootstrapWatchCfg(context.Background(), ctl, "obfs4", cfg, time.Now, nil)
	if err == nil || !strings.Contains(err.Error(), "silent") {
		t.Fatalf("want silent, got %v", err)
	}
}

func TestBootstrapWatchHardCapSnowflake(t *testing.T) {
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
}

func TestOwnsPIDPairCheck(t *testing.T) {
	pid := os.Getpid()
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Skipf("/proc unavailable: %v", err)
	}
	if !OwnsPID(pid, exe) {
		t.Fatalf("self pid+exe must verify: %q", exe)
	}
	if OwnsPID(pid, "/nonexistent/binary") || OwnsPID(-1, exe) || OwnsPID(0, exe) {
		t.Fatal("wrong exe/invalid pid must never verify")
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
}

func TestSpawnTorBinaryMissing(t *testing.T) {
	_, err := SpawnTor(context.Background(), "/nonexistent/tor", "/tmp/x-torrc", t.TempDir())
	if err == nil {
		t.Fatal("missing binary must refuse")
	}
}

func TestSpawnStopLadder(t *testing.T) {
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
	pid := h.PID()
	if pid <= 0 || !h.Alive() {
		t.Fatalf("pid=%d alive=%t", pid, h.Alive())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h.Stop(ctx, nil)
	if h.Alive() {
		t.Fatal("process must not remain alive after Stop")
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatal("reaped process must not answer signal 0")
	}
}

func TestDetectTorVersion(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-tor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'Tor version 0.4.8.12 (git-abcdef).'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := DetectTorVersion(context.Background(), script)
	if err != nil || !strings.Contains(v, "0.4.8.12") {
		t.Fatalf("version=%q err=%v", v, err)
	}
}
