// echprobe automates the L-steer v2 mechanics gate (bd b4x-p0.8) from a PC
// client (YOUTUBE_DATAPLANE.md §7, 22.08). It synthesizes the phone-shaped
// ClientHello via fixtures.BuildTLSClientHello and drives three plain-TCP
// steps against one googlevideo destination:
//
//	A steer     — ECH CH (~1800 B): b4 must RST us fast (CH never reaches
//	              the server, so the only possible reset is b4's).
//	B suppress  — fresh-tuple connect inside the client scope window must
//	              time out: the SYN is dropped silently by L-steer v2.
//	C clean     — after the window expires an ECH-free CH must NOT be
//	              steered or gated: no fast reset on the regular path.
//
// curl.exe is unusable as a probe ([00]-corrupted CH), hence this tool.
// Final UX verdict stays manual (.152 owner test) per project rules.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/daniellavrushin/b4/fixtures"
)

var (
	dstFlag    = flag.String("dst", "173.194.6.6:443", "googlevideo destination host:port")
	hostFlag   = flag.String("host", "rr1---sn-4g5edndd.googlevideo.com", "SNI used for classification")
	windowFlag = flag.Duration("window", 10*time.Second, "expected client-scope window (steerClientTTL)")
	rtoFlag    = flag.Duration("rto", 3*time.Second, "read/connect budget for single steps")
	sizeFlag   = flag.Int("size", 1800, "ECH ClientHello target size")
	splitFlag  = flag.Int("split", 1396, "first-segment size of the phone-like CH")
	// L-quicsynrst (Часть 2.6): step B expects an immediate refused-RST on a
	// fresh-tuple SYN instead of v2's silent drop.
	expectSynRstFlag = flag.Bool("expect-synrst", false, "step B waits for a fast refused-RST on the fresh-tuple SYN")
)

var verdicts = map[string]bool{"A-steer": false, "B-suppress": false, "C-clean": false}

func report(step string, pass bool, format string, args ...any) {
	verdicts[step] = pass
	fmt.Printf("[echprobe] step=%s result=%s %s\n", step, map[bool]string{true: "PASS", false: "FAIL"}[pass], fmt.Sprintf(format, args...))
}

func main() {
	flag.Parse()
	failed := false

	if *expectSynRstFlag {
		// L-quicsynrst flow: the arming CH itself goes through the regular
		// path (silence is expected and fine); arming is PROVEN by the next
		// fresh-tuple SYN receiving an immediate refused-RST.
		stepArmForSynRst()
		stepSuppress()
		remain := *windowFlag + time.Second
		fmt.Printf("[echprobe] waiting %v for client-scope expiry\n", remain.Round(time.Millisecond))
		time.Sleep(remain)
		stepClean()

		for _, ok := range verdicts {
			if !ok {
				failed = true
			}
		}
		if failed {
			fmt.Println("[echprobe] VERDICT=FAIL")
			os.Exit(1)
		}
		fmt.Println("[echprobe] VERDICT=PASS (synrst mechanics gate; final UX verdict is manual .152)")
		return
	}

	steerTS := stepSteer()
	if !verdicts["A-steer"] {
		report("B-suppress", false, "skipped: steering did not fire, scope cannot be armed")
		report("C-clean", false, "skipped: steering did not fire")
		fmt.Println("[echprobe] VERDICT=FAIL (A failed; B/C depend on it)")
		os.Exit(1)
	}

	stepSuppress()

	// Wait out the client-scope window armed at the A-step RST.
	remain := *windowFlag - time.Since(steerTS) + time.Second
	if remain < time.Second {
		remain = time.Second
	}
	fmt.Printf("[echprobe] waiting %v for client-scope expiry\n", remain.Round(time.Millisecond))
	time.Sleep(remain)

	stepClean()

	for _, ok := range verdicts {
		if !ok {
			failed = true
		}
	}
	if failed {
		fmt.Println("[echprobe] VERDICT=FAIL")
		os.Exit(1)
	}
	fmt.Println("[echprobe] VERDICT=PASS (mechanics gate; log [steer] markers checked separately; final UX verdict is manual .152)")
}

func dialBudget() (net.Conn, error) {
	return net.DialTimeout("tcp", *dstFlag, *rtoFlag)
}

// stepArmForSynRst sends the ECH CH of a fresh flow. In the quicsynrst build
// this flow is NOT reset — it classifies doomed and ARMS the client scope
// while proceeding through the regular holdch3 path. PASS = both CH segments
// were written; the read outcome (silence/timeout) is irrelevant here.
func stepArmForSynRst() time.Time {
	start := time.Now()
	conn, err := dialBudget()
	if err != nil {
		report("A-steer", false, "connect to %s failed: %v", *dstFlag, err)
		return start
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	ch := fixtures.BuildTLSClientHello(*hostFlag, 0x0304, true, *sizeFlag)
	if len(ch) <= *splitFlag {
		report("A-steer", false, "CH too small (%dB)", len(ch))
		return start
	}
	_ = conn.SetDeadline(start.Add(*rtoFlag))
	if _, err = conn.Write(ch[:*splitFlag]); err == nil {
		_, err = conn.Write(ch[*splitFlag:])
	}
	if err != nil {
		report("A-steer", false, "CH write failed after %v: %v", time.Since(start).Round(time.Millisecond), err)
		return start
	}
	_, _ = conn.Read(make([]byte, 1)) // doomed silence expected; outcome ignored
	report("A-steer", true, "arming CH sent (%dB split@%d) local=%s; scope assumed armed", len(ch), *splitFlag, local)
	return start
}

// stepSteer opens a connection and sends the ECH CH in two phone-like
// segments. PASS when the connection errors quickly (b4's spoofed RST); FAIL
// on silent read timeout (CH passed through unsteered) or connect failure.
func stepSteer() time.Time {
	start := time.Now()
	conn, err := dialBudget()
	if err != nil {
		report("A-steer", false, "connect to %s failed: %v", *dstFlag, err)
		return start
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	ch := fixtures.BuildTLSClientHello(*hostFlag, 0x0304, true, *sizeFlag)
	if len(ch) <= *splitFlag {
		report("A-steer", false, "CH too small (%dB)", len(ch))
		return start
	}
	_ = conn.SetDeadline(start.Add(*rtoFlag))
	if _, err = conn.Write(ch[:*splitFlag]); err == nil {
		_, err = conn.Write(ch[*splitFlag:])
	}
	elapsed := time.Since(start)
	buf := make([]byte, 1)
	if err == nil {
		_, err = conn.Read(buf)
	}
	switch {
	case err != nil && elapsed < *rtoFlag:
		report("A-steer", true, "reset after %v local=%s ch=%dB split@%d", elapsed.Round(time.Millisecond), local, len(ch), *splitFlag)
	case err != nil:
		report("A-steer", false, "late/odd error after %v: %v", elapsed.Round(time.Millisecond), err)
	default:
		report("A-steer", false, "no reset within %v — CH was not steered", *rtoFlag)
	}
	return start
}

// stepSuppress immediately reconnects with a fresh tuple.
//
// Default (L-steer v2): inside the armed window the SYN must die silently —
// connect timeout, not success and not a reset from anything else.
//
// --expect-synrst (L-quicsynrst): the SYN must be answered with a fast
// refused-RST: connect fails quickly (<1 s) with a non-timeout error, and
// definitely not success and not a silent timeout.
func stepSuppress() {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", *dstFlag, *rtoFlag)
	if err == nil {
		local := conn.LocalAddr().String()
		conn.Close()
		report("B-suppress", false, "fresh-tuple connect SUCCEEDED (%s) after %v — scope did not gate the SYN", local, time.Since(start).Round(time.Millisecond))
		return
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		if *expectSynRstFlag {
			report("B-suppress", false, "connect timed out after %v — silent drop, refused-RST never arrived", time.Since(start).Round(time.Millisecond))
			return
		}
		report("B-suppress", true, "connect timed out after %v — SYN dropped silently", time.Since(start).Round(time.Millisecond))
		return
	}
	if *expectSynRstFlag {
		if elapsed := time.Since(start); elapsed <= time.Second {
			report("B-suppress", true, "refused-RST after %v (%v) — connection-refused semantics confirmed", elapsed.Round(time.Millisecond), err)
			return
		}
		report("B-suppress", false, "late refusal after %v (%v) — RST was not immediate", time.Since(start).Round(time.Millisecond), err)
		return
	}
	report("B-suppress", false, "unexpected connect error after %v: %v", time.Since(start).Round(time.Millisecond), err)
}

// stepClean sends an ECH-free CH after the window expired. The regular
// fake+combo path must proceed: no fast reset within the read budget.
func stepClean() {
	start := time.Now()
	conn, err := dialBudget()
	if err != nil {
		report("C-clean", false, "connect after expiry failed: %v", err)
		return
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	ch := fixtures.BuildTLSClientHello(*hostFlag, 0x0304, false, 776)
	_ = conn.SetDeadline(start.Add(2 * time.Second))
	writeErr := error(nil)
	readErr := error(nil)
	if _, writeErr = conn.Write(ch); writeErr == nil {
		// Expected outcomes inside the budget: silence (timeout) or
		// handshake bytes from the regular path. Any other error means the
		// connection was reset — i.e. steering leaked to a clean flow.
		_, readErr = conn.Read(make([]byte, 1))
	}
	reset := writeErr != nil || (readErr != nil && !isTimeout(readErr))
	if reset {
		report("C-clean", false, "reset on ECH-free CH after %v local=%s (write=%v read=%v) — steering leaked to clean flows",
			time.Since(start).Round(time.Millisecond), local, writeErr, readErr)
		return
	}
	report("C-clean", true, "no reset on ECH-free CH local=%s read=%v (regular path untouched)", local, readErr)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
