package tor

// torrc renderer (patch-plan §7.3, design §7.4): a PURE function of the
// render input — regenerated on every start, validated before it ever
// touches disk. The tessera/torware canon encoded here:
//
//   - CRLF is forbidden anywhere (a config-file injection);
//   - `\`, `#`, `"` are forbidden (the bridge parser already rejects them
//     in lines; ValidateRendered re-checks the WHOLE rendered output);
//   - every Bridge line goes back through ParseBridgeLine (the admission
//     gate is absolute — even for our own rendering);
//   - transport tokens on Bridge lines must equal the registered PT names;
//   - paths ride argv, only the owning-controller pid and functional
//     directives live in the file;
//   - GeoIP lines only when Speed.GeoIP is on (26 MB of parsing otherwise);
//   - Socks5Proxy only for vanilla/direct sets (PT legs dial themselves);
//   - PT plugin lines only for PT entries in the set.

import (
	"fmt"
	"strings"
)

// Padding / isolation names (the config enums live in src/config —
// importing it from here would close a cycle).
const (
	paddingReduced   = "reduced"
	paddingFull      = "full"
	isolationPerDest = "per-destination"
)

// TorrcInput is the render input (the service layer assembles it from the
// config + runtime ports/pids).
type TorrcInput struct {
	// DataPath is the tor state slot (DataDirectory + control cookie live
	// under it).
	DataPath string
	// OwningPID is b4's pid for __OwningControllerProcess (b4 death = tor
	// death — the owning-controller contract).
	OwningPID int
	// SocksPort is the resolved socks listener ("127.0.0.1:auto").
	SocksPort string
	// ControlSocket is the unix control socket path ("unix:<path>") or
	// empty when a ControlPort is used instead.
	ControlSocket string
	// ControlPort is the resolved TCP control listener (used when unix
	// sockets are unavailable).
	ControlPort string
	// EgressProxy is the "user:pass@127.0.0.1:port" of the egress bridge
	// (empty = no Socks5Proxy directive — PT-only sets).
	EgressProxy string
	// PTProxyPort is the loopback PT proxy port for the
	// ClientTransportPlugin directives (0 = no PT in the set).
	PTProxyPort int
	// Bridges is the active bridge set (already admission-parsed).
	Bridges []Bridge
	// UseBridges: 1 when the set is non-empty (vanilla/direct carry it too
	// — vanilla relays ARE bridges here), 0 for the direct entry.
	UseBridges bool
	// Entry selects per-transport rendering policy.
	Entry string // entryVanilla | entryDirect | PT kinds
	// Padding is TorPaddingReduced|TorPaddingFull.
	Padding string
	// GeoIP enables the GeoIPFile lines (off by default — a client that
	// does not pick exit countries does not need the tables).
	GeoIP bool
	// GeoIPFile / GeoIPv6File are the table paths when GeoIP is on.
	GeoIPFile   string
	GeoIPv6File string
	// Isolation adds the SocksPort isolation flags (per-destination opt-in).
	Isolation string // ""|TorIsolationPerDestination
}

// RenderTorrc renders the torrc document (pure function).
func RenderTorrc(in TorrcInput) string {
	var b strings.Builder
	b.WriteString("# Written by b4x E-TOR. Regenerated on every start.\n")
	b.WriteString("ClientOnly 1\n")
	b.WriteString("AvoidDiskWrites 1\n")
	b.WriteString("SafeLogging 1\n")
	socksLine := "SocksPort " + in.SocksPort
	switch in.Isolation {
	case isolationPerDest:
		socksLine += " IsolateDestAddr IsolateDestPort"
	}
	b.WriteString(socksLine + "\n")
	b.WriteString("SocksPolicy accept 127.0.0.0/8\n")
	b.WriteString("SocksPolicy reject *\n")
	if in.ControlSocket != "" {
		b.WriteString("ControlSocket " + in.ControlSocket + "\n")
	} else if in.ControlPort != "" {
		b.WriteString("ControlPort " + in.ControlPort + "\n")
	}
	b.WriteString("CookieAuthentication 1\n")
	b.WriteString("CookieAuthFile " + in.DataPath + "/data/control.cookie\n")
	b.WriteString("DormantCanceledByStartup 1\n")
	b.WriteString("NumEntryGuards 1\n")
	b.WriteString("LearnCircuitBuildTimeout 0\n")
	padding := in.Padding
	if padding == "" {
		padding = paddingReduced
	}
	switch padding {
	case paddingFull:
		b.WriteString("ConnectionPadding 1\n")
	default:
		b.WriteString("ReducedConnectionPadding 1\n")
	}
	if in.UseBridges {
		b.WriteString("UseBridges 1\n")
	} else {
		b.WriteString("UseBridges 0\n")
	}
	// Socks5Proxy: only for vanilla/direct sets — the PT legs dial through
	// the in-process PT proxy and never touch the egress bridge.
	if in.EgressProxy != "" && (in.Entry == entryVanilla || in.Entry == entryDirect) {
		b.WriteString("Socks5Proxy " + in.EgressProxy + "\n")
	}
	// PT plugin lines: one per DISTINCT transport present in the set.
	if in.PTProxyPort > 0 {
		seen := map[string]bool{}
		for _, br := range in.Bridges {
			if br.Transport == "vanilla" {
				continue
			}
			if seen[br.Transport] {
				continue
			}
			seen[br.Transport] = true
			b.WriteString(fmt.Sprintf("ClientTransportPlugin %s socks5 127.0.0.1:%d\n", br.Transport, in.PTProxyPort))
		}
	}
	for _, br := range in.Bridges {
		b.WriteString("Bridge " + br.Line + "\n")
	}
	if in.GeoIP && in.GeoIPFile != "" {
		b.WriteString("GeoIPFile " + in.GeoIPFile + "\n")
		if in.GeoIPv6File != "" {
			b.WriteString("GeoIPv6File " + in.GeoIPv6File + "\n")
		}
	}
	if in.OwningPID > 0 {
		b.WriteString(fmt.Sprintf("__OwningControllerProcess %d\n", in.OwningPID))
	}
	return b.String()
}

// ValidateRendered re-checks the rendered document against the injection
// contract (tessera canon: validation is a separate pass, testable against
// `tor --verify-config`).
func ValidateRendered(s string) error {
	if strings.Contains(s, "\r") {
		return fmt.Errorf("torrc validation: CR present (CRLF injection guard)")
	}
	// full-line comments are the torrc convention (our own header uses
	// one); the character ban covers DIRECTIVE lines only — a value
	// carrying '\', '#' or '"' is an injection, a comment is a comment.
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, bad := range []string{"\\", "#", "\""} {
			if strings.Contains(line, bad) {
				return fmt.Errorf("torrc validation: forbidden character %q in %q", bad, trimmed)
			}
		}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Bridge ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Bridge "))
			if rest == "" {
				return fmt.Errorf("torrc validation: empty Bridge line")
			}
			b, err := ParseBridgeLine(rest)
			if err != nil {
				return fmt.Errorf("torrc validation: Bridge line rejected: %v", err)
			}
			if b.Transport != "vanilla" && !KnownTransport(b.Transport) {
				return fmt.Errorf("torrc validation: transport %q has no plugin", b.Transport)
			}
		}
	}
	return nil
}
