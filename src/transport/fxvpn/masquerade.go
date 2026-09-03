// Masquerade layer for the Firefox VPN reserve transport (review chapter 7,
// stage FX-M0). Unlike Opera, the fxvpn control plane is already partly
// self-masqueraded (UA MozillaVPN, the Fastly PoW cookie even helps) and the
// edge SNI is the REAL Fastly node name — so this layer focuses on the two
// signatures the TSPU actually has left: the QUIC/TLS ClientHello
// fingerprint and the "first datagram of the flow" statistics.
//
// Mechanisms shipped here:
//
//   - Firefox-shaped ClientHello via the plain Go stack (§7.4.3): the
//     cipher-suite and curve offer, ALPN discipline and the Initial padding
//     tuned to the Firefox profile. Extension ORDER stays Go — that is what
//     the uTLS layer (FX-M1) exists for; this rung removes the crudest
//     differences and stays the fallback when uTLS is off.
//   - QUIC pre-flight fake with TTL (§7.4.1, the "I1 for H3" — the MAIN
//     mechanism): BEFORE the real Initial, 1-2 RFC-9001-accurate QUIC
//     Initials carrying a WHITE SNI leave the same 5-tuple on a throwaway
//     socket with a small TTL. The DPI's flow classifier reads the white
//     SNI; the datagram dies in transit — Fastly never sees it, so
//     compatibility is total. UDP-only by red line 2 (no TTL tricks on
//     live TCP); the fake never replaces or touches the real handshake
//     (red line 1), the WebPKI/pin trust anchors stay untouched (§7.4.0).
//
// Control plane stays untouched (§7.4.5): UA MozillaVPN + PoW cookie +
// WebPKI to the public Mozilla hosts is the most legitimate profile there is.
package fxvpn

import (
        "context"
        crand "crypto/rand"
        "crypto/sha256"
        "crypto/tls"
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "net"
        "strings"
        "time"

        quici1 "github.com/daniellavrushin/b4/transport/quici1"
)

// MasqueradeProfile selects the masquerade ladder step (§7.3 config model).
type MasqueradeProfile string

const (
        // MasqueradeFirefox: full masquerade — Firefox-shaped hello (cheap layer
        // + uTLS at FX-M1), QUIC preflight bait when configured.
        MasqueradeFirefox MasqueradeProfile = "firefox"
        // MasqueradeGoPlain: the explicit plain-Go rung of the ladder (no
        // fingerprint layer, no bait) — the fallback when the shaped hello
        // breaks a path.
        MasqueradeGoPlain MasqueradeProfile = "go-plain"
        // MasqueradeOff: identical wire behavior to go-plain at the transport
        // layer; the name exists so the config model matches the review 1:1.
        MasqueradeOff MasqueradeProfile = "off"
)

// Default fake-SNI pool (§7.4.1 "белый пул"): Mozilla-owned names a
// Firefox install legitimately talks to, so the bait Initial is
// indistinguishable from everyday Firefox noise on the wire. Override via
// config masquerade.fake_sni_pool.
var defaultFakeSNI = []string{
        "detectportal.firefox.com",
        "content-signature-2.cdn.mozilla.net",
        "firefox.settings.services.mozilla.com",
        "incoming.telemetry.mozilla.org",
        "aus5.mozilla.org",
}

// MasqueradeSettings is the resolved engine-side masquerade state.
type MasqueradeSettings struct {
        Profile MasqueradeProfile
        // Fingerprint selects the ClientHello producer (§7.4.3/FX-M1):
        // "firefox" (default — uTLS HelloFirefox_Auto on the H2 carrier),
        // "none" (plain Go TLS — the ladder fallback rung).
        Fingerprint string
        // PreflightFake sends the TTL-limited QUIC-Initial bait before the real
        // QUIC handshake (H3 only; UDP-only per red line 2).
        PreflightFake bool
        // FakeSNI is the white-SNI pool of the bait.
        FakeSNI []string
        // FakeTTL is the bait's hop limit (2-8 typical: must cover the hops to
        // the DPI but NOT to Fastly — typically 8+ hops away).
        FakeTTL int
        // FakeCount is how many bait datagrams precede the real handshake (1-2).
        FakeCount int
        // InitialPadding is the QUIC InitialPacketSize (Firefox pads to
        // ~1200-1250; the constant 1200 was itself a marker, review §7.4.3).
        InitialPadding int
        // HelloShaping applies the Firefox cipher/curve offer to the plain-Go
        // TLS configs (H2 + QUIC).
        HelloShaping bool
}

// DefaultMasquerade returns the shipping defaults (§7.3): the firefox
// profile with hello shaping and 1250 padding; the bait is config-gated
// (it needs a calibrated TTL).
func DefaultMasquerade() MasqueradeSettings {
        return MasqueradeSettings{
                Profile:        MasqueradeFirefox,
                Fingerprint:    FingerprintFirefox,
                FakeSNI:        append([]string(nil), defaultFakeSNI...),
                FakeTTL:        4,
                FakeCount:      2,
                InitialPadding: quici1.PadTo,
                HelloShaping:   true,
        }
}

// ResolveMasquerade folds the config section into engine settings (the
// config layer validates shapes; this layer owns semantics and defaults).
// helloShaping nil = profile default (enabled for firefox, disabled for the
// plain rungs).
func ResolveMasquerade(profile string, preflight bool, sniPool []string, fakeTTL, fakeCount, initialPadding int, helloShaping *bool) MasqueradeSettings {
        m := DefaultMasquerade()
        switch MasqueradeProfile(strings.ToLower(strings.TrimSpace(profile))) {
        case MasqueradeGoPlain, MasqueradeOff:
                m.Profile = MasqueradeProfile(strings.ToLower(strings.TrimSpace(profile)))
                m.Fingerprint = FingerprintNone
                m.HelloShaping = false
                m.PreflightFake = false
                return m
        case "", MasqueradeFirefox:
                // defaults hold
        default:
                // validated upstream; unknown falls back to firefox
        }
        m.PreflightFake = preflight
        if len(sniPool) > 0 {
                m.FakeSNI = normalizeSNI(sniPool)
        }
        if fakeTTL > 0 {
                m.FakeTTL = fakeTTL
        }
        if fakeCount > 0 {
                m.FakeCount = fakeCount
        }
        if initialPadding >= 1200 && initialPadding <= 1400 {
                m.InitialPadding = initialPadding
        }
        if helloShaping != nil {
                m.HelloShaping = *helloShaping
        }
        return m
}

func normalizeSNI(pool []string) []string {
        out := make([]string, 0, len(pool))
        seen := make(map[string]struct{}, len(pool))
        for _, n := range pool {
                n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
                if n == "" {
                        continue
                }
                if _, ok := seen[n]; ok {
                        continue
                }
                seen[n] = struct{}{}
                out = append(out, n)
        }
        return out
}

// EffectiveFakeSNI resolves the bait SNI for one node: a stable pick from
// the white pool (SHA-256 truncated — deterministic, uniformly distributed,
// sticky per node so one flow never sees two different baits).
func (m MasqueradeSettings) EffectiveFakeSNI(nodeKey string) string {
        if len(m.FakeSNI) == 0 {
                return ""
        }
        sum := sha256.Sum256([]byte(nodeKey))
        return m.FakeSNI[int(binary.BigEndian.Uint32(sum[:4])%uint32(len(m.FakeSNI)))]
}

// firefoxCipherSuites mirrors the Firefox TLS 1.2 offer order (§7.4.3):
// AES-128-GCM first, CHACHA20 next, AES-256-GCM last. TLS 1.3 suites are
// not configurable in Go and coincide with Firefox.
var firefoxCipherSuites = []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// firefoxCurves mirrors the Firefox key-share order.
var firefoxCurves = []tls.CurveID{
        tls.X25519,
        tls.CurveP256,
        tls.CurveP384,
}

// ApplyHelloShaping folds the Firefox cipher/curve offer into a TLS config
// (caller owns ALPN/ServerName/verification semantics).
func (m MasqueradeSettings) ApplyHelloShaping(cfg *tls.Config) {
        if cfg == nil || !m.HelloShaping || m.Profile != MasqueradeFirefox {
                return
        }
        cfg.CipherSuites = firefoxCipherSuites
        cfg.CurvePreferences = firefoxCurves
}

// sendPreflightFake is the bait injection seam (tests pin the datagrams);
// the production implementation dials a throwaway TTL-limited socket.
type preflightSender func(payloads [][]byte, raddr *net.UDPAddr, policy DialPolicy, network string) error

// sendPreflightReal opens ONE throwaway UDP socket with the bait TTL, fires
// the fake Initials and closes it. The real carrier socket is untouched —
// the fake never rides the live flow (red line 2) and never reaches the
// server (TTL dies in transit).
func sendPreflightReal(payloads [][]byte, raddr *net.UDPAddr, policy DialPolicy, network string) error {
        bait := DialPolicy{TTL: policy.TTL}
        uc, err := bait.ListenUDP(context.Background(), network, ":0")
        if err != nil {
                return fmt.Errorf("fxvpn: preflight bait socket: %w", err)
        }
        defer uc.Close()
        for _, p := range payloads {
                if _, err := uc.WriteToUDP(p, raddr); err != nil {
                        return fmt.Errorf("fxvpn: preflight bait send: %w", err)
                }
        }
        return nil
}

// preflightFakeInitials builds 1-2 RFC-accurate fake Initials with the
// white SNI (review §7.4.1 step 2; empty pool/SNI => no bait).
func preflightFakeInitials(m MasqueradeSettings, nodeKey string, n int) [][]byte {
        sni := m.EffectiveFakeSNI(nodeKey)
        if sni == "" || n <= 0 {
                return nil
        }
        out := make([][]byte, 0, n)
        for i := 0; i < n; i++ {
                raw := quici1.Build(sni, nil)
                if raw == "" {
                        return nil
                }
                // Strip the AmneziaWG grammar to raw bytes for the direct UDP write.
                hexPart := strings.TrimSuffix(strings.TrimPrefix(raw, "<b 0x"), ">")
                payload, err := hex.DecodeString(hexPart)
                if err != nil || len(payload) == 0 {
                        return nil
                }
                out = append(out, payload)
        }
        return out
}

// baitGap returns the randomized 0-50ms spacing between bait datagrams
// (§7.4.1: breaks per-flow first-packet statistics timing).
func baitGap() time.Duration {
        var b [2]byte
        if _, err := crand.Read(b[:]); err != nil {
                return 0
        }
        return time.Duration(binary.BigEndian.Uint16(b[:])%51) * time.Millisecond
}
