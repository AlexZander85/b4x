// Command warpscan scans the b4x WG endpoint catalog for verified cf-warp
// endpoints (warp-plus/nova-go lineage): a full-cycle LCG walks the catalog
// ranges, every candidate gets a Noise-IK handshake probe, and a HIT is an
// endpoint that answered with an AUTHENTICATED type-2 response — not
// "something listens".
//
//	warpscan --config cfg.json
//	warpscan --config cfg.json --limit 20 --workers 8 --max-rtt 800ms
//	warpscan --private-key <b64> --peer-key <b64> --reserved <b64-3B>
//
// Keys come from the warp WG identity slot when --config is used; they can
// also be passed explicitly for field diagnostics on a laptop. Output: one
// "addr:port|rtt_ms" per line, sorted by RTT (the Android-shaped parsers
// read exactly this), plus a stats tail on stderr.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

func main() {
	fs := flag.NewFlagSet("warpscan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to config json (identity slot resolution)")
	privB64 := fs.String("private-key", "", "base64 WireGuard private key (overrides config)")
	peerB64 := fs.String("peer-key", "", "base64 peer static public key (overrides config)")
	reservedB64 := fs.String("reserved", "", "base64 cf-warp client_id bytes (<=3, optional)")
	prefixFlag := fs.String("prefix", "", "comma-separated CIDR prefixes to scan (default: catalog ZT v4)")
	portsFlag := fs.String("ports", "", "comma-separated ports to scan (default: core + extended)")
	limit := fs.Int("limit", twg.DefaultWarpScanLimit, "stop after this many verified hits")
	workers := fs.Int("workers", twg.DefaultWarpScanWorkers, "concurrent probes")
	maxRTT := fs.Duration("max-rtt", twg.DefaultWarpScanMaxRTT, "discard hits slower than this")
	timeout := fs.Duration("timeout", 120*time.Second, "overall scan budget")
	allowOutOfCatalog := fs.Bool("allow-out-of-catalog", false, "escape catalog gate for field probes")
	connectEndpoint := fs.String("connect", "", "run a live session against endpoint (ip:port)")
	profileFlag := fs.String("profile", "quic-a", "obfuscation profile for connect: quic-a, quic-b, sip-invite, crlf-light, crlf-aggressive, vanilla-off")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	priv, peer, reserved, err := resolveKeys(*cfgPath, *privB64, *peerB64, *reservedB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warpscan:", err)
		os.Exit(2)
	}

	if *connectEndpoint != "" {
		runConnectSession(*connectEndpoint, *profileFlag, *cfgPath, priv, peer, reserved, *timeout)
		return
	}

	var prefixes []netip.Prefix
	if *prefixFlag != "" {
		for _, s := range strings.Split(*prefixFlag, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				ip, iperr := netip.ParseAddr(s)
				if iperr != nil {
					fmt.Fprintf(os.Stderr, "bad prefix %q: %v\n", s, err)
					os.Exit(2)
				}
				p = netip.PrefixFrom(ip, 32)
			}
			prefixes = append(prefixes, p)
		}
	}
	var ports []uint16
	if *portsFlag != "" {
		for _, s := range strings.Split(*portsFlag, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			var p uint16
			if _, err := fmt.Sscanf(s, "%d", &p); err == nil && p > 0 {
				ports = append(ports, p)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	hits, stats, err := twg.WarpScan(scanCtx, twg.WarpScanOptions{
		PrivateKey:    priv,
		PeerPublicKey: peer,
		Reserved:      reserved,
		Prefixes:      prefixes,
		Ports:         ports,
		Limit:         *limit,
		Workers:           *workers,
		MaxRTT:            *maxRTT,
		AllowOutOfCatalog: *allowOutOfCatalog,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "warpscan:", err)
		os.Exit(1)
	}
	for _, hit := range hits {
		rttMs := hit.RTT.Milliseconds()
		if rttMs < 1 {
			rttMs = 1 // a zero reads as "unverified" to downstream parsers
		}
		fmt.Printf("%s|%d\n", hit.AddrPort, rttMs)
	}
	fmt.Fprintf(os.Stderr, "warpscan: probes=%d hits=%d too_slow=%d timeouts=%d unreachable=%d elapsed=%s\n",
		stats.Probes, stats.Hits, stats.TooSlow, stats.Timeouts, stats.Unreachable,
		stats.Elapsed.Round(100*time.Millisecond))
	if len(hits) == 0 {
		os.Exit(1)
	}
}

// resolveKeys picks the explicit flags or falls back to the identity slot
// resolved through the config (warpenroll conventions).
func resolveKeys(cfgPath, privB64, peerB64, reservedB64 string) (priv, peer [32]byte, reserved [3]byte, err error) {
	if privB64 == "" || peerB64 == "" {
		if cfgPath == "" {
			return priv, peer, reserved, fmt.Errorf("--private-key/--peer-key or --config required")
		}
		p, pe, r, e := keysFromConfig(cfgPath)
		if e != nil {
			return priv, peer, reserved, e
		}
		privB64, peerB64, reservedB64 = p, pe, r
	}
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(raw) != 32 {
		return priv, peer, reserved, fmt.Errorf("bad private key (want base64 of 32 bytes)")
	}
	copy(priv[:], raw)
	raw, err = base64.StdEncoding.DecodeString(peerB64)
	if err != nil || len(raw) != 32 {
		return priv, peer, reserved, fmt.Errorf("bad peer key (want base64 of 32 bytes)")
	}
	copy(peer[:], raw)
	if reservedB64 != "" {
		raw, err = base64.StdEncoding.DecodeString(reservedB64)
		if err != nil || len(raw) == 0 || len(raw) > 3 {
			return priv, peer, reserved, fmt.Errorf("bad reserved (want base64 of 1..3 bytes)")
		}
		copy(reserved[:], raw)
	}
	return priv, peer, reserved, nil
}

// keysFromConfig reads the warp WG identity slot (wg_private_key /
// wg_peer_public_key / wg_client_id — the transport/wg Identity JSON).
func keysFromConfig(cfgPath string) (priv, peer, reserved string, err error) {
	type cfgShape struct {
		System struct {
			Warp struct {
				IdentityPath string `json:"identity_path"`
			} `json:"warp"`
		} `json:"system"`
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", "", "", fmt.Errorf("read config: %w", err)
	}
	var c cfgShape
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", "", "", fmt.Errorf("parse config: %w", err)
	}
	if c.System.Warp.IdentityPath == "" {
		return "", "", "", fmt.Errorf("config has no system.warp.identity_path")
	}
	idRaw, err := os.ReadFile(c.System.Warp.IdentityPath)
	if err != nil {
		return "", "", "", fmt.Errorf("read identity slot: %w", err)
	}
	var id struct {
		PrivateKey    string `json:"wg_private_key"`
		PeerPublicKey string `json:"wg_peer_public_key"`
		ClientID      string `json:"wg_client_id"`
	}
	if err := json.Unmarshal(idRaw, &id); err != nil {
		return "", "", "", fmt.Errorf("parse identity slot: %w", err)
	}
	if id.PrivateKey == "" || id.PeerPublicKey == "" {
		return "", "", "", fmt.Errorf("identity slot has no WG keys (MASQUE-only slot?)")
	}
	return id.PrivateKey, id.PeerPublicKey, id.ClientID, nil
}

func runConnectSession(endpoint, profileName, cfgPath string, priv, peer [32]byte, reserved [3]byte, timeout time.Duration) {
	var ident *twg.Identity
	if cfgPath != "" {
		type cfgShape struct {
			System struct {
				Warp struct {
					IdentityPath string `json:"identity_path"`
				} `json:"warp"`
			} `json:"system"`
		}
		raw, _ := os.ReadFile(cfgPath)
		var c cfgShape
		_ = json.Unmarshal(raw, &c)
		if c.System.Warp.IdentityPath != "" {
			store := twg.IdentityStore{Path: c.System.Warp.IdentityPath}
			if id, err := store.Load(); err == nil {
				ident = id
			}
		}
	}
	if ident == nil {
		clientB64 := ""
		if reserved != ([3]byte{}) {
			clientB64 = base64.StdEncoding.EncodeToString(reserved[:])
		}
		var err error
		ident, err = twg.NewIdentity(base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(peer[:]), clientB64, "172.16.0.2", "", true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warpscan: build identity: %v\n", err)
			os.Exit(1)
		}
	}

	tunCfg := twg.TunnelConfig{
		Mode:          twg.ModeNetstack,
		InterfaceName: "b4wg0",
	}
	if ident.AssignedV4 != "" {
		if addr, err := netip.ParseAddr(ident.AssignedV4); err == nil {
			tunCfg.Addresses = append(tunCfg.Addresses, addr)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	establishedCh := make(chan struct{}, 1)
	lostCh := make(chan twg.Failure, 1)

	prof := twg.Profile{}
	if profileName != "" && profileName != "vanilla-off" {
		tpl, err := twg.LookupProfile(profileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warpscan: %v\n", err)
			os.Exit(1)
		}
		p, err := tpl.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warpscan: build profile: %v\n", err)
			os.Exit(1)
		}
		prof = p
		fmt.Printf("warpscan: using AWG obfuscation profile %q (jc=%d jmin=%d jmax=%d)\n", profileName, prof.JunkCount, prof.JunkMin, prof.JunkMax)
	} else {
		fmt.Printf("warpscan: using profile %q (vanilla)\n", profileName)
	}

	sessCfg := twg.SessionConfig{
		Ident:              ident,
		Profile:            prof,
		Endpoint:           endpoint,
		Tunnel:             tunCfg,
		VerboseDiagnostics: true,
		Health: twg.HealthConfig{
			HandshakeTimeout: 10 * time.Second,
			Gate: twg.TrustGate{
				RoundTrips: 2,
				Gap:        50 * time.Millisecond,
				Window:     3 * time.Second,
			},
			KeepaliveSec: 25,
		},
		Callbacks: twg.SessionCallbacks{
			OnEvent: func(ev twg.SessionEvent) {
				fmt.Printf("event=%s class=%s reason=%s\n", ev.Name, ev.Class, ev.Reason)
			},
			OnEstablished: func() {
				select {
				case establishedCh <- struct{}{}:
				default:
				}
			},
			OnLost: func(f twg.Failure) {
				select {
				case lostCh <- f:
				default:
				}
			},
		},
	}

	sess, err := twg.NewSession(sessCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warpscan: new session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("warpscan: starting session to %s (netstack)...\n", endpoint)
	if err := sess.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "warpscan: start: %v\n", err)
		os.Exit(1)
	}
	defer sess.Stop()

	select {
	case <-runCtx.Done():
		fmt.Fprintln(os.Stderr, "warpscan: timeout waiting for establishment")
		os.Exit(1)
	case f := <-lostCh:
		fmt.Fprintf(os.Stderr, "warpscan: session lost: class=%s reason=%s err=%v\n", f.Class, f.Reason, f.Err)
		os.Exit(1)
	case <-establishedCh:
		fmt.Println("warpscan: ESTABLISHED! Trust gate passed.")
	}

	tun := sess.Tunnel()
	if tun != nil && tun.Netstack != nil {
		fmt.Println("warpscan: fetching https://1.1.1.1/cdn-cgi/trace through netstack...")
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: tun.Netstack.DialContext,
			},
			Timeout: 10 * time.Second,
		}
		req, _ := http.NewRequestWithContext(runCtx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warpscan: trace failed: %v\n", err)
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			fmt.Println("--- cdn-cgi/trace ---")
			fmt.Println(string(body))
			fmt.Println("---------------------")
		}
	}
}
