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
	"os"
	"os/signal"
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
	limit := fs.Int("limit", twg.DefaultWarpScanLimit, "stop after this many verified hits")
	workers := fs.Int("workers", twg.DefaultWarpScanWorkers, "concurrent probes")
	maxRTT := fs.Duration("max-rtt", twg.DefaultWarpScanMaxRTT, "discard hits slower than this")
	timeout := fs.Duration("timeout", 120*time.Second, "overall scan budget")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	priv, peer, reserved, err := resolveKeys(*cfgPath, *privB64, *peerB64, *reservedB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warpscan:", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	hits, stats, err := twg.WarpScan(scanCtx, twg.WarpScanOptions{
		PrivateKey:    priv,
		PeerPublicKey: peer,
		Reserved:      reserved,
		Limit:         *limit,
		Workers:       *workers,
		MaxRTT:        *maxRTT,
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
