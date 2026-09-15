package tor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestTorrcVerifyConfig is the TT6 external-truth gate. Unit tests prove our
// renderer invariants; this test asks the real C-Tor parser. It is opt-in so
// ordinary developer/CI runs never require Entware/Tor or network access.
//
//   B4X_TOR_INTEGRATION=1 [B4X_TOR_BINARY=/opt/bin/tor] go test ./transport/tor -run VerifyConfig
func TestTorrcVerifyConfig(t *testing.T) {
	if os.Getenv("B4X_TOR_INTEGRATION") == "" {
		t.Skip("set B4X_TOR_INTEGRATION=1 to verify rendered torrc with real Tor")
	}
	binary := os.Getenv("B4X_TOR_BINARY")
	if binary == "" {
		if p, err := exec.LookPath("tor"); err == nil {
			binary = p
		} else if _, err := os.Stat("/opt/bin/tor"); err == nil {
			binary = "/opt/bin/tor"
		} else {
			t.Skip("Tor binary not found; set B4X_TOR_BINARY")
		}
	}

	const fp = "0123456789ABCDEF0123456789ABCDEF01234567"
	cases := map[string]TorrcInput{
		"direct-proxy": {
			SocksPort: "127.0.0.1:19050", Entry: entryDirect,
			EgressProxyAddr: "127.0.0.1:19080", EgressProxyUsername: "u", EgressProxyPassword: "p",
		},
		"vanilla-proxy": {
			SocksPort: "127.0.0.1:19051", Entry: entryVanilla, UseBridges: true,
			EgressProxyAddr: "127.0.0.1:19081", EgressProxyUsername: "u", EgressProxyPassword: "p",
			Bridges: []Bridge{{Transport: "vanilla", Line: "198.51.100.10:443 " + fp, AddrPort: "198.51.100.10:443", Fingerprint: fp}},
		},
		"pt-obfs4": {
			SocksPort: "127.0.0.1:19052", Entry: "obfs4", UseBridges: true, PTProxyPort: 19100,
			Bridges: []Bridge{{Transport: "obfs4", Line: "obfs4 198.51.100.11:443 " + fp + " cert=abc iat-mode=0", AddrPort: "198.51.100.11:443", Fingerprint: fp}},
		},
		"mixed-pt": {
			SocksPort: "127.0.0.1:19053", Entry: "auto-mixed", UseBridges: true, PTProxyPort: 19101,
			Bridges: []Bridge{
				{Transport: "webtunnel", Line: "webtunnel 198.51.100.12:443 " + fp + " url=https://example.com/secret", AddrPort: "198.51.100.12:443", Fingerprint: fp},
				{Transport: "obfs4", Line: "obfs4 198.51.100.13:443 " + fp + " cert=abc iat-mode=0", AddrPort: "198.51.100.13:443", Fingerprint: fp},
			},
		},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			data := filepath.Join(root, "data")
			if err := os.MkdirAll(filepath.Join(data, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			in.DataPath = data
			in.ControlSocket = filepath.Join(data, "data", "control.sock")
			in.OwningPID = os.Getpid()
			doc := RenderTorrc(in)
			if err := ValidateRendered(doc); err != nil {
				t.Fatalf("internal validate: %v\n%s", err, doc)
			}
			torrc := filepath.Join(root, "torrc")
			defaults := filepath.Join(root, "defaults")
			if err := os.WriteFile(torrc, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(defaults, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary,
				"--verify-config", "-f", torrc,
				"--DefaultsTorrcFile", defaults,
				"--DataDirectory", filepath.Join(data, "data"),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("tor --verify-config failed: %v\n%s\n--- torrc ---\n%s", err, out, doc)
			}
		})
	}
}
