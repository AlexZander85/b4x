// Command awgenroll provisions/revalidates an AWG-WARP (WireGuard-class)
// identity from outside the SNI-filtered network — the AWG twin of
// cmd/warpenroll (which covers MASQUE only). Used for the nested matrix
// (FIELD3): awg+awg needs TWO distinct WG devices, one per layer slot.
//
//	awgenroll enroll --config cfg.json
//
// The identity is written to system.warp.awg.identity_path. A valid existing
// identity produces ZERO registration requests (idempotent).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/daniellavrushin/b4/awgwarpservice"
	"github.com/daniellavrushin/b4/config"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "awgenroll: %v\n", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "enroll" && os.Args[1] != "-h" && os.Args[1] != "--help" && os.Args[1] != "help") {
		fmt.Fprintln(os.Stderr, "usage: awgenroll enroll --config <cfg.json>")
		os.Exit(2)
	}
	if os.Args[1] != "enroll" {
		fmt.Fprintln(os.Stderr, "usage: awgenroll enroll --config <cfg.json>")
		return
	}
	fs := flag.NewFlagSet("awgenroll enroll", flag.ContinueOnError)
	path := fs.String("config", "", "path to config json (required)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}

	c := config.NewConfig()
	if _, err := c.LoadWithMigration(*path); err != nil {
		fatal(err)
	}
	rt, err := awgwarpservice.Build(&c, awgwarpservice.Options{})
	if err != nil {
		fatal(err)
	}
	if err := rt.EnrollOnce(context.Background()); err != nil {
		fatal(err)
	}
	st := rt.Status()
	out, _ := json.MarshalIndent(map[string]any{
		"identity_present": st.IdentityPresent,
		"assigned_v4":      st.AssignedV4,
		"state":            st.State,
		"identity_path":    c.System.Warp.AWG.EffectiveIdentityPath(),
	}, "", "  ")
	fmt.Println(string(out))
}
