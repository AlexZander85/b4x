package warpservice

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	warp "github.com/daniellavrushin/b4/transport/warp"
)

// b4x-h6o: the H3 ladder arms the fake-QUIC cover around every establishment
// (warp.LadderConfig.Cover). This file is the FIELD binding the engine side
// deliberately left to us: CoverApplier over the kernel sets the fake-QUIC
// NFQUEUE rules reference (b4_cf_fakequic_v4/v6), implemented with `ipset`.
// Arm must be all-or-nothing (partial camouflage is worse than none).

// coverRunner runs one command. Tests inject a fake; production uses the OS.
type coverRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type osCoverRunner struct{}

func (osCoverRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ipsetCoverApplier implements warp.CoverApplier against hash:net sets.
type ipsetCoverApplier struct {
	run coverRunner
}

// Activate ensures both family sets exist and every prefix is present. A
// failure at any step is returned so the ladder fails closed to H2.
func (a *ipsetCoverApplier) Activate(setV4, setV6 string, v4, v6 []netip.Prefix) error {
	ctx := context.Background()
	if err := a.ensureSet(ctx, setV4, "inet"); err != nil {
		return err
	}
	if err := a.ensureSet(ctx, setV6, "inet6"); err != nil {
		return err
	}
	for _, p := range v4 {
		if err := a.addPrefix(ctx, setV4, p); err != nil {
			return err
		}
	}
	for _, p := range v6 {
		if err := a.addPrefix(ctx, setV6, p); err != nil {
			return err
		}
	}
	return nil
}

// Deactivate releases coverage from both sets. The sets themselves stay in
// place: the fake-QUIC NFQUEUE rules reference them, so destroying them would
// break the rules for the next window. Flush is the release.
func (a *ipsetCoverApplier) Deactivate(setV4, setV6 string) error {
	ctx := context.Background()
	for _, s := range []string{setV4, setV6} {
		if _, err := a.run.Run(ctx, "ipset", "flush", s); err != nil {
			return fmt.Errorf("cover release: flush %s: %w", s, err)
		}
	}
	return nil
}

func (a *ipsetCoverApplier) ensureSet(ctx context.Context, set, family string) error {
	if _, err := a.run.Run(ctx, "ipset", "create", set, "hash:net", "family", family, "-exist"); err != nil {
		return fmt.Errorf("cover activate: create %s: %w", set, err)
	}
	return nil
}

func (a *ipsetCoverApplier) addPrefix(ctx context.Context, set string, p netip.Prefix) error {
	if _, err := a.run.Run(ctx, "ipset", "add", set, p.Masked().String(), "-exist"); err != nil {
		return fmt.Errorf("cover activate: add %s to %s: %w", p, set, err)
	}
	return nil
}

// newFakeQUICCover builds the production cover: the Nova-default profile bound
// to the ipset applier. The ladder arms it before every H3 dial and releases
// it strictly after ValidateDataPlane.
func newFakeQUICCover() (*warp.FakeQUICCover, error) {
	return warp.NewFakeQUICCover(warp.FakeQUICCoverConfig{
		Profile: warp.DefaultFakeQUICCoverProfile(),
		Apply:   &ipsetCoverApplier{run: osCoverRunner{}},
	})
}
