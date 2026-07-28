package ppe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const defaultProbeTimeout = 3 * time.Second

type Detector struct {
	runner  Runner
	timeout time.Duration
	now     func() time.Time
}

func NewDetector(runner Runner) *Detector {
	if runner == nil {
		runner = OSRunner{}
	}
	return &Detector{runner: runner, timeout: defaultProbeTimeout, now: time.Now}
}

func (d *Detector) Detect(ctx context.Context) CapabilityReport {
	if ctx == nil {
		ctx = context.Background()
	}
	report := CapabilityReport{
		CheckedAt: d.now().UTC(),
		Platform:  d.detectPlatform(ctx),
		Evidence:  map[string]string{"decision": "runtime capabilities, not router model"},
	}
	report.IPv4 = d.detectFamily(ctx, "ipv4", "iptables", "/proc/net/ip_tables_targets")
	report.IPv6 = d.detectFamily(ctx, "ipv6", "ip6tables", "/proc/net/ip6_tables_targets")
	report.FunctionalProbeRun = report.IPv4.ConnskipUsable || report.IPv6.ConnskipUsable ||
		containsReason(report.IPv4.Reasons, "connskip") || containsReason(report.IPv6.Reasons, "connskip")

	switch {
	case report.IPv4.State == CapabilityBroken || report.IPv6.State == CapabilityBroken:
		report.State = CapabilityBroken
	case report.IPv4.State == CapabilitySupported && report.IPv6.State == CapabilitySupported:
		report.State = CapabilitySupported
	case report.IPv4.State == CapabilitySupported || report.IPv6.State == CapabilitySupported:
		report.State = CapabilityPartial
	case report.IPv4.State == CapabilityPartial || report.IPv6.State == CapabilityPartial:
		report.State = CapabilityPartial
	case report.IPv4.State == CapabilityUnsupported && report.IPv6.State == CapabilityUnsupported:
		report.State = CapabilityUnsupported
	default:
		report.State = CapabilityUnknown
	}
	report.Supported = report.Platform.NDM && report.IPv4.State == CapabilitySupported
	if !report.Platform.NDM && (report.IPv4.State == CapabilitySupported || report.IPv6.State == CapabilitySupported) {
		report.Warnings = append(report.Warnings, "PPE primitives detected outside confirmed Keenetic NDM; product support remains disabled")
	}
	if report.State == CapabilitySupported || report.State == CapabilityPartial {
		report.Warnings = append(report.Warnings, "static capability does not prove bidirectional packet visibility")
	}
	return report
}

func (d *Detector) detectPlatform(ctx context.Context) PlatformMetadata {
	meta := PlatformMetadata{Platform: "linux", Arch: runtime.GOARCH}
	if _, err := d.runner.Stat("/var/run/ndm"); err == nil {
		meta.NDM = true
	}
	if _, err := d.runner.LookPath("ndmc"); err == nil {
		meta.NDM = true
	}
	if meta.NDM {
		meta.Platform = "keenetic"
	}
	if data, err := d.runner.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		meta.Kernel = strings.TrimSpace(string(data))
	}
	if data, err := d.runner.ReadFile("/proc/cpuinfo"); err == nil {
		lower := strings.ToLower(string(data))
		switch {
		case strings.Contains(lower, "mediatek"), strings.Contains(lower, "mt762"):
			meta.SocFamily = "mediatek"
		case strings.Contains(lower, "qualcomm"):
			meta.SocFamily = "qualcomm"
		case strings.Contains(lower, "broadcom"):
			meta.SocFamily = "broadcom"
		}
	}
	return meta
}

func (d *Detector) detectFamily(parent context.Context, family, binary, targetFile string) FamilyCapability {
	out := FamilyCapability{Family: family, Binary: binary, State: CapabilityUnknown}
	path, err := d.runner.LookPath(binary)
	if err != nil {
		out.State = CapabilityUnsupported
		out.Reasons = append(out.Reasons, binary+" not found")
		return out
	}
	out.Binary = path
	data, err := d.runner.ReadFile(targetFile)
	if err != nil {
		out.State = CapabilityUnsupported
		out.Reasons = append(out.Reasons, fmt.Sprintf("cannot read %s: %v", targetFile, err))
		return out
	}
	out.TargetRegistered = exactLine(string(data), "PPE")
	if !out.TargetRegistered {
		out.State = CapabilityUnsupported
		out.Reasons = append(out.Reasons, "PPE target is not registered")
		return out
	}

	ctx, cancel := context.WithTimeout(parent, d.timeout)
	defer cancel()
	out.WaitSupported = d.commandOK(ctx, path, "-w", "-t", "mangle", "-S")
	base := []string{"-t", "mangle"}
	if out.WaitSupported {
		base = append([]string{"-w"}, base...)
	}
	out.MangleAvailable = d.commandOK(ctx, path, append(base, "-S")...)
	out.Prerouting = d.commandOK(ctx, path, append(base, "-S", "PREROUTING")...)
	out.Forward = d.commandOK(ctx, path, append(base, "-S", "FORWARD")...)
	if !out.MangleAvailable || !out.Prerouting || !out.Forward {
		out.State = CapabilityPartial
		out.Reasons = append(out.Reasons, "mangle PREROUTING/FORWARD is unavailable")
		return out
	}

	chain := fmt.Sprintf("B4_PPE_TEST_%d", d.now().UnixNano()%1000000000)
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), d.timeout)
		defer cleanupCancel()
		_, _ = d.runner.Run(cleanupCtx, path, append(base, "-F", chain)...)
		_, _ = d.runner.Run(cleanupCtx, path, append(base, "-X", chain)...)
	}
	defer cleanup()
	if _, err = d.runner.Run(ctx, path, append(base, "-N", chain)...); err != nil {
		out.PermissionDenied = permissionDenied(err)
		out.State = CapabilityUnsupported
		out.Reasons = append(out.Reasons, "cannot create transient connskip probe chain: "+err.Error())
		return out
	}
	if _, err = d.runner.Run(ctx, path, append(base, "-A", chain, "-m", "connskip", "--connskip", "1", "-j", "RETURN")...); err != nil {
		out.PermissionDenied = permissionDenied(err)
		out.State = CapabilityPartial
		out.Reasons = append(out.Reasons, "functional connskip probe failed: "+err.Error())
		return out
	}
	out.ConnskipUsable = true
	out.State = CapabilitySupported
	return out
}

func (d *Detector) commandOK(ctx context.Context, name string, args ...string) bool {
	_, err := d.runner.Run(ctx, name, args...)
	return err == nil
}

func exactLine(text, wanted string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func containsReason(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func permissionDenied(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "permission denied") || strings.Contains(strings.ToLower(err.Error()), "operation not permitted")
}
