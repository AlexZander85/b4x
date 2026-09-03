package ppe

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeInfo struct{ name string }

func (f fakeInfo) Name() string     { return f.name }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return os.ModeDir }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return true }
func (fakeInfo) Sys() any           { return nil }

type fakeRunner struct {
	files map[string]string
	paths map[string]string
	ndm   bool
	fail  string
	runs  [][]string
}

func (f *fakeRunner) ReadFile(path string) ([]byte, error) {
	if value, ok := f.files[path]; ok {
		return []byte(value), nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeRunner) Stat(path string) (os.FileInfo, error) {
	if path == "/var/run/ndm" && f.ndm {
		return fakeInfo{name: "ndm"}, nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeRunner) LookPath(file string) (string, error) {
	if value, ok := f.paths[file]; ok {
		return value, nil
	}
	return "", errors.New("not found")
}
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	entry := append([]string{name}, args...)
	f.runs = append(f.runs, entry)
	joined := strings.Join(entry, " ")
	if f.fail != "" && strings.Contains(joined, f.fail) {
		return "permission denied", os.ErrPermission
	}
	return "", nil
}

func supportedRunner() *fakeRunner {
	return &fakeRunner{
		ndm: true,
		files: map[string]string{
			"/proc/net/ip_tables_targets":  "MARK\nPPE\n",
			"/proc/net/ip6_tables_targets": "PPE\n",
			"/proc/sys/kernel/osrelease":   "5.10-test\n",
			"/proc/cpuinfo":                "Hardware: MediaTek MT7622\n",
		},
		paths: map[string]string{"iptables": "/sbin/iptables", "ip6tables": "/sbin/ip6tables", "ndmc": "/bin/ndmc"},
	}
}

func TestDetectSupportedRequiresFunctionalProbe(t *testing.T) {
	runner := supportedRunner()
	report := NewDetector(runner).Detect(context.Background())
	if !report.Supported || report.State != CapabilitySupported || !report.IPv4.ConnskipUsable || !report.IPv6.ConnskipUsable {
		t.Fatalf("unexpected report: %+v", report)
	}
	foundCleanup := false
	for _, run := range runner.runs {
		if strings.Contains(strings.Join(run, " "), " -X B4_PPE_TEST_") {
			foundCleanup = true
		}
	}
	if !foundCleanup {
		t.Fatal("transient probe chain was not cleaned up")
	}
}

func TestDetectDoesNotTrustMediaTekModel(t *testing.T) {
	runner := supportedRunner()
	runner.files["/proc/net/ip_tables_targets"] = "MARK\n"
	report := NewDetector(runner).Detect(context.Background())
	if report.Supported || report.IPv4.State != CapabilityUnsupported {
		t.Fatalf("false support: %+v", report)
	}
}

func TestDetectNonKeeneticNeverProductSupported(t *testing.T) {
	runner := supportedRunner()
	runner.ndm = false
	delete(runner.paths, "ndmc")
	report := NewDetector(runner).Detect(context.Background())
	if report.Supported || report.Platform.Platform != "linux" || len(report.Warnings) == 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestDetectPermissionDeniedIsNotSuccess(t *testing.T) {
	runner := supportedRunner()
	runner.fail = "-N B4_PPE_TEST_"
	report := NewDetector(runner).Detect(context.Background())
	if report.IPv4.State == CapabilitySupported || !report.IPv4.PermissionDenied {
		t.Fatalf("permission denial accepted: %+v", report.IPv4)
	}
}

func TestExactTargetLine(t *testing.T) {
	if exactLine("NOTPPE\nPPE_EXTRA\n", "PPE") {
		t.Fatal("substring matched as exact target")
	}
	if !exactLine("MARK\n PPE \n", "PPE") {
		t.Fatal("exact trimmed line not found")
	}
}
