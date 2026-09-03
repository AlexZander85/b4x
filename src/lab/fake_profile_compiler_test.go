package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/sni"
)

func sourceArtifact(t *testing.T, raw []byte) RawClientHelloArtifact {
	t.Helper()
	artifact, err := newSourceArtifact(raw)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func newSourceArtifact(raw []byte) (RawClientHelloArtifact, error) {
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	return NewRawClientHelloArtifact("android-source-1", CapturedHelloProfile{ID: "source-profile", HelloHash: hash, SHA256: hash, IPFamily: "ipv4"}, raw, "local-test-capture")
}

func compilerRequest(source RawClientHelloArtifact, mode CompileMode) CompileRequest {
	return CompileRequest{Source: source, Mode: mode, MTU: MTUEstimator{Family: "ipv4", MTU: 1500, TCPOptionsBytes: 12}, Seed: 42, Provenance: "stage-26-test"}
}

func TestCompileFakeProfileShorterAndLongerSNIReparse(t *testing.T) {
	sourceBytes := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	source := sourceArtifact(t, sourceBytes)
	for _, replacement := range []string{"y.t", "very-long-android-clienthello-profile.example"} {
		request := compilerRequest(source, CompileFingerprintPreserving)
		request.ReplacementSNI = replacement
		compiled, err := CompileFakeProfile(request)
		if err != nil {
			t.Fatalf("replacement %q failed: %v", replacement, err)
		}
		metadata := sni.ParseTLSClientHelloMetadata(compiled.Bytes())
		if !metadata.Complete || metadata.SNI != replacement || compiled.Profile.Active {
			t.Fatalf("compiled SNI/profile invalid: %+v metadata=%+v", compiled.Profile, metadata)
		}
		if err := ValidateCompiledProfile(compiled, request); err != nil {
			t.Fatalf("compiled profile validation failed: %v", err)
		}
	}
	if !reflect.DeepEqual(source.Raw(), sourceBytes) {
		t.Fatal("source artifact was mutated by compilation")
	}
}

func TestCompileFakeProfileExtensionRemovalAndValidation(t *testing.T) {
	source := sourceArtifact(t, fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800))
	request := compilerRequest(source, CompileCompactCompatible)
	request.AllowedVersions = []uint16{0x0304}
	compiled, err := CompileFakeProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Profile.Size >= source.Source.RawSize && source.Source.RawSize != 0 {
		t.Fatalf("compact compiler did not remove padding: source=%d compiled=%d", source.Source.RawSize, compiled.Profile.Size)
	}
	foundPaddingRemoval := false
	for _, change := range compiled.Profile.ChangeReport.Extensions {
		if change.Type == 0x0015 && change.Action == "removed" {
			foundPaddingRemoval = true
		}
	}
	if !foundPaddingRemoval || !compiled.Profile.MTUFits {
		t.Fatalf("padding/MTU report incomplete: %+v", compiled.Profile.ChangeReport)
	}
	badALPN := request
	badALPN.RequiredALPN = []string{"h2"}
	if _, err := CompileFakeProfile(badALPN); !errors.Is(err, ErrCompiledInvalid) {
		t.Fatalf("missing required ALPN was accepted: %v", err)
	}
}

func TestCompileFakeProfileMTUIPv4IPv6AndMultiPacketGate(t *testing.T) {
	mtu4, err := (MTUEstimator{Family: "ipv4", MTU: 1500, TCPOptionsBytes: 12}).MaxPayload()
	if err != nil || mtu4 != 1448 {
		t.Fatalf("IPv4 MTU estimate = %d err=%v, want 1448", mtu4, err)
	}
	mtu6, err := (MTUEstimator{Family: "ipv6", MTU: 1500, TCPOptionsBytes: 12}).MaxPayload()
	if err != nil || mtu6 != 1428 {
		t.Fatalf("IPv6 MTU estimate = %d err=%v, want 1428", mtu6, err)
	}
	source := sourceArtifact(t, fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0))
	request := compilerRequest(source, CompileMultiPacketFake)
	if _, err := CompileFakeProfile(request); !errors.Is(err, ErrMultiPacketDisabled) {
		t.Fatalf("multi-packet fake was not gated: %v", err)
	}
	request.Mode = CompileSinglePacketSafe
	request.MTU = MTUEstimator{Family: "ipv6", MTU: 1500}
	compiled, err := CompileFakeProfile(request)
	if err != nil || !compiled.Profile.MTUFits {
		t.Fatalf("single-packet IPv6 profile failed: %+v err=%v", compiled.Profile, err)
	}
}

func TestCompileFakeProfileRejectsInvalidSourceAndOversizedSinglePacket(t *testing.T) {
	if _, err := NewRawClientHelloArtifact("bad", CapturedHelloProfile{}, []byte{1, 2, 3}, "test"); !errors.Is(err, ErrInvalidSourceArtifact) {
		t.Fatalf("malformed source was accepted: %v", err)
	}
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800)
	// Make padding a non-padding extension so single-packet-safe cannot remove
	// it as a compatibility optimization.
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == 0x00 && raw[i+1] == 0x15 {
			raw[i+1] = 0x16
			break
		}
	}
	source := sourceArtifact(t, raw)
	request := compilerRequest(source, CompileSinglePacketSafe)
	if _, err := CompileFakeProfile(request); !errors.Is(err, ErrMTUExceeded) {
		t.Fatalf("oversized single-packet profile was accepted: %v", err)
	}
	request.Mode = CompileFingerprintPreserving
	compiled, err := CompileFakeProfile(request)
	if err != nil || compiled.Profile.MTUFits {
		t.Fatalf("non-single profile did not report MTU overflow: %+v err=%v", compiled.Profile, err)
	}
}

func TestCompileFakeProfileDeterministicSeedAndProvenance(t *testing.T) {
	source := sourceArtifact(t, fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0))
	request := compilerRequest(source, CompileFingerprintPreserving)
	request.ReplacementSNI = "api.example"
	first, err := CompileFakeProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileFakeProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Profile, second.Profile) || string(first.Bytes()) != string(second.Bytes()) {
		t.Fatal("same seed did not produce deterministic compiled artifact")
	}
	if first.Profile.Provenance == "" || first.Profile.Active || first.Profile.ChangeReport.OriginalSHA256 != source.SHA256 {
		t.Fatalf("provenance/safety metadata incomplete: %+v", first.Profile)
	}
}

func FuzzCompileFakeProfileNeverPanics(f *testing.F) {
	f.Add("api.example", int64(1), false)
	f.Add("", int64(99), true)
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	fuzzSource, err := newSourceArtifact(raw)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, replacement string, seed int64, removePadding bool) {
		request := compilerRequest(fuzzSource, CompileFingerprintPreserving)
		request.ReplacementSNI = replacement
		request.Seed = seed
		if removePadding {
			request.RemoveExtensions = []uint16{0x0015}
		}
		_, _ = CompileFakeProfile(request)
	})
}

func BenchmarkCompileFakeProfile(b *testing.B) {
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800)
	source, err := newSourceArtifact(raw)
	if err != nil {
		b.Fatal(err)
	}
	request := compilerRequest(source, CompileCompactCompatible)
	request.ReplacementSNI = "api.example"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = CompileFakeProfile(request)
	}
}
