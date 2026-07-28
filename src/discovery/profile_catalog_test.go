package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/lab"
)

func catalogArtifact(t testing.TB) lab.CompiledArtifact {
	t.Helper()
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	source, err := lab.NewRawClientHelloArtifact("catalog-source", lab.CapturedHelloProfile{ID: "catalog-source", HelloHash: hash, SHA256: hash, RawSize: len(raw), IPFamily: "ipv4", PrivacySafe: true}, raw, "stage-30")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := lab.CompileFakeProfile(lab.CompileRequest{Source: source, Mode: lab.CompileFingerprintPreserving, ReplacementSNI: "fake.example", MTU: lab.MTUEstimator{Family: "ipv4", MTU: 1500}, Provenance: "stage-30;clean-room"})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func catalogRegistration(artifact lab.CompiledArtifact) ProfileRegistration {
	return ProfileRegistration{ID: artifact.Profile.ID, Kind: ProfileAndroidCaptured, Template: "android-captured", Source: "local-android-capture", Provenance: "stage-30-clean-room", License: "B4-compatible-clean-room", LicenseReviewed: true}
}

func TestFakeProfileCatalogLicenseBoundAndMetadataOnly(t *testing.T) {
	catalog := NewFakeProfileCatalog(1)
	if err := catalog.AddDescriptor(ProfileRegistration{ID: "quic-initial-1", Kind: ProfileQUICInitial, Source: "local-generated", Provenance: "clean-room", License: "generated", LicenseReviewed: false, SHA256: "hash", Size: 32}); !errors.Is(err, ErrProfileLicense) {
		t.Fatalf("license error=%v", err)
	}
	if err := catalog.AddDescriptor(ProfileRegistration{ID: "quic-initial-1", Kind: ProfileQUICInitial, Source: "local-generated", Provenance: "clean-room", License: "generated", LicenseReviewed: true, SHA256: "hash", Size: 32}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.AddDescriptor(ProfileRegistration{ID: "quic-initial-2", Kind: ProfileQUICInitial, Source: "local-generated", Provenance: "clean-room", License: "generated", LicenseReviewed: true, SHA256: "hash2", Size: 32}); !errors.Is(err, ErrProfileCatalogFull) {
		t.Fatalf("catalog bound error=%v", err)
	}
	profiles := catalog.Profiles()
	if len(profiles) != 1 || profiles[0].Active || profiles[0].ID != "quic-initial-1" {
		t.Fatalf("profiles=%+v", profiles)
	}
	if candidates := catalog.Select(ProfileSelectionRequest{TargetProfile: "youtube-api"}); len(candidates) != 0 {
		t.Fatalf("metadata-only profile became executable candidate=%+v", candidates)
	}
}

func TestFakeProfileCatalogSelectionSeparatesTechniqueAndPromotion(t *testing.T) {
	artifact := catalogArtifact(t)
	catalog := NewFakeProfileCatalog(8)
	if err := catalog.AddCompiled(catalogRegistration(artifact), artifact); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: 2, Successful: 2, StableSuccesses: 1, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-ui", Samples: 1, Successful: 1, StableSuccesses: 1, CanaryPassed: true, ObservedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if got := catalog.Select(ProfileSelectionRequest{TargetProfile: "youtube-api", TechniqueID: "multisplit", MinSamples: 2, RequireCanary: true}); len(got) != 0 {
		t.Fatalf("uncanaryed target selected=%+v", got)
	}
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: 1, Successful: 1, StableSuccesses: 0, CanaryPassed: true, ObservedAt: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	first := catalog.Select(ProfileSelectionRequest{TargetProfile: "youtube-api", TechniqueID: "multisplit", MinSamples: 2, RequireCanary: true})
	second := catalog.Select(ProfileSelectionRequest{TargetProfile: "youtube-api", TechniqueID: "hostfakesplit", MinSamples: 2, RequireCanary: true})
	if len(first) != 1 || len(second) != 1 || first[0].Profile.ID != second[0].Profile.ID || first[0].Score != second[0].Score {
		t.Fatalf("technique polluted profile selection first=%+v second=%+v", first, second)
	}
	if first[0].TechniqueID != "multisplit" || second[0].TechniqueID != "hostfakesplit" || first[0].Profile.Active || !first[0].PromotionEligible {
		t.Fatalf("candidate promotion state first=%+v second=%+v", first, second)
	}
	compiled := first[0].Compiled()
	if err := compiled.Validate(); err != nil {
		t.Fatal(err)
	}
	metadata, err := catalog.ExportMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), "fake.example") || strings.Contains(string(metadata), "artifact") {
		t.Fatalf("metadata export leaked payload detail: %s", metadata)
	}
}

func TestFakeProfileCatalogEvidenceBoundaries(t *testing.T) {
	artifact := catalogArtifact(t)
	catalog := NewFakeProfileCatalog(4)
	if err := catalog.AddCompiled(catalogRegistration(artifact), artifact); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: 0}); !errors.Is(err, ErrProfileEvidence) {
		t.Fatalf("zero sample error=%v", err)
	}
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: 2, Successful: 3}); !errors.Is(err, ErrProfileEvidence) {
		t.Fatalf("success overflow error=%v", err)
	}
	if evidence := catalog.Evidence("missing"); evidence != nil {
		t.Fatalf("missing evidence=%v", evidence)
	}
}

func FuzzFakeProfileCatalogRecordOutcome(f *testing.F) {
	f.Add(uint64(2), uint64(1), uint64(1), true)
	f.Add(uint64(0), uint64(0), uint64(0), false)
	artifactBytes := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	f.Fuzz(func(t *testing.T, samples, successful, stable uint64, canary bool) {
		// The catalog remains bounded and rejects out-of-range observations.
		rawSum := sha256.Sum256(artifactBytes)
		hash := hex.EncodeToString(rawSum[:])
		source, err := lab.NewRawClientHelloArtifact("fuzz-source", lab.CapturedHelloProfile{ID: "fuzz-source", HelloHash: hash, SHA256: hash, IPFamily: "ipv4"}, artifactBytes, "fuzz")
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := lab.CompileFakeProfile(lab.CompileRequest{Source: source, Mode: lab.CompileFingerprintPreserving, ReplacementSNI: "fake.example", MTU: lab.MTUEstimator{Family: "ipv4", MTU: 1500}, Provenance: "fuzz"})
		if err != nil {
			t.Fatal(err)
		}
		catalog := NewFakeProfileCatalog(1)
		if err := catalog.AddCompiled(catalogRegistration(artifact), artifact); err != nil {
			t.Fatal(err)
		}
		_ = catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: samples, Successful: successful, StableSuccesses: stable, CanaryPassed: canary})
	})
}

func BenchmarkFakeProfileCatalogSelect(b *testing.B) {
	artifact := catalogArtifact(b)
	catalog := NewFakeProfileCatalog(8)
	if err := catalog.AddCompiled(catalogRegistration(artifact), artifact); err != nil {
		b.Fatal(err)
	}
	if err := catalog.RecordOutcome(artifact.Profile.ID, ProfileObservation{TargetProfile: "youtube-api", Samples: 3, Successful: 3, StableSuccesses: 2, CanaryPassed: true}); err != nil {
		b.Fatal(err)
	}
	request := ProfileSelectionRequest{TargetProfile: "youtube-api", TechniqueID: "multisplit", MinSamples: 2, RequireCanary: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = catalog.Select(request)
	}
}
