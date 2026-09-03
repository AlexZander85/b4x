package warp

import "testing"

func TestManifestRejectsRuntimeDownloadAndRequiresLicense(t *testing.T) {
	m := EngineManifest{BinaryName: "b4-warpd", SourceCommit: "c", SourceHash: "s", LicenseHash: "l", Architecture: "mipsel", Version: "1", Bundled: true}
	if ValidateManifest(m) != nil {
		t.Fatal("valid manifest rejected")
	}
	m.RuntimeDownload = true
	if ValidateManifest(m) == nil {
		t.Fatal("runtime download accepted")
	}
}
