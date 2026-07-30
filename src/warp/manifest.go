package warp

import "errors"

type EngineManifest struct {
	BinaryName, SourceCommit, SourceHash, LicenseHash, Architecture string
	Version                                                         string
	Bundled                                                         bool
	RuntimeDownload                                                 bool
}

func (m EngineManifest) Valid() bool {
	return m.BinaryName == "b4-warpd" && m.SourceCommit != "" && m.SourceHash != "" && m.LicenseHash != "" && m.Architecture != "" && m.Version != "" && m.Bundled && !m.RuntimeDownload
}
func ValidateManifest(m EngineManifest) error {
	if !m.Valid() {
		return errors.New("invalid bundled warp manifest")
	}
	return nil
}

type PackageTransition struct {
	Previous, Next      EngineManifest
	Committed, Rollback bool
}

func (p PackageTransition) Valid() bool { return p.Next.Valid() && (p.Committed || p.Rollback) }
