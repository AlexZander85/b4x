package validation

type ProfileConformance struct {
	Schema, Ownership, Compiler, Transactions, Catalog, Objectives, Wizard, YouTube, StarterPacks, Transport, Telegram, ImportExport, Capabilities, GSORST, Controls, WARP, Recovery, DetectorTargets, DetectorCapabilities, EvidenceUX, GuidedDiscovery, Bridge, Release bool
	SafetyHash                                                                                                                                                                                                                                                            string
}

func (p ProfileConformance) Ready() bool {
	return p.Schema && p.Ownership && p.Compiler && p.Transactions && p.Catalog && p.Objectives && p.Wizard && p.YouTube && p.StarterPacks && p.Transport && p.Telegram && p.ImportExport && p.Capabilities && p.GSORST && p.Controls && p.WARP && p.Recovery && p.DetectorTargets && p.DetectorCapabilities && p.EvidenceUX && p.GuidedDiscovery && p.Bridge && p.Release && p.SafetyHash != ""
}
