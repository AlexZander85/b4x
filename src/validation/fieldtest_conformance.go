package validation

type FieldTestConformance struct {
	Session, RouterAPI, Controller, Android, Companion, Optimizer, Canary, Controls, Auditor, GSO, RST, Promotion, WARPBase, WARPTrace, Nested, Detector, DDI, Telegram bool
	Artifacts                                                                                                                                                           int
	SourceHash                                                                                                                                                          string
}

func (f FieldTestConformance) Ready() bool {
	return f.Session && f.RouterAPI && f.Controller && f.Android && f.Companion && f.Optimizer && f.Canary && f.Controls && f.Auditor && f.GSO && f.RST && f.Promotion && f.WARPBase && f.WARPTrace && f.Nested && f.Detector && f.DDI && f.Telegram && f.Artifacts > 0 && f.SourceHash != ""
}
