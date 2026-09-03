package validation

type SafetyResult struct {
	ControlsClean, GSOParity, RSTObserveSafe, CamouflageAuthorized, CutoffVerified, GeoLeakFree, RollbackClean bool
	PostCutoffMutations                                                                                        int
	ForeignActions                                                                                             int
}

func (r SafetyResult) Ready() bool {
	return r.ControlsClean && r.GSOParity && r.RSTObserveSafe && r.CamouflageAuthorized && r.CutoffVerified && r.GeoLeakFree && r.RollbackClean && r.PostCutoffMutations == 0 && r.ForeignActions == 0
}
