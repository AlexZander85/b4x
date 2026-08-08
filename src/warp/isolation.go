package warp

type InstanceState struct {
	InstanceID        string
	Mark              uint32
	SessionGeneration string
	Active            bool
}
type IsolationReport struct {
	Outer, Inner             InstanceState
	ParentLinkValid          bool
	InnerRevokedBeforeParent bool
}

func (r IsolationReport) Valid() bool {
	return r.Outer.InstanceID != "" && r.Inner.InstanceID != "" && r.Outer.InstanceID != r.Inner.InstanceID && r.Outer.Mark != r.Inner.Mark && r.ParentLinkValid && !r.InnerRevokedBeforeParent
}
