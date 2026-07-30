package serviceprofile

import "github.com/daniellavrushin/b4/serviceprofile/schema"

type StarterPack struct {
	Manifest      schema.Manifest
	Objectives    []ComponentObjective
	ReviewedSeeds []string
	Maturity      string
	Owner         string
	Controls      []string
}

func YouTubePack() StarterPack {
	return StarterPack{Manifest: schema.Manifest{SchemaVersion: 1, ID: "youtube", Name: "YouTube", Classification: "official", Components: []schema.Component{{ID: "api", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, PassiveRST: "observe-max", Targets: []schema.Target{{Name: "youtubei", Role: "primary", Domains: []string{"youtubei.googleapis.com"}}, {Name: "gmail", Role: "same-provider-control", Domains: []string{"mail.google.com"}}}}, {ID: "video", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, PassiveRST: "observe-max", Targets: []schema.Target{{Name: "video", Role: "primary", Domains: []string{"*.googlevideo.com"}}}}}}, Objectives: []ComponentObjective{{ComponentID: "api", Delivery: schema.DirectStrategy}, {ComponentID: "video", Delivery: schema.DirectStrategy}}, ReviewedSeeds: []string{"youtubei.googleapis.com"}, Maturity: "experimental", Owner: "b4", Controls: []string{"gmail-inbox", "google-feed-load", "concurrent-youtube-controls"}}
}
