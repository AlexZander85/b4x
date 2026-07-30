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

func DiscordPack() StarterPack { return basicPack("discord", schema.Hybrid, "discord.com") }
func InstagramPack() StarterPack {
	return basicPack("instagram", schema.DirectStrategy, "instagram.com")
}
func TwitchPack() StarterPack { return basicPack("twitch", schema.DirectStrategy, "twitch.tv") }
func basicPack(id string, mode schema.DeliveryMode, domain string) StarterPack {
	return StarterPack{Manifest: schema.Manifest{SchemaVersion: 1, ID: id, Name: id, Classification: "starter", Components: []schema.Component{{ID: "main", Delivery: mode, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: id, Role: "primary", Domains: []string{domain}}}}}}, Objectives: []ComponentObjective{{ComponentID: "main", Delivery: mode}}, Maturity: "experimental", Owner: "b4"}
}
