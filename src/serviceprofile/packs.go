package serviceprofile

import (
	"strconv"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

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

// Custom templates (SP v1.6 §17 "Custom templates"): pre-filled manifests that
// let a user author their own profile without writing a manual manifest.
// They differ from starter packs by classification "custom" and by accepting
// the user-supplied domain instead of shipping a hardcoded one.

// CustomDomainGroupPack = a user-selected domain group behind one component,
// directly observed. The caller supplies the intended primary domain.
func CustomDomainGroupPack(id, domain string) StarterPack {
	return customPack(id, schema.DirectStrategy, schema.ExecutionObserve, domain)
}

// CustomStreamingServicePack mirrors the video streaming pattern (media CDN
// domain) with streaming-safe observe execution.
func CustomStreamingServicePack(id, domain string) StarterPack {
	return customPack(id, schema.DirectStrategy, schema.ExecutionObserve, domain)
}

// CustomAPIPlusMediaPack covers a service split into an api component and a
// media component, both observed directly.
func CustomAPIPlusMediaPack(id, apiDomain, mediaDomain string) StarterPack {
	return customPack(id, schema.DirectStrategy, schema.ExecutionObserve, apiDomain, mediaDomain)
}

// CustomTransportRequiredServicePack marks a service that needs a configured
// client transport (MTProxy/SOCKS5/…): the manifest forces ClientConfigured
// delivery and observe execution, so a packet executor is never set up.
func CustomTransportRequiredServicePack(id, domain string) StarterPack {
	return customPack(id, schema.ClientConfigured, schema.ExecutionObserve, domain)
}

func customPack(id string, mode schema.DeliveryMode, exec schema.ExecutionPolicy, domains ...string) StarterPack {
	var components []schema.Component
	for i, d := range domains {
		components = append(components, schema.Component{ID: id + "-c" + strconv.Itoa(i+1), Delivery: mode, Execution: exec, Targets: []schema.Target{{Name: id + "-" + d, Role: "primary", Domains: []string{d}}}})
	}
	return StarterPack{Manifest: schema.Manifest{SchemaVersion: 1, ID: id, Name: id, Classification: "custom", Components: components}, Maturity: "experimental", Owner: "b4"}
}
