package serviceprofile

import "github.com/daniellavrushin/b4/serviceprofile/schema"

func TelegramPack() StarterPack {
	return StarterPack{Manifest: schema.Manifest{SchemaVersion: 1, ID: "telegram", Name: "Telegram", Classification: "transport-required", Components: []schema.Component{{ID: "messaging", Delivery: schema.ClientConfigured, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "telegram-dc", Role: "primary", Domains: []string{"telegram.org"}}}}}}, Objectives: []ComponentObjective{{ComponentID: "messaging", Delivery: schema.ClientConfigured}}, Maturity: "experimental", Owner: "b4", Controls: []string{"direct-dc-connectivity", "transport-health", "failover"}}
}
