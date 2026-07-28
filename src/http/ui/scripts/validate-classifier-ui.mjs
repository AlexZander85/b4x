import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(root, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const readRepo = (relative) => fs.readFileSync(path.join(repoRoot, relative), "utf8");

const app = read("src/App.tsx");
const page = [
  "Page.tsx",
  "OverviewPanel.tsx",
  "FlowsPanel.tsx",
  "DryRunPanel.tsx",
  "DiscoveryPanel.tsx",
  "FailureInboxPanel.tsx",
  "ClientHelloPanel.tsx",
  "RolloutPanel.tsx",
  "shared.tsx",
].map((name) => read(`src/components/classifier/${name}`)).join("\n");
const api = read("src/api/classifier.ts");
const model = read("src/models/classifier.ts");
const en = JSON.parse(read("src/i18n/classifier.en.json"));
const ru = JSON.parse(read("src/i18n/classifier.ru.json"));
const handlers = [
  readRepo("http/handler/observability.go"),
  readRepo("http/handler/failure_inbox.go"),
  readRepo("http/handler/clienthello_lab.go"),
  readRepo("http/handler/classifier_v23.go"),
].join("\n");

assert.match(app, /path="\/classifier"/);
assert.match(app, /labelKey: "core\.nav\.classifier"/);
assert.equal(en.core.nav.classifier, "Classifier");
assert.equal(ru.core.nav.classifier, "Классификатор");

const requiredTabs = ["overview", "flows", "dryRun", "discovery", "inbox", "lab", "rollout"];
for (const tab of requiredTabs) {
  assert.ok(en.classifier.tabs[tab], `missing EN classifier tab ${tab}`);
  assert.ok(ru.classifier.tabs[tab], `missing RU classifier tab ${tab}`);
}

for (const endpoint of [
  "/api/v2/classifier/config",
  "/api/diagnostics/issue-bundle",
  "/api/diagnostics/failures",
  "/api/lab/clienthello",
]) {
  assert.match(api + handlers, new RegExp(endpoint.replaceAll("/", "\\/")));
}

assert.match(page, /evaluateStrategyDryRun/);
assert.match(page + model, /release_on_pressure|ReleaseOnPressure|releaseOnPressure/);
assert.match(page, /runtimeControlAvailable = false/);
assert.match(page, /disabled=\{!canControl\}/);
assert.doesNotMatch(page, /apiPut\([^)]*(promote|rollback|canary)/i);
assert.match(page + api, /confirm_raw/);
assert.match(page + api, /include_raw/);
assert.match(page, /offload_suspected/);
assert.match(page, /deriveFlowDiagnostics/);
assert.match(page, /clienthello/i);
assert.match(page, /baseline-none/);
assert.match(page, /captureCounters/);
assert.match(page, /actionCounters/);
assert.match(page, /lastGoodUnavailable/);
assert.match(page, /setId/);
assert.match(model, /set or strategy scope is required/);
assert.match(model, /maxAmplification/);

console.log("classifier UI contract: OK");
