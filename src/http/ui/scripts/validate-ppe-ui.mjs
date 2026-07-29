import fs from "node:fs";

const read = (path) => fs.readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const panel = read("src/components/classifier/PPEPanel.tsx");
const api = read("src/api/classifier.ts");
const en = JSON.parse(read("src/i18n/ppe.en.json"));
const ru = JSON.parse(read("src/i18n/ppe.ru.json"));

const requiredEndpoints = [
  "/api/v1/capture/offload/status",
  "/api/v1/capture/offload/apply",
  "/api/v1/capture/offload/rollback",
  "/api/v1/capture/offload/self-test",
  "/api/v1/capture/offload/issue-bundle",
];
for (const endpoint of requiredEndpoints) {
  if (!api.includes(endpoint)) throw new Error(`missing PPE endpoint ${endpoint}`);
}
if (!panel.includes("expected_generation")) throw new Error("PPE mutations are not generation-bound");
if (!panel.includes("ppeRollback")) throw new Error("UI rollback control missing");
if (!panel.includes("advanced")) throw new Error("advanced PPE controls missing");
for (const translations of [en.ppe, ru.ppe]) {
  for (const key of ["beginnerSafety", "toggle", "noGlobalClaim", "runSelfTest"]) {
    if (!translations[key]) throw new Error(`missing PPE translation ${key}`);
  }
}
const combined = `${en.ppe.beginnerSafety}\n${ru.ppe.beginnerSafety}`.toLowerCase();
if (!combined.includes("не отключает") || !combined.includes("does not disable")) {
  throw new Error("beginner wording does not explicitly reject a global-offload claim");
}
console.log("PPE UI contract: PASS");
