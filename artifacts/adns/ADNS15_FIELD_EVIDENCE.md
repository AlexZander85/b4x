# ADNS-15 — Field evidence status

**Verdict: BLOCKED_BY_TARGET** (per stage DoD: missing target evidence returns
BLOCKED_BY_TARGET, not PASS).

## What is proven

- ADNS-1…ADNS-14 code complete: canonical model, providers (native classic,
  native encrypted, managed DNSCrypt backend), differential detector,
  selection/scoring/priors, DNSPathManager transactional binding, monitoring
  failover/recovery, API `/api/dns/v1/*` (incl. artifacts endpoint),
  FaultLab validation-of-validation suite, config schema + validation
  (default-safe: `mode=current`, adaptive off).
- Go: `go build ./...`, `go vet`, targeted + full test suites green.
- UI panel for adaptive DNS control plane added (beginner status + advanced
  policy, honest verdict per §20). UI build not executed in the offline
  sandbox — `pnpm install` cannot reach the registry; CI must run
  `pnpm build` (dist/ is gitignored, built in CI per .gitignore note).

## What is NOT proven (requires live targets)

- Real Keenetic router architecture/resource proof (managed backend budgets,
  loopback lifecycle on MIPS/ARM target).
- Real Android source-scoped canary.
- Shadow → canary → controlled cutover on the production router.

Per repo rules (AGENTS.md): live-router deploys happen one ladder layer per
session, only with owner direction. No deploy attempted.
