# FB27 — GSO Readiness Evidence (GSO_CLASSIFY_READY verdict, GSO_RUNTIME_READY / ActionAuthorization gates, production entry point)

**Task:** FB-27 «GSO pipeline closure» (B4X_AUDIT_FIX_TASKS v2.md §FB-27; B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md §H3–H5). Трекер: b4x-95i.
**Criterion covered:** §H3 «GSO observe и classify fast path» (verdict-gated classify: READY → classify; UNKNOWN/STALE/FAIL → auto-downgrade) + §H4 «Conditional GSO normalizer и first-pass token» (normalization требует GSO_RUNTIME_READY + ActionAuthorization + single-use token) + §H5 «Transactional GSO queue topology» (production runtime API).
**Commit SHAs:** D1+D2 = `53be408a`; D3 = `44beac3c` (ветка `agent/classifier-v2.3-capture-envelope`, pushed).
**Created:** 2026-08-02
**Environment:** Windows host + Linux Docker (golang:1.25-alpine build/vet/test; golang:1.25 race) reference CI. `go build ./... && go vet ./... && go test ./...` — 43 пакета ok; `go test -race ./nfq/ ./http/handler/` — ok.

## Semantics (модель evidence)

- `GSOReadinessEvidence` разделяет **wire-наблюдения** (packet path, sticky: OR-merge, переживают любое `Set`) и **static proof** (оператор/control plane, заменяемо).
- «Не проверено» (`UNKNOWN`) ≠ «нарушено» (`FAIL`): раздельные флаги `*Proven` и `*Violated`.
- Verdict `GSO_CLASSIFY_READY` — **current-generation**: при несовпадении `ConfigGeneration` или возрасте evidence > 30 s (default staleness) — `STALE` → auto-downgrade.
- Classify разрешает только classification на GSO-представлении; **mutation/normalization** дополнительно требуют `FullActionReady` (GSO_RUNTIME_READY) + single-use токен + digest-совпадение Authorization/EffectivePolicy.
- Auto-downgrade идемпотентен и считает `nfqueue_gso_transition_total{transition=classify-to-observe, reason=classify-ready-stale|fail|unknown}` (регистрируется в hard-gate registry, row 12 матрицы FB03).

## Verification commands (executed)

```powershell
# 1. Build + vet + full suite (reference CI)
docker run --rm -v "D:\b4x:/src" -w /src/src golang:1.25-alpine sh -c "go build ./... && go vet ./... && go test ./..."
#    -> 43 packages ok, 0 FAIL

# 2. Race on the touched subsystems
docker run --rm -v "D:\b4x:/src" -w /src/src golang:1.25 sh -c "go test -race ./nfq/ ./http/handler/"
#    -> ok (nfq 1.107s, http/handler 1.217s)

# 3. Handler API contract
docker run --rm -v "D:\b4x:/src" -w /src/src golang:1.25-alpine go test -run 'TestClassifierGSOReadiness' ./http/handler/ -v
#    -> PASS (mutation → READY snapshot; operator generation rejected; 400/405 paths)
```

## Evidence facts

| # | Fact | Type | Persistence | Source (production) | Effect on snapshot | Test |
|---|------|------|-------------|--------------------|--------------------|------|
| 1 | `MetadataEnvelopeSeen` | wire | sticky | `nfq/gso_readiness.go:205` `observeGSOReadinessMetadata` (вызывается из `offload.go` на GSO-пакетах) | `MetadataEnvelopeReady` | `TestWorkerGSOReadinessEvidenceMerge`, `TestWorkerGSOReadinessSnapshotInstanceAndEnvelope` |
| 2 | `TruncationObserved` | wire | sticky | то же; `OffloadMetadata.Truncated` с `OriginalLength > PayloadLength` | FAIL; `MetadataEnvelopeReady=false` | `TestGSOClassifyFastPathFailsOpenWithoutCapabilityOrCompleteInput` (truncated → input fail-open) |
| 3 | `ChecksumNotReadyObserved` | wire | sticky | то же; csum-not-ready флаг envelope | FAIL | gso_readiness_test.go (FAIL-кейсы) |
| 4 | `RepresentationParityProven` | static | replaceable | оператор через API | `RepresentationParityReady` | `TestEvaluateGSOClassifyReadinessReady` |
| 5 | `IPv4Ready` | static | replaceable | оператор через API | `IPv4Ready` | `TestGSOClassifyFastPathIPv6Parity` (IPv6), `TestEvaluateGSOClassifyReadinessReady` |
| 6 | `IPv6State` (`"proven"`/`"unsupported"`/`""`) | static | replaceable | оператор через API; `"unsupported"` — допустимый stack property | `IPv6State` | `TestEvaluateGSOClassifyReadinessIPv6UnsupportedAllowed` |
| 7 | `RetransmissionProven` | static | replaceable | оператор через API | `RetransmissionReady` | `TestEvaluateGSOClassifyReadinessReady` |
| 8 | `ResourceBudgetsProven` / `ResourceBudgetViolated` | static / wire | replaceable / sticky | оператор / packet path | `ResourceBudgetsReady`; violation → FAIL | READY-кейсы, FAIL-кейсы |
| 9 | `QueueDropBudgetProven` / `QueueDropBudgetViolated` | static / wire | replaceable / sticky | оператор / packet path | `QueueDropBudgetReady`; violation → FAIL | READY-кейсы, FAIL-кейсы |
| 10 | `PPEVisibilityState` (`"complete"`/`"incomplete"`/`"not-required"`) | static | replaceable | оператор через API | `PPEVisibilityState`; incomplete → FAIL | `TestEvaluateGSOClassifyReadinessFail` (PPE-incomplete) |
| 11 | `ProductionEntryPointVerified` | static | replaceable | оператор через API (подтверждает §H3 «production reachability») | `ProductionEntryPointVerified` | READY-кейсы |
| 12 | `ProcessInstanceID` (`b4-<uuid>`) | derived | после первого evidence | `gso_readiness.go:293` `gsoProcessInstanceIDLocked` | `ProcessInstanceID` (пусто до evidence) | `TestWorkerGSOReadinessSnapshotInstanceAndEnvelope` |
| 13 | `EvidenceHash` (`gso-<sha256 hex 12>`) | derived | детерминирован | `gso_readiness.go:168` `gsoReadinessEvidenceHash` | `EvidenceHash` | `TestEvaluateGSOReadinessDeterministicHash` |

## Gates

| Gate | Condition | Non-satisfied behavior | Production location | Tests |
|------|-----------|------------------------|--------------------|----|
| `GSO_CLASSIFY_READY` | `gsoClassifyReady(gen)` — evidence текущей генерации, возраст ≤ 30 s | classify не входит: capability-fail-open + `downgradeGSOCapability` (idempotent) | `gso_readiness.go:239` (verdict), `:271` (downgrade); вызов в `gso_fastpath.go` | `TestGSOClassifyFastPathFailsOpenWithoutCapabilityOrCompleteInput`, `TestWorkerGSOClassifyReadyGateAndAutomaticDowngrade`, `TestWorkerGSOClassifyReadyGenerationMismatch` |
| `GSO_RUNTIME_READY` (mutation) | `FullActionReady` + `gsoClassifyReady(gen)` | action-suppressed, токен не создаётся | `gso_normalizer.go:72` `gsoRuntimeReadyForExecution`; `gso_fastpath.go` mutation-гейт | `TestGSONormalizerMutationRequiresFullActionCapability` (first-pass suppress), `TestGSONormalizerSecondaryRequiresRuntimeReady` |
| Authorization revocation | `authorizationDigestForGSO(flow,setID,gen) == token.AuthorizationID` | fail-open `authorization-revoked` | `gso_normalizer.go:57-58` | `TestGSONormalizerSecondaryRejectsRevokedAuthorization` |
| Policy revocation | `effectivePolicyDigestForGSO(setID, cfg.EffectiveDomainPolicy(set)) == token.EffectivePolicyID` | fail-open `policy-revoked` | `gso_normalizer.go:61-62` | `TestGSONormalizerSecondaryRejectsRevokedPolicy` |

## Production entry point (D3, commit `44beac3c`)

```text
POST /api/v2/classifier/gso/readiness      (handler: src/http/handler/classifier_gso_readiness.go)
GET  /api/v2/classifier/hardening          (snapshot: GSO.readiness, src/http/handler/classifier_hardening.go)
```

- Операционный гейт: `runtimeControlOperationalGate` (Discovery active / Watchdog enabled → 409 Conflict).
- Операторская `Generation` принудительно обнуляется: evidence привязывается к **активной генерации каждого воркера** (`Pool.SetGSOReadinessEvidence`, `gso_readiness.go:321`; worker bind `:184` при `Generation==0`) — защита от вечного STALE при рассинхронизации.
- Wire-наблюдения через API не принимаются (sticky, NFQ-owned). Static proof — единственное, что принимает API.
- Применяется ко всем воркерам пула; ответ — worst-snapshot (`{api_version, applied_workers, generation, evaluated_at, snapshot}`).

Пример запроса:

```json
{"evidence":{"metadata_envelope_seen":true,"representation_parity_proven":true,"ipv4_ready":true,"ipv6_state":"proven","retransmission_proven":true,"resource_budgets_proven":true,"queue_drop_budget_proven":true,"ppe_visibility_state":"complete","production_entry_point_verified":true}}
```

## Test matrix (FB-27)

| File | Tests | Coverage |
|------|-------|----------|
| `src/nfq/gso_readiness_test.go` | 9 | READY / UNKNOWN / FAIL×5 (truncation, checksum, resource budget, queue drop, PPE incomplete) / IPv6-unsupported не FAIL / детерминированный hash / gate+downgrade / generation mismatch → STALE / instance id + envelope / sticky-merge |
| `src/nfq/gso_runtime_ready_test.go` | 5 | first-pass suppress; secondary runtime-not-ready; authorization-revoked; policy-revoked; valid consume |
| `src/nfq/gso_fastpath_test.go` | 9 (вкл. D3 `TestGSOClassifyFastPathIPv6Parity`) | GSO flag mode/scope gating; accept unchanged (1988/4/16/32 KiB); action suppress; routing-only; fail-open без capability/при truncation; observe shadow-only; IPv6 parity (flow key L3Family=6) |
| `src/nfq/gso_token_test.go` | 8 | canonical token, scope, first-pass+secondary → FullActionReady+evidence |
| `src/nfq/topology_test.go` | 3 (вкл. D3 rollback invalidation leak) | shared state; off-режим без normalizer; `InvalidateTokens()` очищает общий store без утечки |
| `src/http/handler/classifier_gso_readiness_test.go` | 2 (D3) | mutation → READY + hardening отражает verdict; операторская generation отвергается; 400 unknown field; 405 GET |

## Scope / остатки

- Полевой evidence (Keenetic target + Android/Chrome) для target-scoped release claims — вне рамок этого артефакта: fail-closed валидатор требует реальные field inputs (docs/reports/implementation-validation-v1.5.md).
- Wire-наблюдения верифицируются на реальном устройстве; в CI они покрыты fixtures (packet path), не живым трафиком.
