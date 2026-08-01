# B4X Architecture Compliance Report

**Audit artifact:** B4X_ARCHITECTURE_COMPLIANCE_REPORT
**Date:** 2026-07-31

Reference design: B4_FORK_ARCHITECTURE_v2.4.md (SHA-256: 815d1069...)

---

## 1. Directed control/data flow (ARCH §6)

Required flow: visibility/identity → passive observation → authoritative diagnosis → bounded candidate search → scoped authorization → canary/path proof → promote/rollback

**Compliance: PARTIAL → FAIL**

- capture/classifier (visibility/identity): reachable via nfq (transitive) — appears implemented
- monitor (passive observation): NOT wired into nfq packet path (B4X-AUDIT-0010)
- detector (authoritative diagnosis): reachable via discovery but not on packet path
- discovery (bounded candidate search): reachable (main.go imports discovery)
- authorization (scoped authorization): legacy watchdog bypasses (B4X-AUDIT-0005)
- canary/promote/rollback: runtimecontrol reachable via HTTP but legacy watchdog doesn't use it

## 2. Forbidden shortcut paths (ARCH §6)

Forbidden: IP candidate → destructive action; monitor failure → Discovery/config mutation; BlockingProfile → direct production strategy; profile manifest → capability lifecycle mutation; transport connect success → promotion without path proof

**Compliance: FAIL**

- monitor failure → Discovery/config mutation: EXACTLY what watchdog does (B4X-AUDIT-0005: healBatch → applyBatchResults → cfg.Sets mutation)
- The forbidden shortcut is the production runtime path

## 3. Service ownership (ARCH §53)

- TransportService (WARP lifecycle): FAIL — warp/ disconnected (B4X-AUDIT-0002)
- ServiceProfileCompiler: FAIL — serviceprofile/ disconnected (B4X-AUDIT-0003)
- MonitorService: FAIL — not wired into packet path (B4X-AUDIT-0010)
- TransactionalRuntime: PARTIAL — reachable via HTTP but legacy watchdog bypasses it
- RecoveryService: needs verification (silentpath/ exists, 18 files)

## 4. Safety invariants (ARCH)

- "Legacy direct Watchdog apply MUST быть удалён до MON_PRODUCTION_READY" (ARCH §2232): FAIL (B4X-AUDIT-0005)
- "Legacy direct Discovery/apply and automatic watchdog-* set mutation are prohibited in production-safe mode" (ARCH ADR-014): FAIL
- TGB delayed-first-data FSM (ARCH §70B): FAIL (B4X-AUDIT-0007)

## 5. Post-v2.3 subsystem rollout (ARCH §93A)

Required phases: A (shared schemas) → B (cross-service/GSO/PPE) → C (Monitoring shadow) → D (manual ABD) → E (diagnostic cutover) → F (DDI/guided Discovery) → G (base WARP + Service Profile) → H (API/UI cutover from legacy Watchdog) → I (auto-canary) → J (experimental camouflage/nested non-RU)

**Compliance: FAIL**

- Phase H (API/UI cutover from legacy Watchdog): NOT DONE — legacy watchdog still direct apply
- Phase G (base WARP + Service Profile): NOT DONE — both disconnected
- "direct Watchdog apply MUST быть удалён до MON_PRODUCTION_READY": NOT DONE

## Overall architecture compliance: NOT COMPLIANT
