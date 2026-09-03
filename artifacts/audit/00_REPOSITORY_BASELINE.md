# B4X Repository Baseline Audit

**Audit artifact:** 00_REPOSITORY_BASELINE
**Auditor:** independent read-only audit agent
**Date:** 2026-07-31
**Mode:** read-only (no modifications to any tracked or untracked file)

---

## 1. Repository identification

| Field | Value |
|---|---|
| Repository URL (declared) | AlexZander85/b4x |
| Declared branch | agent/classifier-v2.3-capture-envelope |
| **Actual .git directory** | **ABSENT — no git repository present** |
| Verified commit SHA | **CANNOT VERIFY — no .git directory** |
| Commit timestamp | **CANNOT VERIFY** |
| Working tree state | Directory `D:\b4x` contains source files; no git index available |

### Critical baseline deviation

The working directory `D:\b4x` does **NOT** contain a `.git` directory. `Test-Path D:\b4x\.git` returns `False`. All git commands fail with `fatal: not a git repository`.

**Impact:** It is impossible to verify: the checked-out branch; the HEAD commit SHA; the commit timestamp; staged/modified/untracked files; commit history; evidence binding to a specific commit.

The directory contains a source tree snapshot with no git metadata. Per audit spec §1 and §2.3, evidence cannot be bound to a commit SHA. This is recorded as **B4X-AUDIT-0001** (CRITICAL).

The files present correspond to module `github.com/daniellavrushin/b4` (per `src/go.mod`). The architecture document declares base commit `7160ee8f066bbbed1c713b4d0114db4e8acbc882` but this cannot be independently verified.

---

## 2. Toolchain and environment

| Tool | Status |
|---|---|
| Go toolchain | **NOT INSTALLED** — `go`, `where.exe go`, `Get-Command go` all fail |
| GOPATH / GOROOT | empty / unset |
| staticcheck / linters | not available (no Go toolchain) |
| git | installed but no repository to operate on |
| Target OS | win32 (audit host); production target is Keenetic/Entware Linux + Android |
| Go version (declared in go.mod) | go 1.25.3 |

**Impact:** `go build`, `go test`, `go vet`, `go test -race`, fuzzing, and mutation tests **cannot be executed**. All test execution is **BLOCKED**. Static analysis is limited to grep/regex source search and file reading.

---

## 3. Normative documents present (all 13)

All 13 mandatory normative documents are present in the repository root `D:\b4x`.

| # | Document | SHA-256 | Lines | Size |
|---|---|---|---|---|
| 1 | B4_FORK_ARCHITECTURE_v2.4.md | 815d1069...8cb5e0f | 2234 | 101603 |
| 2 | B4_FORK_PATCH_PLAN.md | 220f2c67...64a627eb | 1172 | 33265 |
| 3 | B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md | e3d42ec6...1d29fe5 | 817 | 28158 |
| 4 | B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md | 32dc0cc7...cfe0f038 | 813 | 36080 |
| 5 | B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md | 00ce13ec...0116c46e | 966 | 41354 |
| 6 | B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md | 1641a3b7...73974730 | 1674 | 55871 |
| 7 | B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md | 87c909d5...51f8ed3d | 3788 | 123940 |
| 8 | B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md | 98f5dcc5...4104881 | 3302 | 133646 |
| 9 | B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md | e7d42411...4b5ea845 | 1917 | 65216 |
| 10 | B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md | 4737371d...3a30976 | 1406 | 51322 |
| 11 | B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md | 8a384053...723982a | 2774 | 121737 |
| 12 | B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md | b5ee9919...f9961b7 | 3376 | 136376 |
| 13 | B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md | 5b7cac02...44e5a60 | 2621 | 101097 |


---

## 4. Source tree overview

- Module: `github.com/daniellavrushin/b4` (`src/go.mod`, go 1.25.3)
- Go source files: **783** (including tests)
- Production root: `src/main.go` — package `main`, entry `func main()` → `rootCmd.Execute()` → `runB4()`

### Packages in `src/` (46 packages)

action, ai, capture, classifier, clock, config, crossservice, detector, dhcp, diagnostics, discord, discovery, dns, engine, fieldtest, fixtures, geodat, http, lab, leaktest, log, metrics, monitor, mtproto, netprobe, nfq, observability, packetmark, quic, routing, runtimecontrol, serviceprofile, silentpath, sni, sock, socks5, stun, tables, tlsgen, tools, tproxy, tun, utils, validation, warp, watchdog

### Existing reports / docs

- `docs/audit/PPE_IMPLEMENTATION_AUDIT.md` (pre-existing self-audit)
- `docs/reports/warp/` — WARP implementation/validation/camouflage reports (self-reported)
- `docs/reports/mon-11-compatibility-cutover.md` — claims `applyBatchResults` is disabled in production-safe path
- `docs/runtime/` — transactional-control-plane, domain-authorization-contract, warp-trace-schema-v2, warp-transport-contract
- `docs/validation/` — rst-gso-h10, keenetic-android-v23, gmail-google-negative-controls, warp-field-matrix

---

## 5. Production root wiring analysis (main.go runB4)

The production startup path `runB4()` (`src/main.go:86`) directly imports and initializes only:

| Package | Initialized? | Role |
|---|---|---|
| `config` | yes | config load/reload |
| `ai` | yes | AI assistant |
| `discovery` | yes | Discovery sandbox runtime |
| `tproxy` | yes | TPROXY listener |
| `mtproto` | yes | MTProto bridge |
| `nfq` | yes | NFQUEUE packet processing |
| `quic` | yes | QUIC handling |
| `socks5` | yes | SOCKS5 server |
| `tables` | yes | iptables/nftables |
| `tun` | yes | TUN device |
| `watchdog` | **yes** | **LEGACY watchdog — direct apply path** |
| `geodat` | yes | geodata scheduler |
| `http/handler` | yes | REST API + handlers |

**Packages NOT imported by main.go:** capture, classifier, action, monitor, detector, crossservice, silentpath, serviceprofile, validation, fieldtest, warp, observability, runtimecontrol, packetmark, leaktest, lab, netprobe, sni, routing, diagnostics

### Transitive reachability from main.go (verified via import-graph search)

| Package | Reachable? | Via |
|---|---|---|
| `capture` | YES (transitive) | nfq, discovery, tables, tun import capture |
| `classifier` | YES (transitive) | nfq, dns, action, diagnostics, silentpath import classifier |
| `observability` | YES (transitive) | nfq, action, discovery, runtimecontrol import observability |
| `runtimecontrol` | YES (HTTP handler) | http/handler/runtime_control.go registers routes |
| `detector` | YES (HTTP + discovery) | http/handler/detector.go; discovery/diagnostic_profile.go |
| `monitor` | PARTIAL (via discovery only) | discovery/diagnostic_profile.go; NOT wired into nfq packet path |
| `crossservice` | YES (HTTP handler) | http/handler/classifier_isolation.go |
| `warp` | **NO — ZERO IMPORTERS** | no file imports warp |

---

## 6. Dead code, stubs, and disconnected packages

### 6.1 Completely disconnected packages (zero importers)

**`warp/` package** — **B4X-AUDIT-0002 (CRITICAL)**
- 36 Go files, but **no other package imports it** (search for `github.com/daniellavrushin/b4/warp` returns zero results across all 1299 files)
- Files are stubs: `enrollment.go` (13 lines, struct+Valid only), `secrets.go` (67 lines, in-memory map), `tun.go` (50 lines, in-memory registry), `routing.go` (44 lines, mark allocator with `next++`), `product.go` (33 lines, status struct)
- No real Cloudflare WARP enrollment, no real TUN device lifecycle, no kernel routing/marks
- Tests exist but only test struct `Valid()` methods — no production path

**`serviceprofile/` package** — **B4X-AUDIT-0003 (CRITICAL)**
- 21 Go files, but **no other package imports it** (search returns zero results)
- Files are small stubs: `capability.go` (18), `controls.go` (13), `gso_rst.go` (15), `telegram.go` (5), `objectives.go` (20), `import_export.go` (20), `packs.go` (21)
- No compiler that produces real B4 objects, no runtime consumer

### 6.2 Stub-only validation package

**`validation/` package** — **B4X-AUDIT-0004 (HIGH)**
- `ppe.go` (9 lines): struct with `Ready()` only
- `profiles.go` (8 lines): struct with `Ready()` only
- `safety.go` (9 lines): struct with `Ready()` only
- `verdict.go` (47 lines): `Aggregate()` and `DetectFalsePass()` are pure functions taking manually-populated `StageResult` slices
- **No validation runner, no suite registry execution, no artifact binding, no commit binding**
- This is the "manually populated validation object" anti-pattern (audit spec §5.1)

### 6.3 Legacy watchdog direct-apply path still in production

**B4X-AUDIT-0005 (CRITICAL)**
- `main.go:392-422`: `wd := watchdog.New(...)` → `wd.Start()` — legacy watchdog IS production runtime
- `watchdog/watchdog_heal.go:111`: `applyBatchResults(freshCfg, domains, cs, w.saveFunc)` — direct config mutation
- `watchdog/applier.go:18`: `applyBatchResults()` directly mutates `cfg.Sets`
- `watchdog/applier.go:128`: creates `watchdog-<domain>` sets
- `watchdog/applier.go:136`: `cfg.Sets = append([]*config.SetConfig{&newSet}, cfg.Sets...)`
- **Normative prohibition:** MON addendum line 1489: "`applyBatchResults()` MUST be disabled in production-safe mode"; ARCH line 2232: "direct Watchdog apply MUST быть удалён до MON_PRODUCTION_READY"; ARCH ADR-014 line 2993: "Legacy direct Discovery/apply and automatic watchdog-* set mutation are prohibited in production-safe mode"
- **The code violates its own normative documents.**

### 6.4 First-success / BestSuccess pattern

**B4X-AUDIT-0006 (HIGH)**
- `watchdog/applier.go:25`: `!dr.BestSuccess` — uses first successful result
- `watchdog/watchdog_heal.go:130`: `if dr != nil && dr.BestSuccess`
- This is the "first successful IP hides failures of other endpoints" anti-pattern (audit spec §5)

---

## 7. Working-tree integrity

- **Before audit:** directory D:\b4x contains source files; no git index; `artifacts/audit/` did not exist
- **During audit:** auditor created `artifacts/audit/` directory and `_source_file_index.txt` (untracked audit artifact only)
- **No tracked files modified** (read-only mode respected)
- **No production code, tests, configs, or docs modified**

---

## 8. Summary of baseline findings

| Finding ID | Severity | Summary |
|---|---|---|
| B4X-AUDIT-0001 | CRITICAL | No .git directory — cannot verify branch/commit SHA; evidence not bindable to commit |
| B4X-AUDIT-0002 | CRITICAL | warp/ package completely disconnected (zero importers); stub implementations only |
| B4X-AUDIT-0003 | CRITICAL | serviceprofile/ package completely disconnected (zero importers); stub implementations only |
| B4X-AUDIT-0004 | HIGH | validation/ package is stub-only; no runner, no suite execution, no commit binding |
| B4X-AUDIT-0005 | CRITICAL | Legacy watchdog applyBatchResults() direct config mutation still in production main.go; violates MON §59 and ARCH ADR-014 |
| B4X-AUDIT-0006 | HIGH | Watchdog uses BestSuccess/first-success pattern hiding other endpoint failures |

