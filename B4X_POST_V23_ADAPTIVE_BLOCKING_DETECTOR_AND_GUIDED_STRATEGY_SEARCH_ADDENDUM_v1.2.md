# B4X Post-v2.3 Adaptive Blocking Detector & Guided Strategy Search Addendum

**Версия:** 1.2  
**Дата:** 2026-07-30  
**Статус:** обязательный post-v2.3 companion addendum для B4X  
**База:** `B4_FORK_ARCHITECTURE.md` v2.3, завершённый `B4_FORK_PATCH_PLAN.md` v2.3, post-v2.3 companion addenda и B4X branch `agent/classifier-v2.3-capture-envelope`  
**Обязательная интеграция:** `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md` и `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md`  
**Изменения v1.2:** сохранена вся нормативная delta v1.1; добавлен pinned reference `belotserkovtsev/ladon`; введён строгий двусторонний контракт Continuous Monitoring ↔ ABD, `MonitorDiagnosticRequest`, `TargetPlanOverlay`, `ClientResolutionSnapshot`, per-address outcome vector, authority levels, stage-aware multi-vantage observers, разделение physical failure code и attribution, а также безопасный result handoff обратно в Monitoring  
**Область:** аудит и развитие встроенного B4 Detector, входы из Continuous Monitoring, пользовательские target plans и monitor overlays, exact client-resolution binding, multi-protocol differential probes, DNS/TLS/HTTP/QUIC/L4 evidence, stage-aware reference observers, evidence authority/attribution, evidence graph, confidence/exclusion model, `BlockingProfile`, безопасный result handoff, coverage-aware и resource-bounded передача priors в DDI/Discovery и измеримый guided strategy search  
**Главная пользовательская цепочка:** real-client monitoring или явный пользовательский запрос → bounded `MonitorDiagnosticRequest`/`TargetPlan` → чистая диагностика текущего WAN → доказательный `BlockingProfile` → DDI freshness/revalidation → приоритетный bounded Discovery → target-specific Android canary → promote/rollback  
**Главный safety-инвариант:** detector evidence изменяет порядок и budget поиска, но никогда не является самостоятельным разрешением на packet action, routing action или production promotion

---

## 0. Нормативный статус и место в проекте

Этот addendum вводит capability:

```text
adaptive-blocking-detector-and-guided-strategy-search
```

и companion stages:

```text
ABD-1 … ABD-12
```

где `ABD` означает **Adaptive Blocking Detector**.

Документ:

- не переоткрывает и не перенумеровывает Stage 1–36 патч-плана v2.3;
- не создаёт второй packet classifier;
- не создаёт второй strategy optimizer;
- не заменяет `DDI-1…DDI-10`;
- не изменяет независимый Telegram bridge track `TGB-1…TGB-10`;
- расширяет встроенный Detector до source of structured, scoped and confidence-bearing evidence;
- определяет `BlockingProfile`, который затем помещается в versioned `NetworkDiagnosticProfile` envelope и потребляется DDI;
- требует companion updates в Field Test, Service Profiles и umbrella Implementation Validation до production promotion;
- сохраняет `ABD-1…ABD-12`, включая все acceptance criteria v1.1;
- расширяет acceptance criteria stages `ABD-2`, `ABD-3`, `ABD-4`, `ABD-5`, `ABD-9`, `ABD-10`, `ABD-11` и `ABD-12` требованиями v1.2;
- не поглощает `MON-1…MON-12`: Continuous Monitoring остаётся отдельным source of passive observations, temporal state и diagnostic scheduling;
- определяет единственный нормативный adapter path `MonitorAssessment → MonitorDiagnosticRequest → ABD run → MonitorDiagnosticResult`.

### 0.1. Нормативная последовательность

```text
B4_FORK_ARCHITECTURE.md v2.3
→ B4_FORK_PATCH_PLAN.md Stage 1–36
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md
→ B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md
→ B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md
   ├─ MON-1…MON-7 observe, correlate and schedule
   └─ MON-8 requests bounded ABD execution through this addendum
→ этот addendum: ABD-1…ABD-12
→ B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md
   ├─ DDI-1…DDI-10 consume ABD output
   └─ TGB-1…TGB-10 remain independent
→ Field Test Automation update
→ Service Profiles / Beginner UX update
→ Implementation Validation update
→ production promotion
```

`ABD-1…ABD-10` MUST быть завершены до финального `DDI-7` guided search planner. `MON-8` MUST NOT получить production-ready verdict до `ABD_MONITOR_ADAPTER_READY`, но schema и shadow-ingestion части `MON-1…MON-7` MAY реализовываться параллельно. Допускается параллельная реализация schema/persistence частей DDI, но запрещено создавать несовместимую параллельную модель detector profile.

### 0.2. Приоритет требований

При расхождении требований в Detector/Discovery subsystem действует следующий порядок:

```text
B4_FORK_ARCHITECTURE.md v2.3
→ Cross-Service Isolation для scope и authorization
→ RST/GSO + PPE для capture correctness и visibility
→ Silent Path Failure для stall inference и false-positive suppression
→ Continuous Blocking Monitoring addendum для passive observations, temporal state и trigger ownership
→ этот addendum для активного Detector v2, BlockingProfile, monitor adapter и search priors
→ Detector-Guided Discovery addendum для freshness, API selection и planner merge
→ Field Test / Service Profiles / Implementation Validation как release gates
→ reference-project behavior notes
```

### 0.3. Нормативная delta к Detector-Guided Discovery addendum v1.0

Предыдущий документ сохраняет силу, но следующие ownership boundaries становятся обязательными:

| Область | Владелец после этого addendum |
|---|---|
| raw detector probe execution | `ABD` |
| user/service target planning | `ABD` |
| protocol evidence normalization | `ABD` |
| evidence graph, hypotheses, exclusions | `ABD` |
| `BlockingProfile` compiler | `ABD` |
| network-context envelope and reusable profile store | `DDI` |
| freshness, expiry and fast revalidation | `DDI` |
| profile selection API | `DDI` |
| immutable snapshot plumbing into Discovery | `DDI` |
| deterministic merge with current baseline | `DDI` |
| adaptive matrix, shadow probes and candidate scoring | existing Discovery/Optimizer |
| packet actions and routing actions | existing ActionPlanner/Transport control plane |
| Telegram bridge delayed-handshake lifecycle | `TGB`, unaffected |
| passive real-client observation intake | `MON` |
| temporal recurrence, decay, recovery and health state | `MON` |
| Failure Inbox / user-attention projection | `MON` |
| diagnostic trigger scheduling, cooldown and budget token | `MON` |
| validation of `MonitorDiagnosticRequest` | `ABD` |
| compilation of monitor overlay into a complete controlled `TargetPlan` | `ABD` |
| active exact-endpoint and independent-resolution experiments | `ABD` |
| structured result callback to monitoring | `ABD`, consumed by `MON` |

Нормативная модель становится следующей:

```text
DetectorSuiteV2
→ BlockingProfile
→ NetworkDiagnosticProfile envelope
→ DDI context/freshness/revalidation
→ DiscoverySearchPrior
→ existing adaptive Discovery matrix
```

В частности:

- прежний `DDI-2 — Versioned profile schema` MUST использовать `BlockingProfile` как payload, а не определять второй несовместимый evidence schema;
- прежний `DDI-4 — Profile compiler and persistence` MUST делегировать raw evidence → `BlockingProfile` компиляцию `ABD-10`, сохраняя ownership за envelope, persistence и migration;
- прежний `DDI-7 — Hint compiler` MUST принимать `DiscoverySearchPrior`, сформированный из `BlockingProfile`, и объединять его с текущим target baseline;
- `DDI` hard gates остаются обязательными и дополняются gates этого документа;
- `TGB-1…TGB-10` не зависят от `ABD` и не переопределяются.


### 0.3.1. Continuous Monitoring ↔ ABD ownership boundary

Нормативная цепочка v1.2:

```text
MonitorObservation
→ MonitorAssessment
→ DiagnosticTriggerDecision
→ MonitorDiagnosticRequest + budget token
→ ABD request validation
→ TargetPlanOverlay merge with Service Profile controls
→ clean active detector run
→ EvidenceGraph + BlockingProfile
→ MonitorDiagnosticResult
→ Monitoring updates diagnostic state
```

Monitoring сообщает **что и где наблюдал реальный клиент**, но не определяет окончательный экспериментальный план. ABD обязан дополнить monitor overlay:

- same-service controls;
- unrelated controls;
- alternative address-family experiment при применимости;
- exact client-resolution experiment;
- independent current-resolution experiment;
- reference observer experiment только при достаточной capability и health;
- native/direct clean baseline;
- completeness criteria для quick или deep режима.

Следующие объекты не взаимозаменяемы:

```text
MonitorAssessment
≠ MonitorDiagnosticRequest
≠ DiagnosticTargetPlan
≠ BlockingProfile
≠ NetworkDiagnosticProfile
≠ DiscoverySearchPrior
≠ ActionAuthorization
```

ABD MUST NOT:

- запускать бесконечный passive listener;
- владеть temporal health state сервиса;
- самостоятельно создавать subjects из каждого DNS query;
- изменять Monitoring assessment без структурированного result handoff;
- принимать устаревший request после смены WAN или ConfigGeneration;
- считать monitor recurrence независимыми active evidence families;
- использовать monitor trigger как разрешение на Discovery, WARP или packet mutation.

### 0.4. Общие запреты

B4X MUST NOT:

1. заменять текущий Detector внешним Python, PowerShell или сторонним binary runtime;
2. скачивать reference detector code или target lists во время обычного запуска без explicit update policy;
3. считать один timeout, EOF, RST или exception string достаточным доказательством DPI;
4. считать raw byte threshold точным packet threshold;
5. считать packet threshold точным byte threshold;
6. использовать только фиксированные public IP endpoints как вечный источник истины;
7. сканировать произвольные публичные адреса без bounded target policy и пользовательского действия;
8. создавать более одного optimizer/search planner;
9. применять detector recommendation непосредственно к production config;
10. разрешать найденный white SNI как production fake SNI без target-specific Discovery и canary;
11. игнорировать healthy same-service или unrelated controls;
12. использовать профиль после смены WAN context без DDI revalidation;
13. смешивать evidence разных IP family, TLS fingerprint, transport path или config generation;
14. выдавать `DPI confirmed`, когда доказан только generic path failure;
15. объявлять MITM, когда certificate verification фактически отключена;
16. объявлять L4 packet budget по HTTP header-size failure одного origin;
17. позволять detector probes проходить через уже активную обходную стратегию, если режим заявлен как native/direct baseline;
18. создавать collateral traffic или нагрузку, не ограниченную resource budget;
19. сохранять raw public IP, client address, SSID или sensitive DNS history в стандартный export;
20. отключать exhaustive bounded Discovery fallback только из-за detector hints;
21. объявлять `host_dead` по неуспеху одного reference path или одного proxy;
22. использовать reference path, proxy или WARP result как `ActionAuthorization`;
23. объявлять компонент доступным только по TLS handshake, HEAD или response headers, когда success milestone требует body/media progress;
24. терять partial body progress при inter-chunk stall или сворачивать его в безликий общий timeout;
25. считать фиксированный диапазон 10–25 KiB универсальным доказательством DPI data cap;
26. оптимизировать coverage между несвязанными Service Profiles или authorization scopes;
27. удалять failed/excluded targets из denominator без явного отчёта и причины;
28. увеличивать concurrency только ради scan throughput, игнорируя NFQUEUE drops, latency controls, RAM pressure или detector self-interference;
29. выпускать final `BlockingProfile` из cancelled, partial или resumed run без completeness proof;
30. принимать passive monitoring observation как завершённый active detector probe;
31. выпускать `BlockingProfile` только из provisional fast-lane evidence;
32. запускать monitor-request run без `NetworkContextID`, `ConfigGeneration`, expiry и budget token;
33. молча заменять client-observed DNS answer новым resolver result;
34. сворачивать частичные outcomes нескольких CDN IP в один first-success verdict;
35. сравнивать local HTTP-body failure с observer, умеющим только TCP/TLS;
36. считать недоступность observer доказательством недоступности target;
37. смешивать exact-endpoint и independent-resolution experiments в один causal claim;
38. возвращать monitor result без исходного `AssessmentID` и request identity;
39. превращать мониторинговое temporal recurrence в evidence independence;
40. позволять Monitoring result handoff обходить DDI freshness или Action control plane.

---

# Часть I. Reference projects, provenance и clean-room policy

## 1. Reference repositories

Поведение и полевые идеи изучаются по pinned read-only snapshots:

```yaml
references:
  - project: Shiperoid/YT-DPI
    commit: dd3ff36bf38a252a9fee79130836b19e5fcbc16c
    license: MIT
    roles:
      - user-selected target lists
      - TLS 1.2 / TLS 1.3 / HTTP matrix
      - low-level ClientHello diagnostics
      - target-oriented quick/deep UX
      - waterfall progress reporting

  - project: hyperion-cs/dpi-checkers
    commit: 8965b28125262366bd594b4bc95e14616411485f
    license: Apache-2.0
    roles:
      - l4-25 packet-budget research model
      - dynamic subnet/ASN/provider target farming
      - CIDR whitelist controls
      - browser TLS fingerprints
      - service/infrastructure/control sections

  - project: Runnin4ik/dpi-detector
    commit: 173d3af5cd0385f0db6113af86e3438931dd92f4
    license: MIT
    roles:
      - detailed staged error taxonomy
      - fresh-connection probes
      - DNS interception and ISP stub detection
      - TLS/HTTP redirect integrity
      - configurable domain targets

  - project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    release: 0.9.2
    license: MIT
    roles:
      - direct-versus-reference-egress aliveness comparison
      - HTTPS baseline that requires bounded body progress
      - preservation of partial downloaded bytes on inter-chunk stall
      - multi-domain strategy coverage ranking
      - repeated candidate verification and median performance reporting
      - resource-aware worker benchmark and cancellation-safe partial artifacts

  - project: belotserkovtsev/ladon
    commit: 8af5e68cadea16c177f17fb6a50f1e0b6931aa8d
    license: MIT
    roles:
      - demand-driven target intake from real client DNS activity
      - client-observed DNS/CNAME/IP correlation
      - provisional inline probe versus authoritative background result
      - stage-aware local/remote comparison
      - temporal recurrence and hysteresis inspiration
      - scoped domain-cohort diagnostic hints
```

### 1.1. License and attribution contract

По умолчанию используется clean-room behavioral reimplementation:

```text
observed behavior / research idea
→ B4X-specific normative contract
→ independent Go implementation
```

Прямое копирование кода допускается только если одновременно выполнены:

- отдельный source-level license review;
- сохранение required copyright/license notices;
- provenance entry с source path, commit и copied/adapted status;
- отсутствие incompatible dependency/runtime footprint;
- security review;
- deterministic tests против B4X contract.

Apache-2.0 reference code требует соблюдения NOTICE/patent-related условий при фактическом копировании. MIT references требуют сохранения copyright and permission notice в substantial copied portions.

### 1.2. Reference Extraction Registry

Каждая перенесённая идея MUST иметь запись:

```yaml
reference_extraction:
  id: abd-ref-l4-packet-budget-v1
  project: hyperion-cs/dpi-checkers
  commit: 8965b28125262366bd594b4bc95e14616411485f
  source_paths:
    - ru/dpi-ch/docs/README.md
  observed_behavior:
    - distinguish packet-count and byte-count triggers
    - dynamic host selection by network ownership filters
  copied_code: false
  b4x_components:
    - L4ThresholdProfiler
    - DynamicControlTargetProvider
  deviations:
    - exact resource budgets
    - capture-visibility gate
    - no automatic action authorization
  license_review: behavior-only
```

### 1.2.1. blockcheckw behavior extraction entries

```yaml
reference_extractions:
  - id: abd-ref-reference-egress-aliveness-v1
    project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    source_paths:
      - README.md
      - src/dto.rs
      - src/cmd/scan.rs
    observed_behavior:
      - compare direct SYN reachability with a separately health-checked proxy path
      - split unresolved IP failure into path-local reachability suspicion and origin-wide unreachability
    copied_code: false
    b4x_components:
      - ReferencePathProbe
      - ReferencePathEvidence
      - OriginReachabilityHypothesisCompiler
    deviations:
      - one reference failure never proves host death
      - exact target/IP-family/network-context identity required
      - reference result never grants routing authorization
    license_review: behavior-only

  - id: abd-ref-partial-body-progress-v1
    project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    source_paths:
      - src/network/http_client.rs
      - src/pipeline/baseline.rs
    observed_behavior:
      - require HTTPS body transfer rather than headers-only availability
      - preserve partial downloaded-byte count when inter-chunk progress stalls
    copied_code: false
    b4x_components:
      - BodyProgressEvidence
      - StagedTransferDeadline
      - ComponentAvailabilityMilestone
    deviations:
      - no fixed universal 16 KiB verdict window
      - unique bytes, expected length and range semantics are recorded
      - repeated target/control/reference-path proof required for strong hypotheses
    license_review: behavior-only

  - id: abd-ref-coverage-aware-ranking-v1
    project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    source_paths:
      - src/cmd/universal.rs
      - src/strategy/rank.rs
    observed_behavior:
      - rank candidates by multi-domain coverage
      - prefer structurally simpler strategies within equal coverage
    copied_code: false
    b4x_components:
      - CandidateCoverageVector
      - ScopedCoveragePlanner
      - CandidateComplexityCost
    deviations:
      - coverage cannot cross Service Profile or authorization scope
      - negative-control regressions dominate target coverage
      - excluded targets remain explicit in denominator and reports
    license_review: behavior-only

  - id: abd-ref-verification-funnel-v1
    project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    source_paths:
      - src/cmd/check.rs
      - src/pipeline/check.rs
      - src/dto.rs
    observed_behavior:
      - wide scan feeds a smaller data-transfer verification step
      - repeated passes produce stability and median performance summaries
    copied_code: false
    b4x_components:
      - CandidateVerificationFunnel
      - CandidateVerificationSummary
    deviations:
      - one transient failure does not permanently reject without failure classification
      - p95, p10 goodput, target variation and controls are retained
      - final promotion remains Android canary-gated
    license_review: behavior-only

  - id: abd-ref-capacity-calibration-v1
    project: rcd27/blockcheckw
    commit: 830c03733cfc1c1d595b9862c48c6151d75926cb
    source_paths:
      - src/cmd/benchmark.rs
      - src/pipeline/benchmark.rs
    observed_behavior:
      - benchmark scan throughput at several worker counts
      - include CPU/RAM availability and peak memory in recommendation
    copied_code: false
    b4x_components:
      - DetectorCapacityProfile
      - AdaptiveProbeScheduler
    deviations:
      - optimize for safety and latency, not raw throughput alone
      - include NFQUEUE drops, softirq, controls and PPE/GSO state
      - strict platform ceilings remain authoritative
    license_review: behavior-only
```


### 1.2.2. Ladon behavior extraction entries

Pinned source:

```text
belotserkovtsev/ladon
commit 8af5e68cadea16c177f17fb6a50f1e0b6931aa8d
```

Extracted behavioral ideas:

| Ladon behavior | B4X normative adaptation | Ownership |
|---|---|---|
| DNS-demand-driven target intake | bounded `ObservedDemandTarget` and `MonitorSubject` creation | `MON` |
| probe exact addresses returned to client | immutable `ClientResolutionSnapshot` plus `AttemptResolutionBinding` | `MON` captures, `ABD` consumes |
| inline quick probe | provisional fast lane that can only schedule authoritative ABD | `MON` |
| background authoritative comparison | bounded quick/deep ABD run with mandatory controls | `ABD` |
| local/remote comparison | capability-declared stage-aligned `MultiVantageComparison` | `ABD` |
| repeated verdict scoring | recurrence/hysteresis without false independence | `MON` |
| sibling-domain coverage | diagnostic priority hint only inside declared service/component cohort | `MON`, optionally referenced by `ABD` |

Clean-room restrictions:

- B4X MUST NOT copy Ladon’s direct `blocked → tunnel list` behavior;
- a first passive failure MUST NOT create WARP or strategy authorization;
- `TLS 1.3 failed / TLS 1.2 worked` MUST remain version/fingerprint asymmetry, not automatic ECH/SNI confirmation;
- generic TCP failure MUST NOT be collapsed into `DPI blocked`;
- remote failure MUST NOT be converted to `clear` without origin/multi-path uncertainty;
- broad eTLD+1 promotion MUST NOT occur from sibling observations;
- reference observer transport failure MUST be represented as `observer-unavailable`, not target failure.

### 1.3. No hidden remote dependency

B4X package MUST remain self-contained. Reference projects are not runtime dependencies. Any optional target-catalog update MUST use the common signed/catalog update mechanism, atomic replacement, last-good retention and rollback.

---

# Часть II. Audit текущего B4 Detector

## 2. Existing detector capabilities

Текущий B4 Detector уже предоставляет полезный нативный фундамент:

```text
TestDNS
TestDNSAvail
TestDomains
TestTCP
TestSNI
TestTelegram
```

Он выполняет пробы из процесса B4 с dedicated mark, сохраняет structured history и различает несколько failure stages.

### 2.1. DNS strengths

Текущая реализация умеет:

- выбирать доступный DoH server;
- выбирать доступный UDP resolver;
- сравнивать DoH и UDP A records;
- распознавать fake NXDOMAIN;
- распознавать empty answer;
- распознавать fake/local/stub IP patterns;
- выявлять повторяющийся stub IP на нескольких доменах;
- фиксировать DoH/UDP availability.

Это сохраняется и расширяется; переписывание с нуля запрещено без доказанного regression-free benefit.

### 2.2. Domain/TLS/HTTP strengths

Текущий Detector уже выполняет:

- forced TLS 1.3;
- forced TLS 1.2;
- TCP connect/handshake/read stage classification;
- bounded HTTPS read;
- HTTP/80 check;
- block-page redirect/body detection;
- basic cross-domain redirect detection;
- statuses `SYN_DROP`, `TLS_DROP`, `TLS_RST`, `TLS_SPOOF`, `TLS_ALERT`, `TLS_MITM`, `TCP16`, `ISP_PAGE` и другие.

### 2.3. TCP/SNI strengths

Текущий Fat Probe:

- использует persistent connection;
- постепенно увеличивает request payload/header size;
- измеряет RTT;
- применяет adaptive timeout;
- фиксирует approximate drop position;
- проверяет несколько infrastructure providers;
- может искать первый working SNI для affected ASN.

### 2.4. Telegram strengths

Отдельный Telegram check даёт:

- reachability DC endpoints;
- download/throughput evidence;
- `ok/slow/stalled/blocked/partial/error` verdicts.

Это полезно как service-specific evidence, но не заменяет transparent bridge validation или target-specific application test.

## 3. Verified gaps текущего Detector

### 3.1. API не принимает пользовательские targets

Current request conceptually equivalent to:

```go
type DetectorRequest struct {
    Tests []string
}
```

Отсутствуют:

- custom domains;
- Service Profile ID;
- component selection;
- primary/control target roles;
- quick/deep mode;
- IP family policy;
- fingerprint policy;
- direct/production comparison mode;
- resource budget;
- explicit consent for dynamic infrastructure targets.

### 3.2. Static target bias

Embedded `targets.json` содержит полезные, но фиксированные:

- domain lists;
- CDN redirect patterns;
- TCP target IPs;
- provider/ASN labels;
- white-SNI candidates;
- DNS providers;
- Telegram targets.

Fixed sentinels MAY сохраняться как regression anchors, но MUST NOT быть единственным evidence source.

### 3.3. Byte-only interpretation risk

Current Fat Probe увеличивает request data and reports `drop_at_kb`. Это не доказывает, что censor trigger основан на bytes. Возможны:

- bidirectional packet-count trigger;
- server header-size limit;
- WAF policy;
- keep-alive limit;
- origin close;
- path loss;
- middlebox idle/read timeout.

Новая реализация MUST измерять packet and byte dimensions separately.

### 3.4. Single-endpoint false-positive risk

Failure одного endpoint не должен становиться provider-wide hypothesis. Нужны:

- multiple independent targets;
- same-provider controls;
- unrelated controls;
- repeatability;
- fresh and persistent connection comparison;
- origin-behavior suppressors.

### 3.5. Standard Go ClientHello only

Forced TLS versions полезны, но стандартный Go ClientHello не покрывает:

- Android/Chrome ordering;
- Firefox ordering;
- GREASE behavior;
- browser ALPN sets;
- real captured ClientHello;
- minimal canonical control;
- extension-order-specific filtering.

### 3.6. Certificate integrity gap

Availability probe использует disabled certificate verification. Поэтому `TLS_MITM` нельзя считать validated verdict без отдельной verified-certificate path.

### 3.7. No QUIC detector track

Отсутствуют first-class:

- UDP/443 reachability;
- QUIC Initial response;
- Version Negotiation;
- Retry;
- handshake progress;
- HTTP/3 availability;
- QUIC fingerprint comparison;
- TCP-vs-QUIC causal result.

### 3.8. Aggregation loses causal detail

`Overall` удобен для UI, но недостаточен для optimizer. Например:

```text
TLS 1.2 = OK
TLS 1.3 = TLS_RST
HTTP/80 = OK
```

MUST компилироваться как version/fingerprint-specific hypothesis, а не generic domain blocked.

### 3.9. History is not reusable BlockingProfile

Raw history lacks:

- target plan identity;
- network context;
- capture visibility;
- direct-path proof;
- protocol fingerprint;
- packet/unique-byte counters;
- controls;
- contradictions;
- confidence;
- exclusions;
- profile version and content hash;
- expiry/revalidation state.

### 3.10. Detector self-interference risk

B4X MUST explicitly prove, для каждого probe mode, проходит ли traffic:

- native/direct bypass path;
- production strategy path;
- candidate sandbox path;
- transport fallback path.

Unlabeled path mixing invalidates evidence.

### 3.11. Direct-path failure does not distinguish path filtering from dead origin

Direct SYN/TLS failure alone cannot distinguish:

```text
path-local filtering
origin outage
address-family mismatch
stale DNS address
reference transport failure
```

Current Detector lacks a first-class, separately health-checked reference-egress comparison that preserves exact target, IP family and network context.

### 3.12. Headers-only success can hide unusable data path

TLS handshake, HEAD or HTTP headers MAY succeed while body/media progress stops after a bounded number of unique bytes. A whole-probe timeout that discards partial progress loses the most useful evidence for throttling, byte-window and silent-stall hypotheses.

### 3.13. Candidate scoring lacks an explicit coverage objective

A candidate that works for one domain is not necessarily suitable for all required components of one service. Current contracts do not explicitly model:

- required versus optional target coverage;
- unknown/excluded targets in denominator;
- negative-control regressions;
- minimal number of distinct strategy bindings;
- structural complexity cost.

### 3.14. Static parallelism and non-resumable deep runs

Fixed quick/deep concurrency is safe as a default but does not account for large differences between Keenetic models. Deep runs may be interrupted by WAN transitions, shutdown or resource pressure; completed evidence should survive safely without allowing an incomplete run to emit a final profile.

---


### 3.15. No normative Monitoring → Detector adapter

Текущий B4X имеет passive `FailureInbox`, observability и legacy Watchdog, но без v1.2 отсутствует единый typed request, связывающий:

```text
MonitorAssessment
→ exact client/service/component scope
→ network context and config generation
→ detector budget
→ TargetPlan overlay
→ active detector run
```

Без этого Monitoring либо остаётся только UI inbox, либо рискует повторить legacy путь `failure → Discovery`.

### 3.16. Client-observed resolution is not a first-class detector input

Повторный resolver lookup может вернуть другой CDN endpoint, чем тот, с которым столкнулся клиент. Detector должен различать:

```text
client-observed resolution
independent current resolution
```

и не выдавать общий verdict, если outcomes адресов различаются.

### 3.17. Reference observer stage mismatch risk

Reachability reference path v1.1 недостаточен для HTTP/body hypothesis. Observer, подтверждающий только TCP/TLS, не доказывает доступность HTTP body. Нужен capability contract и одинаковая required stage.

### 3.18. Physical outcome and causal attribution are mixed

Наблюдение `tcp_syn_timeout` описывает событие, но не доказывает виновника. Нужны отдельные поля:

```text
ProbeFailureCode
FailureAttribution
BlockingHypothesis
```

чтобы origin failure, path failure, observer failure и capture invalidity не смешивались.

### 3.19. No structured result handoff to Monitoring

Monitoring должен получить completion state, confirmed/contradicted/inconclusive targets, profile reference и validity envelope. Иначе assessment может остаться в `running` или переиспользовать результат другой сети.

# Часть III. Goals, non-goals и core invariants

## 4. Goals

B4X Detector v2 MUST:

1. начинаться с сервисов и доменов, которые нужны пользователю;
2. автоматически дополнять их service components и controls;
3. выполнять direct/native network baseline без влияния текущих bypass strategies;
4. собирать multi-protocol structured evidence;
5. различать DNS, route/IP, TCP, TLS, HTTP, QUIC, packet-budget, byte-window, throughput и silent-stall hypotheses;
6. оценивать confidence и хранить contradictions/exclusions;
7. использовать dynamic infrastructure controls при explicit bounded policy;
8. формировать immutable `BlockingProfile`;
9. отдавать `DiscoverySearchPrior`, а не готовую production strategy;
10. измерять, сократил ли profile поиск и сохранил ли тот же безопасный outcome;
11. оставаться bounded для Keenetic-class hardware;
12. поддерживать real Android fingerprint and field validation;
13. различать path-local reachability failure и origin-wide unreachability через independently health-checked reference path;
14. считать service/component available только после его declared application-progress milestone;
15. выбирать минимально сложный scoped candidate set, покрывающий обязательные targets без control regressions;
16. адаптировать concurrency к измеренной capacity, сохраняя deterministic hard ceilings и resumability.

## 5. Non-goals

Этот addendum не поручает:

- автоматически обходить любую блокировку без Discovery;
- заменять Service Profiles hardcoded logic в Detector;
- гарантировать определение оператора конкретного censor box;
- выполнять Internet-wide scanning;
- публиковать raw user network datasets;
- делать browser desktop detector runtime обязательным;
- считать geo/provider metadata доказательством censorship;
- давать destructive ActionAuthorization;
- менять TGB bridge lifecycle;
- обучать непрозрачную ML model без deterministic fallback and explainability.

## 6. Core invariants

```text
Observation ≠ Hypothesis
Hypothesis ≠ Confirmed failure mode
BlockingProfile ≠ ActionAuthorization
SearchPrior ≠ Strategy winner
Strategy winner ≠ Production promotion
```

```text
one target failure
≠ provider-wide censorship
```

```text
one endpoint success
≠ service availability
```

```text
same bytes, different packets
≠ same L4 trigger
```

```text
same SNI, different ClientHello fingerprint
≠ same DPI behavior
```

```text
fresh direct evidence
> stored profile assumption
```

```text
reference-path success
→ evidence of path differential
≠ route authorization
```

```text
TLS/HEAD/headers success
≠ component availability
```

```text
high target coverage
- any negative-control regression
→ candidate rejected
```

```text
partial run evidence
≠ final BlockingProfile
```

---

# Часть IV. User Target Plan

## 7. TargetPlanCompiler

Detector v2 MUST начинаться не с глобального fixed scan, а с `UserTargetSelection`:

```go
type UserTargetSelection struct {
    ServiceProfileIDs []string
    ComponentIDs      []string
    CustomDomains     []string
    CustomURLs        []string
    Mode              DetectorMode
    IPFamily          IPFamilyPolicy
    IncludeQUIC       bool
    AllowDynamicInfra bool
}
```

Compiler создаёт immutable `DiagnosticTargetPlan`.

### 7.1. Canonical target roles

```go
type TargetRole string

const (
    RolePrimary             TargetRole = "primary"
    RoleServiceComponent    TargetRole = "service_component"
    RoleSameServiceControl  TargetRole = "same_service_control"
    RoleSameProviderControl TargetRole = "same_provider_control"
    RoleUnrelatedControl    TargetRole = "unrelated_control"
    RoleDNSControl          TargetRole = "dns_control"
    RoleQUICControl         TargetRole = "quic_control"
    RoleInfraSentinel       TargetRole = "infra_sentinel"
)
```

### 7.2. Canonical plan

```go
type DiagnosticTargetPlan struct {
    SchemaVersion    uint16
    PlanID           string
    CreatedAt        time.Time
    Source           TargetPlanSource
    ServiceProfiles  []string
    Components       []DiagnosticComponent
    Targets          []DiagnosticTarget
    Controls         []DiagnosticTarget
    Budgets          DetectorBudgets
    ContentSHA256    string
}
```

### 7.3. Service component example

```yaml
service: youtube
components:
  - id: youtube-ui
    primary:
      - https://www.youtube.com/
    same_service_controls:
      - https://accounts.google.com/

  - id: youtube-api
    primary:
      - https://youtubei.googleapis.com/
    same_provider_controls:
      - https://www.googleapis.com/

  - id: youtube-video
    discovery_patterns:
      - "*.googlevideo.com"
    sample_from_runtime_dns: true
    unrelated_controls:
      - https://cloudflare.com/
```

Gmail или Google app control MUST NOT автоматически получать YouTube strategy. Controls используются для causal comparison, а не для shared action scope.

### 7.4. Custom domains

Custom domains:

- normalized через IDNA/host validation;
- deduplicated;
- ограничены maximum count;
- получают automatic unrelated controls;
- не становятся Service Profile без явного сохранения;
- не могут включать private/link-local destinations без explicit local-test mode;
- не экспортируются в public issue bundle без opt-in.

### 7.5. Quick and deep modes

```go
type DetectorMode string

const (
    DetectorQuick DetectorMode = "quick"
    DetectorDeep  DetectorMode = "deep"
    DetectorExpert DetectorMode = "expert"
)
```

`quick`:

- primary + minimum controls;
- DNS differential;
- TLS 1.2/1.3 canonical fingerprints;
- TCP reachability;
- bounded HTTP result;
- QUIC Initial when enabled;
- no dynamic farm unless required.

`deep`:

- multiple fingerprints;
- fresh/persistent pairs;
- packet/byte profiler;
- dynamic infra controls;
- throughput/stall samples;
- repeated causal probes.

`expert` MAY expose individual matrices but MUST retain safety budgets.

### 7.6. Target plan bounds

Default maximums for Keenetic-class target:

```yaml
detector_budgets:
  max_primary_targets: 16
  max_control_targets: 16
  max_dynamic_targets: 12
  max_total_targets: 32
  max_parallel_quick: 4
  max_parallel_deep: 2
  max_total_duration_quick_sec: 180
  max_total_duration_deep_sec: 900
  max_download_bytes: 16777216
  max_upload_bytes: 8388608
```

Values MAY be tuned downward by `DetectorCapacityProfile`. Upward tuning is allowed only within platform-certified hard ceilings and MUST NOT occur solely because raw scan throughput improved.

---


### 7.7. MonitorDiagnosticRequest

Continuous Monitoring MAY request an active run only through the following versioned object:

```go
type MonitorDiagnosticRequest struct {
    SchemaVersion      uint16
    RequestID          string
    AssessmentID       string

    ClientScopeHash    string
    ServiceProfileID   string
    ComponentID        string
    TargetRole         string

    NetworkContextID   string
    ConfigGeneration   uint64
    MonitoringEpoch    uint64

    TriggerReason      string
    RequestedDepth     string // quick | deep
    Priority           string // normal | elevated | user

    ResolutionRefs     []string
    ObservationRefs    []string
    CohortHintRefs     []string
    SuppressorSnapshot []string

    BudgetTokenID      string
    CreatedAt          time.Time
    ExpiresAt          time.Time
}
```

Validation requirements:

- request schema supported;
- `AssessmentID`, `RequestID`, `NetworkContextID`, `ConfigGeneration` non-empty/current;
- request not expired;
- budget token valid for requested depth;
- scope maps to one Service Profile/component or an explicitly custom target;
- suppressor snapshot does not hide current WAN/capture failure;
- referenced observations exist and are immutable;
- the request has no action, route or candidate configuration fields.

Rejected request MUST return a typed terminal result and MUST NOT silently fall back to an unscoped detector run.

### 7.8. TargetPlanOverlay

Monitoring supplies observations, not a complete plan:

```go
type TargetPlanOverlay struct {
    SchemaVersion       uint16
    RequestID           string

    ObservedDomains     []TargetIdentity
    ObservedEndpoints   []ResolvedEndpoint
    ObservedComponents  []string
    ResolutionSnapshots []string
    RequiredTargetRefs  []string
    CohortHintRefs      []string

    OverlayReason       string
    CreatedAt           time.Time
    ExpiresAt           time.Time
}
```

`TargetPlanCompiler` MUST merge the overlay with canonical Service Profile policy and MUST add mandatory controls. Overlay entries MUST NOT:

- remove controls;
- widen service/component scope;
- introduce arbitrary CIDRs;
- override protocol objectives;
- disable clean baseline;
- suppress independent resolution;
- become permanent targets merely because they were observed once.

### 7.9. Overlay compilation result

```go
type MonitorTargetPlanCompilation struct {
    RequestID          string
    AssessmentID       string
    TargetPlanID       string
    AcceptedOverlayIDs []string
    RejectedOverlayIDs []string
    AddedControlIDs    []string
    ResolutionModes    []string
    CompletenessPolicy string
}
```

Every rejected overlay item MUST have a stable reason code. Hidden target omission is forbidden.

# Часть V. Probe path and clean baseline

## 8. ProbePathMode

Every attempt MUST declare exact path:

```go
type ProbePathMode string

const (
    ProbePathNativeDirect     ProbePathMode = "native_direct"
    ProbePathProduction       ProbePathMode = "production"
    ProbePathCandidateSandbox ProbePathMode = "candidate_sandbox"
    ProbePathTransport        ProbePathMode = "transport"
)
```

### 8.1. Native direct baseline

`native_direct` MUST:

- bypass normal B4 action processing;
- bypass active routing fallback;
- use dedicated detector mark/token;
- remain visible to detector capture when packet evidence is required;
- avoid recursive interception;
- record actual egress interface and IP family;
- fail closed as `capture_path_invalid` if path cannot be proven.

### 8.2. Production comparison

Optional `production` probes MAY answer:

```text
native direct fails
production currently succeeds
```

but MUST NOT contaminate native BlockingProfile. Evidence must retain separate path identity.

### 8.3. Capture visibility gate

Packet-sensitive verdicts require:

- SYN and SYN-ACK visibility;
- outbound and inbound data progress;
- FIN/RST visibility;
- GSO normalization parity where needed;
- PPE exclusion/self-test PASS;
- no detector NFQUEUE overflow;
- packet counter confidence.

When incomplete:

```text
application-level observation MAY be recorded
packet-budget or injected-RST causal verdict MUST be suppressed
```

### 8.4. Self-interference controls

Detector MUST detect:

- own DNS resolver cache effects;
- own connection pooling;
- current B4 strategy mutation;
- WARP/proxy routing;
- system HTTP proxy;
- captive portal;
- WAN transition during suite;
- resource saturation caused by detector concurrency.

### 8.5. ReferencePathProbe

A reference path is a diagnostic comparison path, not a candidate automatically selected for user traffic.

```go
type ReferencePathKind string

const (
    ReferencePathWARP        ReferencePathKind = "warp"
    ReferencePathSOCKS       ReferencePathKind = "socks"
    ReferencePathRemoteProbe ReferencePathKind = "remote_probe"
    ReferencePathUserDefined ReferencePathKind = "user_defined"
)

type ReferencePathSpec struct {
    PathID             string
    Kind               ReferencePathKind
    EndpointRef        string
    ExpectedEgressHash string
    AllowedIPFamilies  []string
    HealthTargetIDs    []string
    CredentialRef      string
    MaxAttempts        uint16
    Timeout            time.Duration
}
```

Reference path MUST be health-checked before target comparison. Health proof MUST include:

- control target reachable through the reference path;
- route/egress identity consistent with the path specification;
- DNS/IP-family differences recorded explicitly;
- no recursive B4 action or transport loop;
- fresh timestamp and bounded validity;
- secret references redacted from evidence export.

### 8.6. Direct/reference comparison semantics

For the same normalized target endpoint:

```text
direct SYN fails
+ healthy reference path reaches same target/IP family
→ path_local_syn_filter_suspected
```

```text
direct path fails
+ multiple healthy reference paths or independent origin evidence fail
→ origin_unreachable_across_paths_suspected
```

The following are forbidden:

- `host_dead` from one failed proxy probe;
- comparing different stale DNS addresses without declaring the difference;
- using reference success as permission to route production traffic;
- treating reference-path TLS/HTTP success as proof of exact censor mechanism;
- retaining reference verdict after its health lease expires.

Reference-path results are hypotheses/suppressors used by ABD and SPF. WARP/SOCKS/TUN activation still requires profile policy, DDI/Discovery validation and transport `ActionAuthorization`.

---


### 8.7. ObserverCapability

Every reference observer MUST publish a signed or locally pinned capability descriptor:

```go
type ObserverCapability struct {
    SchemaVersion       uint16
    ObserverID          string
    DNS                 bool
    TCP                 bool
    TLS                 bool
    CertificateVerify   bool
    HTTPHeaders         bool
    HTTPBodyProgress    bool
    QUIC                bool
    IPFamilies          []string
    FingerprintIDs      []string
    MaxBodyBytes        uint64
    CapabilityExpiresAt time.Time
}
```

A comparison is valid only when the observer supports the local failure stage and required verification properties.

### 8.8. Exact-endpoint versus independent-resolution modes

Two different questions require two different experiments:

```text
exact-endpoint
→ local and observer probe the same IP/port/name tuple
→ isolates path difference

independent-resolution
→ every vantage resolves the service independently
→ measures service/CDN availability
```

Results MUST NOT be merged into one causal edge. A profile MAY contain both, but every hypothesis edge MUST reference its mode.

### 8.9. MultiVantageComparison

```go
type MultiVantageComparison struct {
    ComparisonID       string
    LocalAttemptID     string
    ObserverAttemptIDs []string

    RequiredStage      FailureStage
    TargetIdentityMode string
    ObserverCapabilityRefs []string

    StageAgreement     map[string]string
    AgreementClass     string
    Confidence         ProfileConfidence
    Suppressors        []EvidenceSuppressor
}
```

Normative rules:

- local HTTP body stall requires observer `HTTPBodyProgress=true`;
- local certificate-integrity hypothesis requires `CertificateVerify=true`;
- local QUIC hypothesis requires observer QUIC support with compatible version/fingerprint policy;
- observer unavailable means no opinion;
- observer health and transport path have independent TTL;
- one observer does not create high confidence without other evidence/control families.

# Часть VI. Evidence model

## 9. DiagnosticAttemptEvidence

```go
type DiagnosticAttemptEvidence struct {
    AttemptID          string
    SuiteID            string
    PlanID             string
    ComponentID        string
    TargetID           string
    TargetRole         TargetRole
    PathMode           ProbePathMode
    ReferencePathID    string
    IPFamily           string
    RemoteIPHash       string
    RemoteASN          string
    ResolverID         string

    Protocol           string
    TLSVersion         string
    FingerprintID      string
    SNI                string
    ALPN               []string

    StartedAt          time.Time
    CompletedAt        time.Time
    Stage              FailureStage
    Outcome            AttemptOutcome

    TCPConnected       bool
    TLSResponse        string
    HTTPStatus         int
    QUICProgress       string
    CertificateState   string

    OutboundPackets    uint32
    InboundPackets     uint32
    OutboundUniqueBytes uint64
    InboundUniqueBytes  uint64
    Retransmissions    uint32
    RSTObserved        bool
    FINObserved        bool
    ICMPObserved       bool

    DNSAnswers         []DNSAnswerEvidence
    FailureOffsetBytes uint64
    LastProgressAt     time.Time
    TTFB               time.Duration
    ThroughputBPS      uint64
    BodyProgress       *BodyProgressEvidence
    ReferenceComparison *ReferencePathEvidence

    CaptureVisibility  string
    Suppressors        []EvidenceSuppressor
    Provenance         EvidenceProvenance
}
```

### 9.1. Unique bytes

Byte counters MUST represent unique stream progress, not packet lengths summed across retransmissions or GSO views.

### 9.2. Packet counts

Packet counts MUST declare counting layer:

```text
wire_estimate
post_GSO_logical_segment
NFQUEUE_skb
application_write
```

Only validated wire/logical-segment counts MAY support packet-budget hypotheses.

### 9.3. Attempt outcome

```go
type AttemptOutcome string

const (
    OutcomeAvailable       AttemptOutcome = "available"
    OutcomeDNSFailure      AttemptOutcome = "dns_failure"
    OutcomeSYNDrop         AttemptOutcome = "syn_drop"
    OutcomeTCPReset        AttemptOutcome = "tcp_reset"
    OutcomeTLSReset        AttemptOutcome = "tls_reset"
    OutcomeTLSDrop         AttemptOutcome = "tls_drop"
    OutcomeTLSAlert        AttemptOutcome = "tls_alert"
    OutcomeTLSSpoof        AttemptOutcome = "tls_spoof"
    OutcomeTLSMITM         AttemptOutcome = "tls_mitm"
    OutcomeHTTPBlockPage   AttemptOutcome = "http_block_page"
    OutcomeQUICDrop        AttemptOutcome = "quic_drop"
    OutcomeL4Budget        AttemptOutcome = "l4_budget_suspected"
    OutcomeStall           AttemptOutcome = "stall"
    OutcomeThrottled       AttemptOutcome = "throttled"
    OutcomeOriginFailure   AttemptOutcome = "origin_failure"
    OutcomeReferenceUnhealthy AttemptOutcome = "reference_path_unhealthy"
    OutcomePathLocalFailure AttemptOutcome = "path_local_failure_suspected"
    OutcomePartialBodyStall AttemptOutcome = "partial_body_stall"
    OutcomeCaptureInvalid  AttemptOutcome = "capture_invalid"
    OutcomeInconclusive    AttemptOutcome = "inconclusive"
)
```

### 9.4. Evidence provenance

Every evidence item MUST include:

- detector build ID;
- config generation;
- target plan hash;
- network context ID;
- probe implementation version;
- direct/production/candidate/reference path;
- source target type: embedded, runtime-derived, dynamic, user-defined;
- capture visibility state.

### 9.5. BodyProgressEvidence

```go
type BodyProgressEvidence struct {
    RequestMethod          string
    RequestedRange         string
    ExpectedContentLength  uint64
    ExpectedLengthKnown    bool
    HeadersReceivedAt      time.Time
    FirstBodyByteAt        time.Time
    LastProgressAt         time.Time
    UniqueBodyBytes        uint64
    BodyFrames             uint32
    InterChunkDeadline     time.Duration
    WholeProbeDeadline     time.Duration
    CompletionReason       string
    ObjectSuitability      string
}
```

`UniqueBodyBytes` MUST exclude retransmissions and duplicated application frames. `CompletionReason` MUST distinguish at least:

```text
success_milestone_reached
origin_eof_before_milestone
inter_chunk_stall
overall_timeout
connection_reset
tls_alert
http_error
user_cancelled
resource_cancelled
```

### 9.6. ReferencePathEvidence

```go
type ReferencePathEvidence struct {
    PathID              string
    PathKind            ReferencePathKind
    PathHealth          string
    PathHealthEvidence  []string
    ExactTargetID       string
    RemoteIPHash        string
    IPFamily            string
    DirectAttemptID     string
    ReferenceAttemptID  string
    DirectOutcome       AttemptOutcome
    ReferenceOutcome    AttemptOutcome
    NetworkContextID    string
    ValidUntil          time.Time
    Confidence          ProfileConfidence
    Suppressors         []EvidenceSuppressor
}
```

A reference comparison MUST NOT merge evidence across different target IP, IP family, target role or network context unless the difference is an explicit experiment dimension.

---


### 9.7. EvidenceAuthority

```go
type EvidenceAuthority string

const (
    AuthorityPassiveMonitoring EvidenceAuthority = "passive-monitoring"
    AuthorityProvisionalFast   EvidenceAuthority = "provisional-fast"
    AuthorityAuthoritativeABD  EvidenceAuthority = "authoritative-abd"
    AuthorityAndroidCanary     EvidenceAuthority = "android-canary"
)
```

Only `AuthorityAuthoritativeABD` evidence MAY compile the active detector portion of a final `BlockingProfile`. Passive/provisional evidence MAY:

- select exact endpoints;
- affect queue priority;
- request additional experiments;
- be referenced as provenance.

It MUST NOT be counted as an independent active probe or as final confirmation.

### 9.8. ClientResolutionSnapshot and attempt binding

```go
type ClientResolutionSnapshot struct {
    SnapshotID        string
    ClientKeyHash     string
    NetworkContextID  string
    ConfigGeneration  uint64

    QueryIDHash       string
    OriginalQNameHash string
    QueryType         string
    ResolverID        string
    ResolverTransport string

    CNAMEChainHashes  []string
    Answers           []ResolvedEndpoint
    AnswerOrder       []uint16
    TTLs              []uint32

    ObservedAt        time.Time
    ValidUntil        time.Time
    Provenance        EvidenceProvenance
}

type AttemptResolutionBinding struct {
    AttemptID            string
    ResolutionSnapshotID string
    SelectedEndpointHash string
    ResolutionMode       string // client-observed | independent-current
    SelectionReason      string
}
```

The snapshot is captured by Monitoring/DNS correlation and consumed immutably by ABD. Clear names remain local according to privacy policy; standard export uses hashes and role labels.

### 9.9. Per-address outcome vector

```go
type AddressAttemptOutcome struct {
    EndpointHash    string
    IPFamily       string
    AddressIndex   uint16
    ResolutionMode string

    TCPOutcome     string
    TLSOutcome     string
    HTTPOutcome    string
    QUICOutcome    string

    UniqueBodyBytes uint64
    LatencyMS       uint64
    FailureCode     ProbeFailureCode
    Attribution     FailureAttribution
}
```

A successful address MUST NOT erase failed siblings. Aggregation reports at least:

```text
all-addresses-success
partial-address-failure
all-addresses-fail
address-family-asymmetry
endpoint-selective-failure
```

### 9.10. Failure code and attribution split

```go
type ProbeFailureCode string

type FailureAttribution string

const (
    AttributionServerActive        FailureAttribution = "server-active"
    AttributionOriginSuspected     FailureAttribution = "origin-suspected"
    AttributionPathSuspected       FailureAttribution = "path-suspected"
    AttributionObserverUnavailable FailureAttribution = "observer-unavailable"
    AttributionCaptureInvalid      FailureAttribution = "capture-invalid"
    AttributionAmbiguous           FailureAttribution = "ambiguous"
)
```

Examples:

```text
failure_code: tcp_syn_timeout
attribution: ambiguous
hypothesis: path_local_syn_filter_suspected
confidence: weak

failure_code: http_body_interchunk_stall
attribution: path-suspected
hypothesis: byte_window_transfer_interference
confidence: probable
```

Physical outcome remains immutable even if later evidence changes attribution.

# Часть VII. DNS differential detector

## 10. DNS probe matrix

Detector v2 SHOULD support:

```text
system resolver
UDP/53 direct
TCP/53 direct
DoH by hostname
DoH with bootstrap IP
A
AAAA
CNAME chain
HTTPS/SVCB
ECHConfig presence/hash
NXDOMAIN control
random nonexistent-domain control
known-good provider control
```

### 10.1. DNS answer model

```go
type DNSAnswerEvidence struct {
    ResolverID      string
    Transport       string
    QueryType       string
    RCode           string
    Answers         []string
    CNAMEChain      []string
    TTLs            []uint32
    Truncated       bool
    Authenticated   bool
    Latency         time.Duration
    ErrorClass      string
}
```

### 10.2. Differential rules

Possible hypotheses:

- `udp_dns_interception`;
- `dns_spoofing`;
- `fake_nxdomain`;
- `fake_empty_answer`;
- `stub_ip_injection`;
- `doh_blocked`;
- `doh_bootstrap_blocked`;
- `aaaa_specific_failure`;
- `https_rr_stripping_suspected`;
- `echconfig_path_difference`.

No hypothesis is confirmed by one resolver disagreement alone. Legitimate CDN geo differences MUST be considered.

### 10.3. Resolver consensus

For target-critical DNS hints, Detector SHOULD use:

- at least two independent trusted reference resolvers when available;
- answer-set normalization;
- ASN/provider plausibility;
- same-query timing proximity;
- CNAME-aware comparison;
- current target connection validation.

### 10.4. DNS controls

Required controls include:

- known existent domain;
- randomized non-existent domain;
- domain expected to have stable public answers;
- provider endpoint control;
- TCP/53 fallback when UDP/53 differs.

### 10.5. Search-prior mapping

DNS evidence MAY:

- boost system-forward or trusted DoH variants;
- seed bootstrap-IP resolver candidates;
- prioritize IPv4 when AAAA path is broken;
- create ECH-aware target variants;
- penalize raw system-resolver assumptions.

It MUST NOT directly rewrite production DNS config.

---

# Часть VIII. TLS and HTTP fingerprint matrix

## 11. TLSFingerprintProfile

```go
type TLSFingerprintProfile struct {
    ID                string
    Source            string
    TLSVersion        uint16
    ClientHelloHash   string
    ExtensionOrderHash string
    ALPN              []string
    GREASE            bool
    ECHPresent        bool
    CapturedDevice    string
    Provenance        string
}
```

Required baseline profiles:

```text
canonical-minimal-tls12
canonical-minimal-tls13
go-default-tls12
go-default-tls13
chrome-like
firefox-like
android-like
real-android-captured when available and consented
```

The actual implementation MAY use the existing Real ClientHello Laboratory and fake-profile catalog. Raw captured payloads MUST remain privacy-safe and provenance-reviewed.

## 12. TLS probe pairs

For each important target, Detector SHOULD compare:

```text
TLS 1.2 vs TLS 1.3
canonical vs browser-like
fresh connection vs persistent connection
verified certificate vs availability-only
SNI vs no-SNI control where protocol-valid
primary SNI vs bounded alternate-SNI control
IPv4 vs IPv6
```

### 12.1. Certificate integrity

Two separate semantics are mandatory:

```text
availability probe:
  certificate verification MAY be disabled

integrity probe:
  system trust and hostname verification MUST be enabled
```

`tls_mitm` requires integrity failure plus supporting evidence. Availability success with integrity failure is not enough to name provider intent; verdict SHOULD be `certificate_substitution_suspected` until controls agree.

### 12.2. TLS staged failure

Stages:

```text
tcp_connect
client_hello_sent
server_hello_received
certificate_received
handshake_complete
request_sent
headers_received
body_progress
```

RST/EOF/timeout MUST be tied to exact stage and packet evidence where visible.

## 13. HTTP matrix

Detector SHOULD support bounded:

- HTTP/80 HEAD;
- HTTP/80 small GET;
- HTTPS HEAD;
- HTTPS small GET;
- bounded body GET;
- redirect integrity;
- content-length/progress validation;
- block-page signatures;
- HTTP 451;
- TTFB and throughput sample;
- same-host and cross-host redirect classification.

### 13.1. Origin-aware suppressors

Before declaring DPI, suppress or downgrade when:

- origin returns same error through trusted transport;
- certificate/HTTP behavior matches public origin configuration;
- WAF/rate limit is visible;
- only one method is rejected but alternate standard method succeeds;
- response is valid application error;
- control targets fail similarly;
- local clock invalidates TLS verification.

### 13.2. Body-progress availability contract

A service component MUST declare its success milestone:

```text
handshake
headers
minimum_unique_body_bytes
complete_known_object
media_progress
goodput_window
application_specific
```

For API/UI/media components whose milestone exceeds headers:

```text
TLS handshake or HEAD success
→ observation only
```

```text
bounded GET/Range reaches declared milestone
→ application-path availability evidence
```

```text
headers received
+ repeatable partial unique-body plateau
+ controls/reference comparison
→ byte-window/throttling/silent-stall hypothesis
```

Detector MUST use separate deadlines for:

```text
connect
TLS/QUIC handshake
TTFB
inter-chunk progress
overall probe
```

An inter-chunk timeout MUST preserve partial progress. The probe MUST NOT return only `timeout` when headers or body bytes were already observed.

### 13.3. Object suitability and small-object guard

A transfer object used for byte-window evidence MUST be one of:

- profile-declared known-large object;
- trusted dynamic object with validated `Content-Length`;
- bounded `Range` response with verified semantics;
- application-specific media/progress endpoint.

A response smaller than the requested diagnostic milestone MUST be classified as `object_too_small` or origin/application outcome, not automatically `throttled`.

Fixed byte ranges such as 10–25 KiB MAY seed a diagnostic dimension but MUST NOT create high confidence without repeatability, controls and target variation.

### 13.4. Fingerprint-specific hypothesis

Example:

```yaml
hypothesis:
  type: tls_fingerprint_specific_reset
  affected_fingerprints:
    - android-like
  unaffected_fingerprints:
    - canonical-minimal-tls13
  targets:
    - youtubei.googleapis.com
  controls_healthy: true
  confidence: probable
```

Such hypothesis MAY prioritize real/canonical ClientHello strategy variants; it MUST NOT authorize generic fake injection.

---

# Часть IX. QUIC detector

## 14. QUIC probe ladder

Detector v2 MUST add first-class QUIC evidence when enabled:

```text
Q0 UDP route/socket availability
Q1 QUIC Initial sent
Q2 any valid QUIC response
Q3 Version Negotiation / Retry
Q4 handshake key progress
Q5 handshake complete
Q6 HTTP/3 headers
Q7 bounded body progress
```

### 14.1. QUIC evidence

```go
type QUICDiagnosticEvidence struct {
    TargetID          string
    IPFamily          string
    Version           uint32
    FingerprintID     string
    InitialSent       bool
    ResponseSeen      bool
    VersionNegotiation bool
    RetrySeen         bool
    HandshakeComplete bool
    HTTP3Headers      bool
    BodyBytes         uint64
    OutboundPackets   uint32
    InboundPackets    uint32
    FailureStage      string
    Verdict           string
}
```

### 14.2. QUIC hypotheses

- `udp_443_global_drop_suspected`;
- `quic_initial_target_drop_suspected`;
- `quic_version_specific_failure`;
- `quic_fingerprint_specific_failure`;
- `quic_handshake_stall`;
- `http3_application_failure`;
- `quic_available_tcp_blocked`;
- `tcp_available_quic_blocked`.

### 14.3. QUIC controls

At least one unrelated QUIC-capable control SHOULD be used. Absence of response from one origin is insufficient to claim UDP/443 block.

### 14.4. Search-prior mapping

```text
QUIC blocked, TCP available
→ boost QUIC block/fallback-safe profile and TCP strategy search

QUIC available, TCP blocked
→ avoid unnecessary UDP disablement

both fail, unrelated controls healthy
→ target/service-specific transport hypothesis

all controls fail
→ WAN/UDP condition, not target DPI proof
```

---

# Часть X. L4 packet/byte threshold profiler

## 15. Motivation

Legacy `TCP 16–20` labels often mix distinct mechanisms:

- byte-volume threshold;
- packet-count threshold;
- bidirectional packet budget;
- request/header-size origin limit;
- persistent-connection policy;
- timing/rate threshold;
- censor trigger followed by silent drop or reset.

B4X MUST report what was actually measured.

## 16. L4ThresholdProfile

```go
type L4ThresholdProfile struct {
    TargetClass          string
    Direction            string
    ConnectionMode       string
    PacketWindow         ThresholdInterval
    UniqueByteWindow     ThresholdInterval
    ApplicationWriteWindow ThresholdInterval
    Repetitions          uint16
    IndependentTargets   uint16
    ControlsPassed       uint16
    FailureModes         []string
    Confidence           ProfileConfidence
}
```

### 16.1. Independent dimensions

Detector MUST provide separate experiment families:

```text
constant bytes, varied packet count
constant packet count, varied bytes
uplink-dominant stream
downlink-dominant stream
fresh connection series
persistent connection series
TLS and non-TLS control where safe
TCP and UDP comparison where applicable
```

### 16.2. Packet accounting

Packet-budget proof requires validated logical/wire packet accounting. GSO skb count MUST NOT be used as wire packet count.

### 16.3. Dynamic controls

A provider-wide threshold requires repeatability across:

- multiple independent endpoints;
- more than one subnet when possible;
- healthy origin controls;
- repeated time-separated samples;
- direct path consistency.

### 16.4. Server-limit suppressors

Downgrade/suppress when:

- HTTP status explicitly indicates header too large;
- TLS/application close is reproducible through trusted transport;
- only one endpoint fails;
- failure aligns with origin-specific size policy;
- connection closes cleanly with FIN and valid application response;
- packet/byte threshold changes randomly across repetitions;
- detector resource saturation occurs.

### 16.5. Search-prior mapping

If packet budget is probable:

- penalize high-amplification fake/disorder candidates;
- prefer minimal-packet split/shaping;
- include packet-amplification cost in score;
- prevent unbounded candidate combinations.

If byte window is probable:

- seed split/body shaping ranges near but not exactly equal to observed interval;
- require target-specific causal shadow probes;
- preserve full search fallback.

---

# Часть XI. Dynamic infrastructure controls

## 17. DynamicControlTargetProvider

Fixed targets remain useful as sentinels but MUST be complemented by bounded dynamic selection.

```go
type DynamicTargetQuery struct {
    Providers       []string
    ASNs            []uint32
    Countries       []string
    Subnets         []string
    Hostnames       []string
    RequiredPorts   []uint16
    Count           uint16
    ExcludeRecent   []string
}
```

### 17.1. Allowed sources

Dynamic targets MAY originate from:

- locally vendored signed ASN/prefix data;
- configured GeoIP/ASN database;
- DNS-derived target subnets;
- Service Profile metadata;
- recently observed runtime destinations;
- user-supplied test servers;
- signed B4X target catalog.

### 17.2. Host validation

Before active probe, candidate MUST pass bounded validation:

- routable public address;
- port policy allowed;
- no private/link-local/multicast/documentation range unless explicit lab mode;
- no duplicate endpoint;
- alive check;
- no known abuse-sensitive target class;
- rate limit and cooldown;
- target source provenance.

### 17.3. Anti-whitelisting and freshness

Dynamic sampling reduces fixed-checker gaming, but does not eliminate it. Profile MUST record:

- target set hash;
- sampling seed;
- selection time;
- target source;
- TTL;
- success/failure distribution.

### 17.4. Ethical and operational bounds

B4X MUST NOT perform broad port scanning. Default target provider only probes known service ports and small bounded samples. User-triggered diagnostic action is required for deep dynamic tests.

### 17.5. Cache

Dynamic target cache:

- atomic;
- signed/hashed when remote;
- max entries bounded;
- age bounded;
- last-good retained;
- invalidated on schema change;
- privacy-safe;
- never treated as production routing list.

---

# Часть XII. Evidence graph and confidence model

## 18. EvidenceGraph

```go
type EvidenceGraph struct {
    Observations   []DiagnosticAttemptEvidence
    Correlations   []EvidenceCorrelation
    Hypotheses     []BlockingHypothesis
    Contradictions []EvidenceContradiction
    Exclusions     []FailureExclusion
    Controls       []ControlOutcome
}
```

### 18.1. BlockingHypothesis

```go
type BlockingHypothesis struct {
    ID               string
    Type             string
    Scope            HypothesisScope
    SupportingIDs    []string
    ContradictingIDs []string
    SuppressorIDs    []string
    Confidence       ProfileConfidence
    Repeatability    float64
    ControlsHealthy  bool
    FirstObservedAt  time.Time
    LastObservedAt   time.Time
}
```

### 18.2. Confidence ladder

```go
type ProfileConfidence string

const (
    ConfidenceObservation  ProfileConfidence = "observation"
    ConfidenceWeak         ProfileConfidence = "weak"
    ConfidenceProbable     ProfileConfidence = "probable"
    ConfidenceHigh         ProfileConfidence = "high"
    ConfidenceCausal       ProfileConfidence = "causal"
)
```

Normative meaning:

`observation`:

- single outcome;
- no independent control;
- no action/search exclusion.

`weak`:

- repeated on same target or consistent stage;
- MAY slightly reorder probes.

`probable`:

- multiple target observations;
- controls healthy;
- no strong contradiction;
- MAY materially boost/penalize candidate families.

`high`:

- repeated independent targets/fingerprints;
- path visibility valid;
- alternative causes excluded;
- MAY reduce low-value search branches but not disable exhaustive fallback.

`causal`:

- direct baseline fails;
- one bounded changed dimension succeeds;
- shadow/control comparison reproduces effect;
- still does not equal production promotion.

### 18.3. Independence rules

Evidence is not independent when attempts share:

- same TCP connection;
- same origin endpoint;
- same resolver cache response;
- same failed WAN interval;
- same candidate strategy;
- same underlying captured packet;
- same dynamic target with aliases;
- same config generation but duplicated event records.

### 18.4. Failure exclusions

Possible exclusions:

```text
origin_failure
origin_rate_limit
certificate_clock_error
local_dns_failure
captive_portal
wan_global_outage
wifi_loss
resource_saturation
capture_incomplete
ppe_visibility_incomplete
gso_packet_count_unknown
proxy_or_vpn_active
production_strategy_interference
application_error
server_header_limit
```

### 18.5. Control precedence

Healthy unrelated and same-provider controls reduce global-failure hypotheses. Failed controls can suppress target-specific conclusions. Control failure MUST be visible in UI and profile.

---


### 18.6. Monitoring recurrence is not evidence independence

`MonitorAssessment` MAY report high recurrence, but EvidenceGraph MUST represent it as temporal support metadata, not duplicated active edges.

```text
50 repeated passive SYN timeouts
→ recurrence_score increases
→ detector priority may increase

50 repeated passive SYN timeouts
≠ 50 independent active evidence families
```

Independence still requires protocol, endpoint, vantage, fingerprint, control or separated experimental dimensions defined by ABD.

### 18.7. Monitor provenance edges

EvidenceGraph MAY include non-causal provenance edges:

```text
triggered_by_assessment
observed_on_client_endpoint
selected_from_resolution_snapshot
requested_by_user
```

These edges explain why an experiment was run. They MUST NOT directly support a blocking hypothesis unless an authoritative ABD attempt produced matching evidence.

# Часть XIII. BlockingProfile

## 19. Canonical model

```go
type BlockingProfile struct {
    SchemaVersion      uint16
    ProfileID          string
    SourceSuiteID      string
    TargetPlanID       string
    CreatedAt          time.Time
    CompletedAt        time.Time

    NetworkContextID   string
    ConfigGeneration   uint64
    DetectorBuildID    string
    ContentSHA256      string

    Components         []ComponentBlockingProfile
    DNS                DNSBlockingProfile
    Infrastructure     []InfrastructureBlockingProfile
    Hypotheses         []BlockingHypothesis
    Exclusions         []FailureExclusion
    Controls           []ControlOutcome

    SearchPrior        DiscoverySearchPrior
    Confidence         ProfileConfidence
    CaptureVisibility  string
    RawEvidenceRef     string
}
```

### 19.1. ComponentBlockingProfile

```go
type ComponentBlockingProfile struct {
    ServiceProfileID string
    ComponentID      string
    TargetIDs        []string
    IPFamilies       []string
    Protocols        []string
    TLSProfiles      []string
    HypothesisIDs    []string
    Confidence       ProfileConfidence
}
```

### 19.2. NetworkDiagnosticProfile envelope compatibility

Existing DDI envelope MUST become conceptually:

```go
type NetworkDiagnosticProfile struct {
    SchemaVersion    uint16
    ProfileID        string
    CreatedAt        time.Time
    ExpiresAt        time.Time
    BuildID          string
    ConfigGeneration uint64
    ContentSHA256    string

    NetworkContext   NetworkContextFingerprint
    TargetScope      DiagnosticTargetScope
    Blocking         BlockingProfile

    State            DiagnosticProfileState
    Revalidation     RevalidationState
}
```

Legacy v1 raw fields MAY be migrated into a low-confidence compatibility `BlockingProfile`, but MUST NOT receive `high` or `causal` confidence without revalidation.

### 19.3. Immutability

Once compiled, `BlockingProfile` is immutable. Additional evidence creates a new profile/version. Runtime pointers to mutable DetectorSuite are forbidden.

### 19.4. Raw evidence retention

Raw evidence store:

- bounded;
- separate from compact profile;
- privacy-redacted by default;
- referenced by stable ID/hash;
- expires earlier than summary profile unless user pins it;
- excluded from ordinary config backup when sensitive.

---


### 19.5. MonitorAssessmentRef

A profile produced from a monitoring request MUST include immutable provenance:

```go
type MonitorAssessmentRef struct {
    AssessmentID      string
    RequestID         string
    MonitoringEpoch   uint64
    TriggerReason     string
    ObservationRefs   []string
    ResolutionRefs    []string
    NetworkContextID  string
    ConfigGeneration  uint64
}
```

The reference does not transfer ownership of temporal state to ABD.

### 19.6. MonitorDiagnosticResult

Every accepted request MUST end with a typed result, including incomplete/canceled runs:

```go
type MonitorDiagnosticResult struct {
    SchemaVersion      uint16
    RequestID          string
    AssessmentID       string
    DetectorRunID      string
    TargetPlanID       string
    BlockingProfileID  string

    CompletionState    string
    // complete | incomplete | canceled | suppressed | rejected

    ConfirmedTargets     []string
    ContradictedTargets  []string
    InconclusiveTargets  []string
    ExclusionCodes       []string

    NetworkContextID   string
    ConfigGeneration   uint64
    MonitoringEpoch    uint64

    CreatedAt          time.Time
    ValidUntil         time.Time
}
```

Rules:

- `BlockingProfileID` is empty unless completeness criteria pass;
- result identity MUST match request identity;
- result for old network/config generation MUST be rejected by Monitoring;
- canceled/incomplete result MAY preserve evidence references but MUST NOT set final profile;
- result contains no action authorization or production candidate;
- Monitoring MAY move assessment state, but MUST NOT rewrite profile hypotheses.

# Часть XIV. DiscoverySearchPrior and guided strategy search

## 20. DiscoverySearchPrior

```go
type DiscoverySearchPrior struct {
    ProfileID        string
    TargetPlanID     string
    ComponentPriors  []ComponentSearchPrior
    FamilyWeights    map[string]float64
    DimensionSeeds   []DimensionSeed
    CandidateBoosts  []CandidateAdjustment
    CandidatePenalties []CandidateAdjustment
    DeferredFamilies []DeferredFamily
    RequiredBaselines []string
    RequiredControls  []string
    MaxHintedProbes  int
    Explain          []PriorExplanation
}
```

### 20.1. Allowed effects

SearchPrior MAY:

- change candidate ordering;
- seed resolver/IP/TLS/fingerprint/fake-SNI dimensions;
- boost likely strategy families;
- penalize high-amplification variants;
- defer low-value branches;
- reduce initial hinted budget;
- request specific shadow dimensions;
- require protocol-specific controls;
- recommend transport fallback confirmation when route/IP block probable.

### 20.2. Forbidden effects

Monitoring-originated observations are treated only as experiment-selection and ordering priors. They MUST NOT:

- bypass mandatory baselines;
- exclude candidate families by themselves;
- create target success;
- authorize WARP or proxy routing;
- promote a candidate before target/control/canary validation;
- override current contradictory active evidence.


SearchPrior MUST NOT:

- skip baseline-none;
- skip baseline-production;
- skip target-specific candidate validation;
- disable exhaustive bounded fallback;
- directly write a set/strategy;
- directly authorize WARP/SOCKS/TUN routing;
- alter unrelated service scope;
- promote white SNI;
- bypass capture visibility gate;
- persist as winning strategy without canary.

## 21. Hypothesis-to-search mapping

### 21.1. DNS interception

```text
boost:
  trusted DoH
  system-forward
  bootstrap-IP resolver
  CNAME-aware target resolution

shadow:
  resolver only
```

### 21.2. TLS 1.3 or fingerprint-specific failure

```text
boost:
  marker split near SNI/extensions
  real/canonical ClientHello profiles
  bounded TLS profile variants

avoid:
  generic conclusion that TLS 1.2-only is permanent solution
```

### 21.3. Active reset after ClientHello

```text
boost:
  bounded disorder/desync
  low-amplification fake
  split around authoritative markers

require:
  RST direction/sequence plausibility
  shadow comparison
```

### 21.4. Silent drop/stall

```text
route through SPF evidence model
boost only after suppression gates
never use single timeout as automatic fallback
```

### 21.5. L4 packet budget

```text
penalize:
  high packet amplification
  repeated fake-per-segment
  excessive split combinations

boost:
  minimal-packet candidates
  low-complexity direct strategy
```

### 21.6. Byte-window transfer failure

```text
seed:
  bounded split/shaping ranges around observed interval

require:
  target body progress proof
  fresh control
```

### 21.7. QUIC-only failure

```text
boost:
  safe QUIC block/fallback
  TCP candidate matrix

preserve:
  direct QUIC when target-specific QUIC controls pass
```

### 21.8. IP/CIDR route block suspicion

```text
first:
  confirm via multiple target IPs and controls
then:
  prioritize scoped transport candidates

never:
  waste full TCP strategy matrix when TCP handshake cannot occur and controls prove route block
```

### 21.9. White SNI evidence

Found SNI enters candidate catalog with:

- source target/ASN;
- timestamp;
- confidence;
- exact fingerprint;
- observed success count;
- no production eligibility.

Discovery MUST revalidate on actual target and Service Component.

## 22. Coverage-aware candidate planning

### 22.1. CandidateCoverageVector

```go
type CandidateCoverageVector struct {
    CandidateID         string
    ScopeID             string
    RequiredTargets     []string
    OptionalTargets     []string
    NegativeControls    []string
    SuccessfulTargets   []string
    FailedTargets       []string
    UnknownTargets      []string
    ExcludedTargets     []TargetExclusion
    ControlRegressions  []string
    ComplexityCost      float64
    PacketCost          float64
    CPUCost             float64
    MemoryCost          float64
}
```

Coverage denominator MUST include every declared required target. A target MAY be excluded only with a machine-readable reason such as unsupported IP family, invalid origin fixture or explicit user removal; excluded targets remain visible in reports and do not silently improve coverage.

### 22.2. Scoped coverage objective

Within one exact Service Profile/component compatibility cohort, planner MAY search for the smallest candidate binding set that:

```text
covers every mandatory target
+ preserves mandatory negative controls
+ meets quality thresholds
+ minimizes complexity and resource cost
```

The objective MUST NOT combine unrelated services or cross an `ActionAuthorization` scope. For example, a strategy that succeeds on YouTube and Gmail cannot be promoted as a universal Google strategy unless a separate profile explicitly defines and validates that shared scope.

Negative-control regression is a hard rejection regardless of target coverage.

### 22.3. Candidate complexity cost

At equal validated coverage and quality, prefer:

```text
fewer strategy bindings
→ fewer packet actions
→ fewer repeats
→ lower packet amplification
→ single-stage before multi-stage
→ lower CPU/RAM
```

Structural simplicity is a tie-breaker, not a substitute for target quality or safety.

### 22.4. Candidate verification funnel

Discovery SHOULD use a bounded funnel:

```text
A. cheap safety/handshake elimination
→ B. functional body/media and control verification
→ C. repeated stability across time/IP/CDN variation
→ D. real Android canary
```

```go
type CandidateVerificationSummary struct {
    CandidateID         string
    Attempts            uint16
    Successes           uint16
    HardFailures        uint16
    SoftFailures        uint16
    SuccessRate         float64
    LatencyMedian       time.Duration
    LatencyP95          time.Duration
    GoodputP10          uint64
    StallRate           float64
    UniqueIPsTested     uint16
    TimeBucketsTested   uint16
    RequiredCoverage    float64
    ControlRegressions  uint16
}
```

A first hard safety failure MAY stop further expensive checks. A single transient network failure MUST be classified and MAY be retried within budget; it MUST NOT silently become permanent candidate exclusion.

### 22.5. Deterministic merge with DDI

DDI merge order:

```text
current target baseline evidence
> current capture/visibility gates
> fresh revalidated BlockingProfile priors
> compatible stored profile priors
> generic catalog defaults
```

Conflict behavior:

- current baseline wins;
- conflicting prior is suppressed, not silently averaged;
- suppression reason is emitted;
- hinted search savings report records profile miss;
- exhaustive fallback remains available.

---

# Часть XV. API and persistence deltas

## 23. Detector API v2

```go
type DetectorRequestV2 struct {
    Tests             []string          `json:"tests"`
    ServiceProfileIDs []string          `json:"service_profile_ids,omitempty"`
    ComponentIDs      []string          `json:"component_ids,omitempty"`
    Domains           []string          `json:"domains,omitempty"`
    URLs              []string          `json:"urls,omitempty"`
    Mode              string            `json:"mode,omitempty"`
    IPVersion         string            `json:"ip_version,omitempty"`
    IncludeQUIC       bool              `json:"include_quic,omitempty"`
    AllowDynamicInfra bool              `json:"allow_dynamic_infra,omitempty"`
    PathMode          string            `json:"path_mode,omitempty"`
    ResourceProfile   string            `json:"resource_profile,omitempty"`
    ReferencePathIDs  []string          `json:"reference_path_ids,omitempty"`
    ResumeRunID       string            `json:"resume_run_id,omitempty"`
    CapacityMode      string            `json:"capacity_mode,omitempty"`
}
```

Backward-compatible v1 request remains valid and compiles into default embedded plan.

### 23.1. New endpoints

```text
POST   /api/detector/v2/plan/preview
POST   /api/detector/v2/start
GET    /api/detector/v2/status/{id}
GET    /api/detector/v2/evidence/{id}
GET    /api/detector/v2/blocking-profile/{id}
GET    /api/detector/v2/profiles
DELETE /api/detector/v2/profiles/{id}
POST   /api/detector/v2/profiles/{id}/revoke
POST   /api/detector/v2/profiles/{id}/start-discovery
GET    /api/detector/v2/capacity
POST   /api/detector/v2/capacity/calibrate
GET    /api/detector/v2/reference-paths
POST   /api/detector/v2/runs/{id}/resume
```

DDI owns reusable profile list/selection and revalidation semantics; Detector endpoint MAY return newly compiled profile immediately after suite completion.

### 23.2. Status response

Must expose:

- current phase;
- completed/total probes;
- target/component;
- active controls;
- bytes and packet budget usage;
- path mode;
- current hypotheses with non-final confidence;
- suppressors;
- ETA MAY be omitted;
- cancellation state;
- final profile ID;
- reference-path health and comparison state;
- body-progress bytes and current milestone;
- effective quick/deep concurrency;
- resumable checkpoint ID and completeness state.


### 23.3. Internal Monitoring adapter API

The preferred integration is an in-process typed service, with an authenticated loopback API only when process separation requires it:

```text
POST /api/detector/v2/monitor-requests
GET  /api/detector/v2/monitor-requests/{request_id}
GET  /api/detector/v2/monitor-results/{request_id}
```

Required behaviors:

- idempotent request submission by `RequestID`;
- conflict on same ID with different content hash;
- explicit accepted/rejected/suppressed terminal state;
- no endpoint that accepts raw `apply`, `strategy`, `warp`, `set` or `route` fields;
- authenticated result callback or polling with matching `AssessmentID`;
- request and result retained only for bounded diagnostic lifecycle;
- cancellation propagates to ABD scheduler but preserves immutable completed evidence.

### 23.4. Monitor-linked status response

Run status adds:

```yaml
monitor_link:
  request_id: ...
  assessment_id: ...
  monitoring_epoch: 17
  trigger_reason: recurrent_client_failure
  resolution_modes:
    - client-observed
    - independent-current
  result_delivery: pending
```

User-started runs omit `monitor_link` rather than fabricating an assessment.

## 24. Persistence

Stores:

```text
detector raw evidence store
blocking profile store
DDI network diagnostic profile store
```

MUST be logically separated.

### 24.1. Atomicity

- temp file + fsync + atomic rename where supported;
- content hash validation;
- bounded entries;
- corrupted newest entry does not destroy last-good;
- migration is idempotent;
- no partial profile visible to Discovery.

### 24.2. Versioning

Initial versions:

```text
DiagnosticTargetPlan schema 1
DiagnosticAttemptEvidence schema 2
BodyProgressEvidence schema 1
ReferencePathEvidence schema 1
DetectorCapacityProfile schema 1
CandidateCoverageVector schema 1
CandidateVerificationSummary schema 1
BlockingProfile schema 2
NetworkDiagnosticProfile envelope schema 2
DiscoverySearchPrior schema 2
```

### 24.3. Resumable partial runs

A run checkpoint MAY persist completed immutable evidence when interrupted by:

- user cancellation;
- process restart;
- WAN transition;
- resource-pressure cancellation;
- bounded global timeout.

Resume is allowed only when:

```text
same target-plan hash
+ compatible detector build/schema
+ same config generation or explicit migration
+ same network context
+ evidence not expired
+ no changed reference-path identity
```

A resumed run MUST revalidate path health and controls. Partial evidence MAY be displayed and exported, but MUST NOT produce final `BlockingProfile` until the target-plan completeness contract is satisfied.

### 24.4. DetectorCapacityProfile

```go
type DetectorCapacityProfile struct {
    PlatformID             string
    CPUClass               string
    AvailableRAMBytes      uint64
    NFQueueBacklogLimit    uint32
    SafeQuickParallelism   uint16
    SafeDeepParallelism    uint16
    MaxBodyBytesInFlight   uint64
    MaxDynamicTargets      uint16
    CalibrationVersion     uint16
    MeasuredAt             time.Time
    ValidUntil             time.Time
    ConfigGeneration       uint64
}
```

Capacity calibration MUST observe:

- completed probes per second;
- control latency delta;
- NFQUEUE drops/backlog;
- CPU/softirq load;
- available RAM and pressure events;
- PPE/GSO visibility state;
- detector cancellation/timeout rate.

The selected concurrency is the highest level that remains below every safety threshold, not the level with maximum raw throughput.

### 24.5. Network context and expiry

DDI retains ownership for:

- exact/compatible/mismatch comparison;
- age TTL;
- WAN change invalidation;
- fast revalidation;
- stale/conflicting states;
- revoke/delete lifecycle.

---


### 24.6. Monitoring-linked persistence

ABD persists only bounded request/result linkage needed for audit and delivery:

- request content hash;
- assessment/request IDs;
- accepted overlay references;
- target-plan hash;
- run/profile IDs;
- delivery acknowledgement;
- network/config/monitoring generations;
- terminal completion state.

ABD MUST NOT become the persistent store for full Monitoring observation history or temporal buckets.

Resume additionally requires matching `MonitoringEpoch` when the run originated from Monitoring. A resumed run after assessment replacement MUST produce a new request/result pair.

# Часть XVI. UI/UX

## 25. Beginner flow

Primary wizard:

```text
Что должно работать?

[x] YouTube
[x] Telegram
[ ] Discord
[ ] Instagram
[ ] Другой домен
```

Next:

```text
Режим диагностики

● Быстрая — основные проверки и минимальная нагрузка
○ Глубокая — fingerprints, QUIC, packet/byte thresholds и дополнительные controls
```

Then:

```text
1. Проверка текущей сети
2. Определение вероятного типа блокировки
3. Приоритетный поиск стратегий
4. Проверка в приложении
5. Ограниченное применение
```

### 25.1. Result summary

Example:

```text
Обнаружено для YouTube:

• DNS-подмена не подтверждена
• UDP/443 не отвечает для YouTube, unrelated QUIC control работает
• TLS 1.3 Android-профиль получает reset после ClientHello
• TLS 1.2 доступен
• Google account control доступен
• возможный packet-budget trigger: 23–27 пакетов, уверенность средняя

Уверенность профиля: высокая
```

### 25.2. Search preview

```text
Discovery сначала проверит:

1. low-amplification TCP candidates
2. ClientHello marker split
3. Android/canonical TLS profile variants
4. QUIC fallback behavior

Если они не помогут, будет выполнен полный bounded search.
```

### 25.3. Honest uncertainty

UI MUST use:

```text
наблюдение
вероятно
высокая уверенность
причинно подтверждено в Discovery
```

and MUST NOT use categorical provider accusations without evidence.

## 26. Advanced UI

Advanced view SHOULD show:

- target plan and roles;
- network context;
- path mode;
- DNS matrix;
- TLS fingerprint matrix;
- QUIC ladder;
- packet/byte experiment graph;
- controls and suppressors;
- evidence graph;
- profile JSON export;
- guided vs full search comparison;
- resource budget consumption;
- direct/reference-path comparison with health provenance;
- partial body-progress timeline and completion reason;
- required/optional/excluded coverage denominator;
- candidate complexity and verification funnel stage;
- calibrated versus effective concurrency.

## 27. One-click Detector → Discovery

Button:

```text
Найти стратегию по результатам диагностики
```

MUST:

1. select exact newly generated profile;
2. invoke DDI context/freshness validation;
3. show plan preview;
4. require baseline probes;
5. start existing Discovery sandbox;
6. display applied and suppressed priors;
7. preserve full fallback;
8. never auto-promote without normal canary flow.

---


### 27.1. Monitoring-linked detector UX

When a run originated from Monitoring, Detector UI shows:

```text
Причина запуска: повторяющаяся проблема у Android-main
Сервис: YouTube
Компонент: video/media
Проверяемый endpoint: получен клиентом через DNS
Изменения конфигурации: не применялись
```

The UI MUST distinguish:

- passive suspicion;
- provisional quick result;
- authoritative ABD profile;
- DDI freshness status;
- Discovery recommendation;
- canary/promotion status.

A passive suspicion MUST NOT be rendered as `Блокировка подтверждена`.

# Часть XVII. Observability and privacy

## 28. Metrics

Required metrics include:

```text
detector_v2_suite_total
detector_v2_probe_total
detector_v2_probe_failure_total
detector_v2_control_failure_total
detector_v2_capture_invalid_total
detector_v2_dynamic_target_total
detector_v2_packet_budget_probe_total
detector_v2_quic_probe_total
detector_v2_hypothesis_total
detector_v2_hypothesis_suppressed_total
blocking_profile_compiled_total
blocking_profile_confidence_total
guided_search_profile_used_total
guided_search_prior_applied_total
guided_search_prior_suppressed_total
guided_search_probe_savings
guided_search_time_savings_ms
guided_search_profile_miss_total
detector_reference_path_probe_total
detector_reference_path_unhealthy_total
detector_path_local_failure_hypothesis_total
detector_partial_body_stall_total
detector_partial_body_bytes_total
detector_object_too_small_total
detector_capacity_calibration_total
detector_effective_parallelism
detector_checkpoint_saved_total
detector_run_resumed_total
guided_search_required_coverage_ratio
guided_search_control_regression_total
guided_search_candidate_funnel_stage_total
```

Labels MUST be bounded and privacy-safe.


Monitoring adapter metrics with bounded labels:

```text
detector_monitor_request_total
detector_monitor_request_rejected_total
detector_monitor_request_suppressed_total
detector_monitor_result_total
detector_monitor_result_delivery_failure_total
detector_client_resolution_binding_total
detector_address_outcome_total
detector_multivantage_comparison_total
detector_observer_capability_rejected_total
```

Allowed labels are bounded enums such as `result`, `reason`, `depth`, `resolution_mode`, `stage`, `authority`. Request IDs, domains, IPs, assessment IDs and client IDs MUST NOT be metric labels.

## 29. Events

```go
type DetectorEvent struct {
    Time          time.Time
    SuiteID       string
    PlanID        string
    ComponentID   string
    TargetID      string
    Phase         string
    Outcome       string
    HypothesisID  string
    Confidence    string
    Reason        string
    BudgetUsed    uint64
    ReferencePathID string
    UniqueBodyBytes uint64
    CoverageState string
    CheckpointID string
}
```


Required structured events:

```text
detector_monitor_request_received
detector_monitor_request_rejected
detector_monitor_request_accepted
detector_monitor_overlay_compiled
detector_client_resolution_bound
detector_address_attempt_completed
detector_multivantage_compared
detector_monitor_result_created
detector_monitor_result_delivered
detector_monitor_result_delivery_failed
```

Every event carries redacted request/assessment correlation, detector run ID, NetworkContextID hash and ConfigGeneration. It MUST NOT contain clear DNS history or raw packet bytes.

## 30. Privacy

Default exports MUST redact:

- raw public egress IP;
- raw LAN client IP/MAC;
- SSID;
- gateway MAC;
- exact custom domain when user selects privacy mode;
- full DNS history unrelated to selected targets;
- raw ClientHello if it may contain identifiers;
- proxy/WARP secrets;
- Telegram secrets.

Hashes MUST be salted per installation or export session as appropriate.

## 31. Issue bundle

Bundle SHOULD contain:

- build/config generation;
- redacted network context;
- target plan roles;
- compact BlockingProfile;
- applied/suppressed priors;
- bounded packet evidence summary;
- capture visibility report;
- resource metrics;
- no secrets.

---

# Часть XVIII. Testing and validation

## 32. Unit tests

Must cover:

- target normalization;
- plan bounds;
- service component expansion;
- target role separation;
- evidence stage classification;
- unique byte accounting;
- packet count layer labeling;
- DNS answer normalization;
- TLS fingerprint identity;
- certificate integrity split;
- QUIC ladder state;
- threshold interval computation;
- evidence independence;
- confidence transitions;
- exclusions/suppressors;
- BlockingProfile deterministic hash;
- SearchPrior mapping;
- DDI adapter compatibility;
- reference-path health and exact-target comparison;
- partial body-progress preservation;
- staged transfer deadlines;
- object suitability/small-object guard;
- coverage denominator and exclusions;
- scoped set-cover tie-breaking;
- verification funnel transitions;
- capacity profile selection;
- resumable checkpoint completeness.


Monitoring adapter unit tests include:

- request expiry/generation/context validation;
- idempotency and content-hash conflict;
- overlay cannot remove controls;
- passive/provisional evidence cannot compile final profile;
- client-resolution snapshot binding;
- per-address outcome aggregation preserves partial failures;
- observer capability/stage mismatch rejection;
- failure code remains immutable when attribution changes;
- result identity and completion semantics;
- result has no action authorization fields.

## 33. Property and fuzz tests

Properties:

```text
same normalized evidence set + same order-independent semantics
→ same BlockingProfile hash
```

```text
duplicate attempt record
→ no confidence increase
```

```text
retransmitted bytes
→ no increase in unique progress
```

```text
GSO skb count change
→ no wire packet verdict change after normalization
```

```text
failed controls
→ target-specific confidence cannot increase
```

```text
one changed search dimension
→ causal shadow result references exact dimension
```

```text
one failed reference path
→ cannot produce host_dead
```

```text
partial body bytes + inter-chunk stall
→ byte count preserved exactly
```

```text
negative-control regression
→ candidate rejected regardless of target coverage
```

```text
same coverage and quality
→ lower complexity candidate ranks first
```

```text
partial run
→ no final BlockingProfile
```

Fuzz:

- malformed domains/URLs;
- malformed DNS packets;
- CNAME loops;
- malformed TLS alerts;
- malformed QUIC packets;
- oversized evidence arrays;
- corrupted profile stores;
- hash collisions in redacted IDs;
- migration input;
- dynamic target metadata;
- reference path state and expiry;
- malformed content-length/range responses;
- coverage bitsets and exclusions;
- checkpoint truncation and duplicate resume.

## 34. Synthetic network laboratory

Required scenarios:

### 34.1. DNS

- UDP spoof, DoH healthy;
- fake NXDOMAIN;
- fake empty;
- stub IP reused;
- legitimate CDN answer difference;
- DoH hostname blocked but bootstrap IP works;
- AAAA-only failure;
- SVCB/HTTPS stripped;
- all resolvers fail due WAN outage.

### 34.2. TLS/HTTP

- TLS 1.3 reset, TLS 1.2 healthy;
- Android fingerprint reset, canonical healthy;
- valid server TLS alert;
- injected garbage TLS;
- certificate substitution;
- local clock failure;
- HTTP 451;
- ISP redirect;
- legitimate OAuth/CDN redirect;
- origin WAF/rate limit;
- bounded body stall;
- headers succeed but body stalls after partial progress;
- known small object below milestone;
- range response ignored or rewritten;
- direct SYN failure with healthy reference success;
- direct and reference failure with unhealthy reference control;
- origin unavailable through two independent healthy paths.

### 34.3. QUIC

- UDP/443 global drop;
- target QUIC Initial drop;
- Version Negotiation only;
- Retry then stall;
- handshake complete, HTTP/3 fails;
- QUIC healthy, TCP blocked;
- TCP healthy, QUIC blocked.

### 34.4. L4 thresholds

- packet-count trigger with constant bytes;
- byte-count trigger with constant packets;
- bidirectional packet budget;
- origin header-size limit;
- keep-alive close;
- random loss;
- GSO visibility incomplete;
- PPE hides inbound progress;
- high-latency path without censorship.

### 34.5. Controls

- target fails, controls healthy;
- same-provider controls fail;
- unrelated controls fail;
- all targets fail due WAN;
- production strategy accidentally active during native test;
- dynamic target disappears mid-suite;
- reference path expires during comparison;
- candidate covers all targets but regresses one negative control;
- excluded target would otherwise inflate coverage.

## 35. Integration tests

- Detector v1 request backward compatibility;
- custom target request;
- Service Profile target compilation;
- quick/deep budget enforcement;
- cancel/restart;
- config reload;
- WAN transition invalidation;
- raw evidence → BlockingProfile;
- BlockingProfile → NetworkDiagnosticProfile envelope;
- DDI revalidation;
- profile-enabled Discovery;
- stale/conflicting profile fallback;
- guided vs unguided same-seed comparison;
- no direct config write;
- no cross-service action;
- reference-path comparison and revocation;
- interrupted deep run checkpoint/resume;
- resumed run rejected after WAN/context change;
- candidate coverage and verification funnel reports;
- capacity calibration fallback to static safe defaults.


Monitoring ↔ ABD integration scenarios:

```text
passive suspicion → accepted quick request → complete profile → result delivered
passive suspicion → global WAN suppressor → request suppressed
expired client resolution → overlay rejected or independently re-resolved
partial multi-IP failure → profile preserves address-selective hypothesis
HTTP local stall + TCP-only observer → comparison inconclusive
observer unavailable → no target-failure edge
WAN change during run → incomplete result, no profile
ConfigGeneration change → cancellation/restart, no cross-generation merge
Monitoring epoch replacement → old result rejected
user cancellation → immutable evidence + incomplete result
```

## 36. Real router validation

Target platform:

- Keenetic/Entware;
- supported architecture builds;
- PPE enabled globally with scoped exclusion;
- NFQUEUE/GSO diagnostics;
- bounded memory and CPU.

Required proof:

- native direct path mark and egress;
- no self-interference;
- complete visibility for packet-sensitive verdicts;
- quick suite completes within budget;
- deep suite degrades safely on low memory;
- restart/WAN flap cleanup;
- profile invalidation after WAN change;
- no persistent high load;
- calibrated parallelism does not cause NFQUEUE loss or control latency regression;
- partial-run cleanup and resume do not leak sockets, marks or temporary routes;
- reference-path credentials never enter artifacts.


Monitoring-originated router validation additionally proves:

- exact DNS answer observed by a LAN client is available to ABD;
- client-observed and independent-current resolution modes remain distinct;
- multiple CDN addresses retain separate outcomes;
- Monitoring request cannot start when PPE/NFQUEUE visibility suppressor is active;
- result returns to the same assessment and current network/config generation;
- no legacy Watchdog direct apply path is invoked.

## 37. Real Android validation

At least one supported Android device must validate:

- selected service profile;
- Android-like or captured ClientHello differential;
- QUIC/TCP behavior;
- actual application component flows;
- same-client negative controls;
- Detector-guided Discovery;
- candidate canary;
- rollback;
- no collateral Gmail/Google Feed failure for YouTube profile.


Monitoring-triggered Android scenarios MUST show:

- passive client failure creates suspicion, not action;
- ABD reproduces the exact endpoint or reports it stale;
- unrelated Android control remains healthy;
- final profile links to the triggering assessment;
- recommendation/canary occurs only after DDI and Discovery;
- recovered real traffic demotes Monitoring health state without rewriting historical profile.

## 38. A/B guided search validation

For the same target plan and deterministic seed:

```text
Run A: profile disabled
Run B: fresh BlockingProfile enabled
Run C: stale/conflicting profile
Run D: intentionally misleading low-confidence profile
```

PASS requires:

- B finds same or better validated winner;
- B reduces probe/time cost or is explicitly reported neutral;
- B never weakens controls;
- C suppresses invalid priors and completes normally;
- D cannot produce false promotion;
- exhaustive fallback remains reachable;
- results explain applied/suppressed priors;
- required component coverage is equal or better;
- no target is silently removed from coverage denominator;
- candidate complexity improves only as a tie-breaker after quality/safety;
- funnel statistics and repeated stability are reported.

---

# Часть XIX. Hard gates and release verdicts

## 39. Detector safety hard gates

```text
detector_single_probe_confirmed_total == 0
detector_exception_string_only_confirmed_total == 0
detector_static_target_only_high_confidence_total == 0
detector_self_interference_total == 0
detector_native_path_unproven_total == 0
detector_capture_invalid_packet_verdict_total == 0
detector_control_failure_ignored_total == 0
detector_duplicate_evidence_confidence_increase_total == 0
detector_cross_component_evidence_merge_total == 0
detector_cross_generation_evidence_merge_total == 0
detector_unbounded_dynamic_scan_total == 0
detector_resource_budget_bypass_total == 0
detector_sensitive_export_total == 0
detector_host_dead_from_single_reference_failure_total == 0
detector_reference_path_unhealthy_used_total == 0
detector_reference_path_used_as_action_authorization_total == 0
detector_partial_run_profile_compiled_total == 0
detector_resume_cross_network_context_total == 0
detector_capacity_self_interference_total == 0
```

## 40. DNS/TLS/QUIC hard gates

```text
detector_dns_single_resolver_spoof_confirmed_total == 0
detector_dns_cdn_variance_misclassified_total == 0
detector_unverified_mitm_verdict_total == 0
detector_tls_availability_integrity_conflation_total == 0
detector_tls_fingerprint_unlabeled_total == 0
detector_quic_single_target_global_udp_verdict_total == 0
detector_quic_tcp_evidence_conflation_total == 0
detector_valid_application_error_dpi_total == 0
detector_head_only_available_verdict_total == 0
detector_partial_progress_discarded_total == 0
detector_small_object_classified_throttled_total == 0
detector_fixed_16kb_window_confirmed_without_profile_total == 0
```

## 41. L4 threshold hard gates

```text
detector_packet_threshold_reported_as_byte_threshold_total == 0
detector_byte_threshold_reported_as_packet_threshold_total == 0
detector_gso_skb_count_as_wire_packet_total == 0
detector_single_origin_l4_budget_confirmed_total == 0
detector_server_header_limit_dpi_total == 0
detector_retransmission_counted_as_progress_total == 0
detector_l4_threshold_without_controls_total == 0
```

## 42. BlockingProfile and DDI hard gates

```text
blocking_profile_without_target_plan_total == 0
blocking_profile_without_network_context_total == 0
blocking_profile_without_provenance_total == 0
blocking_profile_mutated_after_compile_total == 0
blocking_profile_high_confidence_with_contradiction_total == 0
blocking_profile_direct_action_authorization_total == 0
blocking_profile_direct_production_write_total == 0
guided_search_skipped_baseline_total == 0
guided_search_disabled_full_fallback_total == 0
guided_search_profile_overrode_current_baseline_total == 0
guided_search_target_unvalidated_promotion_total == 0
guided_search_cross_service_action_total == 0
guided_search_white_sni_direct_promotion_total == 0
guided_search_false_savings_report_total == 0
guided_search_required_component_uncovered_total == 0
guided_search_coverage_ignored_control_regression_total == 0
guided_search_cross_service_set_cover_total == 0
guided_search_excluded_target_hidden_total == 0
guided_search_more_complex_candidate_preferred_without_gain_total == 0
guided_search_unverified_shortlist_promotion_total == 0
```

All hard gates from DDI addendum remain mandatory.


### 42.1. Monitoring adapter hard gates

```text
detector_monitor_request_direct_action_total == 0
detector_monitor_request_without_target_plan_overlay_total == 0
detector_monitor_request_without_network_context_total == 0
detector_monitor_request_without_config_generation_total == 0
detector_monitor_request_without_budget_token_total == 0
detector_monitor_request_expired_accepted_total == 0

detector_provisional_monitor_evidence_profile_compiled_total == 0
detector_passive_observation_counted_as_independent_probe_total == 0
detector_monitor_recurrence_counted_as_evidence_independence_total == 0

detector_client_resolution_replaced_silently_total == 0
detector_probe_without_resolution_binding_total == 0
detector_cname_terminal_ip_misattributed_total == 0
detector_multi_ip_partial_failure_hidden_total == 0
detector_first_success_erased_address_failures_total == 0
detector_stale_client_resolution_used_total == 0

detector_multivantage_stage_mismatch_total == 0
detector_http_hypothesis_from_tcp_tls_only_observer_total == 0
detector_observer_unavailable_as_target_failure_total == 0
detector_exact_endpoint_service_resolution_conflated_total == 0
detector_observer_capability_unproven_total == 0

detector_result_without_monitor_assessment_link_total == 0
detector_result_cross_network_context_total == 0
detector_result_cross_config_generation_total == 0
detector_result_cross_monitoring_epoch_total == 0
detector_incomplete_run_final_profile_total == 0
detector_monitor_result_action_authorization_total == 0
detector_monitor_result_delivery_identity_mismatch_total == 0
```

## 43. Release verdicts

```text
ABD_TARGET_PLAN_READY
ABD_CLEAN_BASELINE_READY
ABD_REFERENCE_PATH_READY
ABD_DNS_EVIDENCE_READY
ABD_TLS_HTTP_EVIDENCE_READY
ABD_BODY_PROGRESS_READY
ABD_QUIC_EVIDENCE_READY
ABD_L4_PROFILER_READY
ABD_DYNAMIC_CONTROLS_READY
ABD_EVIDENCE_GRAPH_READY
ABD_BLOCKING_PROFILE_READY
ABD_DDI_ADAPTER_READY
ABD_MONITOR_ADAPTER_READY
ABD_CLIENT_RESOLUTION_READY
ABD_MULTI_VANTAGE_READY
ABD_COVERAGE_PLANNER_READY
ABD_CAPACITY_PROFILE_READY
ABD_ROUTER_VALIDATED
ABD_ANDROID_VALIDATED
ABD_PRODUCTION_READY
```

`ABD_PRODUCTION_READY` requires all previous verdicts plus updated companion validation.

Combined end-to-end verdict:

```text
DETECTOR_GUIDED_STRATEGY_SEARCH_READY
```

It requires:

- `ABD_PRODUCTION_READY`;
- `DDI_PRODUCTION_READY`;
- existing Discovery/Optimizer release gates;
- real target A/B search proof;
- no false production promotion.

---


Additional v1.2 verdicts:

```text
ABD_MONITOR_ADAPTER_READY
ABD_CLIENT_RESOLUTION_READY
ABD_MULTI_VANTAGE_READY
```

`ABD_MONITOR_ADAPTER_READY` requires:

- typed request validation;
- complete overlay compilation with mandatory controls;
- authority separation;
- result handoff identity/generation tests;
- all Monitoring adapter hard gates zero.

`ABD_CLIENT_RESOLUTION_READY` requires:

- DNS query/CNAME/terminal address correlation;
- client-observed versus independent-current separation;
- per-address outcome vector;
- stale snapshot handling;
- no hidden first-success aggregation.

`ABD_MULTI_VANTAGE_READY` requires:

- capability descriptors;
- stage-aligned comparisons;
- exact-endpoint versus independent-resolution separation;
- observer-health suppressors;
- no remote result used as action authorization.

Final Monitoring escalation dependency:

```text
MON_OBSERVATION_READY
+ MON_TEMPORAL_MODEL_READY
+ MON_TRIGGER_PLANNER_READY
+ ABD_MONITOR_ADAPTER_READY
+ ABD_CLIENT_RESOLUTION_READY
+ ABD_MULTI_VANTAGE_READY
+ ABD_PRODUCTION_READY
→ MON_ABD_ESCALATION_READY
```

# Часть XX. Implementation stages

## ABD-1 — Baseline audit and compatibility fixtures

Deliverables:

- exact map of current `detector/*`, API, UI, history and target catalog;
- map of detector marks/path behavior;
- fixtures for current DNS/domain/TCP/SNI/Telegram outputs;
- backward-compatibility tests;
- verified gaps report;
- reference extraction registry including pinned `rcd27/blockcheckw` 0.9.2 and `belotserkovtsev/ladon` behavior entries;
- implementation commit.

Exit gates:

- existing behavior is reproducible;
- no silent change to v1 API;
- source/provenance review complete.

## ABD-2 — User Target Plan and Service Components

v1.2 additions:

- define `MonitorDiagnosticRequest` and strict validator;
- define `TargetPlanOverlay` and compilation report;
- merge observed targets only through Service Profile/component policy;
- preserve all mandatory controls and clean baseline;
- reject cross-client, cross-service and expired overlay items;
- add Ladon-derived demand-target provenance without moving intake ownership from Monitoring.


Deliverables:

- `UserTargetSelection`;
- `DiagnosticTargetPlan` schema;
- Service Profile adapter;
- custom domains/URLs;
- target roles and controls;
- quick/deep budgets;
- preview API;
- unit/fuzz tests.

Exit gates:

- user-selected services compile deterministically;
- controls are separate from action scope;
- bounds enforced.

## ABD-3 — Clean probe path and network context

v1.2 additions:

- validate request network/config/monitoring generations and budget token;
- define `ObserverCapability` and health lease;
- implement exact-endpoint and independent-resolution modes;
- implement stage-aware `MultiVantageComparison`;
- treat observer-unavailable as no opinion;
- preserve v1.1 reference-egress aliveness semantics.


Deliverables:

- dedicated detector path token/mark;
- native/production/candidate/transport path identity;
- self-interference detector;
- capture visibility integration;
- WAN transition handling;
- path proof events;
- `ReferencePathSpec`, health leases and exact-target comparison;
- path-local versus origin-unreachable hypotheses;
- reference secret redaction and revocation;
- namespace integration tests.

Exit gates:

- native baseline cannot traverse active strategies unnoticed;
- packet-sensitive verdict blocked on incomplete visibility;
- unhealthy or expired reference path cannot refine reachability;
- one reference failure cannot produce `host_dead`;
- reference success cannot authorize routing.

## ABD-4 — DNS differential evidence

v1.2 additions:

- consume immutable `ClientResolutionSnapshot`;
- correlate original query, CNAME chain and terminal A/AAAA answers;
- bind every exact-endpoint attempt to a snapshot;
- run independent-current resolution as a separate experiment;
- retain per-address and per-family outcomes;
- detect stale or mismatched client resolution.


Deliverables:

- UDP/TCP/DoH/bootstrapped DoH matrix;
- A/AAAA/CNAME/HTTPS/SVCB support where platform permits;
- NXDOMAIN/random controls;
- answer normalization;
- resolver consensus;
- DNS hypotheses and suppressors;
- guided resolver priors.

Exit gates:

- CDN variance not misclassified;
- single resolver cannot produce confirmed spoof verdict.

## ABD-5 — TLS/HTTP fingerprint matrix

v1.2 additions:

- add `EvidenceAuthority` to every attempt;
- split `ProbeFailureCode` from `FailureAttribution`;
- require stage-compatible observer evidence;
- forbid HTTP hypothesis from TCP/TLS-only remote success;
- preserve all v1.1 body-progress, staged deadline and small-object contracts.


Deliverables:

- canonical/browser/Android profiles;
- TLS 1.2/1.3 pairs;
- fresh/persistent pairs;
- verified/unverified certificate split;
- staged failure evidence;
- HTTP method/body/redirect checks;
- staged connect/TLS/TTFB/inter-chunk/overall deadlines;
- `BodyProgressEvidence` with exact partial unique-byte preservation;
- component availability milestones and object-suitability guards;
- origin suppressors;
- Real ClientHello Laboratory integration.

Exit gates:

- MITM requires verified path;
- fingerprint identity preserved end-to-end;
- headers-only success cannot satisfy body/media milestone;
- small objects cannot become throttling proof;
- partial progress survives stall classification.

## ABD-6 — QUIC detection

Deliverables:

- QUIC ladder Q0–Q7;
- UDP/443 controls;
- Version Negotiation/Retry evidence;
- handshake/HTTP3 progress;
- fingerprint/IP-family dimensions;
- TCP-vs-QUIC comparison;
- resource bounds.

Exit gates:

- one target cannot imply global UDP block;
- QUIC evidence remains separate from TCP evidence.

## ABD-7 — L4 packet/byte threshold profiler

Deliverables:

- independent packet/byte experiments;
- unique-byte accounting;
- validated packet accounting layer;
- uplink/downlink and fresh/persistent modes;
- multi-target controls;
- threshold intervals;
- server-limit suppressors;
- amplification-aware search priors.

Exit gates:

- no `drop_at_kb` claim when only packet trigger measured;
- no high-confidence result from one origin.

## ABD-8 — Dynamic infrastructure controls

Deliverables:

- bounded `DynamicControlTargetProvider`;
- ASN/provider/subnet/service selectors;
- local/signed data sources;
- target validation;
- cache/TTL/last-good;
- anti-abuse limits;
- deterministic sampling seed;
- provenance export.

Exit gates:

- no broad scanning;
- dynamic target failures do not become service proof automatically.

## ABD-9 — Evidence graph and confidence engine

v1.2 additions:

- represent monitoring recurrence as metadata, never duplicate independence;
- add provenance-only edges from assessment/request/resolution;
- reject passive/provisional evidence as final active support;
- model observer capability and target-identity mode in causal edges;
- preserve contradictions from partially failing CDN address sets.


Deliverables:

- observation/correlation/hypothesis/contradiction/exclusion graph;
- independence checker;
- confidence ladder;
- suppressor engine;
- control precedence;
- deterministic aggregation;
- property/fuzz tests.

Exit gates:

- duplicate evidence cannot increase confidence;
- contradictions visible and enforce downgrades.

## ABD-10 — BlockingProfile compiler

v1.2 additions:

- embed `MonitorAssessmentRef` when applicable;
- compile final profile only from authoritative complete ABD evidence;
- produce typed `MonitorDiagnosticResult` for every accepted request;
- forbid profile ID in incomplete/canceled/suppressed result;
- keep Monitoring temporal state outside `BlockingProfile`.


Deliverables:

- immutable schema;
- component profiles;
- DNS/infrastructure sections;
- content hash;
- raw evidence refs;
- compatibility migration;
- deterministic compile;
- compact/redacted export;
- profile store interface.

Exit gates:

- same normalized graph compiles identically;
- profile cannot authorize action.

## ABD-11 — DDI adapter and guided planner priors

v1.2 additions:

- monitor observations affect only experiment/search ordering priors;
- require DDI freshness even when monitoring triggered the run;
- prohibit direct Monitoring → Discovery/WARP handoff;
- keep current active target evidence dominant over stored/passive priors;
- preserve v1.1 coverage-aware funnel and full bounded fallback.


Deliverables:

- `BlockingProfile` inside `NetworkDiagnosticProfile` envelope;
- `DiscoverySearchPrior` compiler;
- hypothesis mappings;
- DDI freshness/revalidation adapter;
- current baseline precedence;
- applied/suppressed explanations;
- guided/full A/B harness;
- `CandidateCoverageVector` and explicit coverage denominator;
- scoped set-cover/minimal-binding planner;
- candidate complexity/resource cost model;
- bounded A→D verification funnel and repeated stability summary;
- exhaustive fallback proof.

Exit gates:

- no second optimizer;
- DDI and ABD schemas interoperable;
- search prior cannot skip safety phases;
- negative-control regression rejects any coverage winner;
- coverage cannot cross service/authorization scope;
- excluded targets remain visible;
- shortlist cannot be promoted without functional/stability/canary stages.

## ABD-12 — UX, field validation and release

v1.2 additions:

- implement internal Monitoring adapter API and idempotency;
- show assessment/request linkage and evidence authority in UX;
- validate result delivery identity and generation safety;
- run shadow/cutover tests against legacy Watchdog without direct apply;
- require `ABD_MONITOR_ADAPTER_READY`, `ABD_CLIENT_RESOLUTION_READY` and `ABD_MULTI_VANTAGE_READY`;
- synchronize Continuous Monitoring, Field Test, Service Profiles and Implementation Validation documents.


Deliverables:

- beginner service/domain wizard;
- quick/deep mode;
- advanced evidence view;
- one-click Detector → Discovery;
- metrics/events/issue bundle;
- `DetectorCapacityProfile` calibration and safe static fallback;
- checkpoint/resume lifecycle for partial deep runs;
- Keenetic validation;
- Android validation;
- A/B search savings report;
- companion addenda updates;
- final release verdict.

Exit gates:

- real target proof complete;
- false-positive suites pass;
- hard gates zero;
- calibrated concurrency causes no NFQUEUE/control regression;
- interrupted run resumes only in compatible context and never emits incomplete profile;
- `DETECTOR_GUIDED_STRATEGY_SEARCH_READY` issued only by umbrella validation.

---

# Часть XXI. Companion document updates

## 44. Field Test Automation

Must add suites:

```text
FT-ABD-A  user target plan and clean baseline
FT-ABD-B  DNS differential and resolver controls
FT-ABD-C  TLS/HTTP fingerprints and certificate integrity
FT-ABD-D  QUIC ladder and TCP comparison
FT-ABD-E  L4 packet/byte profiler and false-positive controls
FT-ABD-F  dynamic infrastructure target bounds
FT-ABD-G  evidence graph/confidence/suppressors
FT-ABD-H  BlockingProfile → DDI → guided Discovery A/B
FT-ABD-I  Keenetic resource and WAN transition
FT-ABD-J  Android application and negative controls
FT-ABD-K  direct/reference-egress aliveness and path-health expiry
FT-ABD-L  body-progress preservation, small-object guard and staged deadlines
FT-ABD-M  coverage planner, verification funnel and control dominance
FT-ABD-N  capacity calibration, interruption and resumable checkpoints
FT-ABD-O  Monitoring request validation, overlay and authority separation
FT-ABD-P  client DNS/CNAME/IP snapshot and per-address outcomes
FT-ABD-Q  stage-aware multi-vantage observer comparison
FT-ABD-R  result handoff, generation mismatch and cancellation
```

## 45. Service Profiles / Beginner UX

Must add:

- diagnostic target definitions per component;
- same-service/same-provider/unrelated control roles;
- protocol objectives;
- QUIC/TCP requirements;
- allowed dynamic-target policy;
- default quick/deep budgets;
- profile-specific success thresholds;
- no hardcoded runtime service branching;
- beginner wizard strings and safety explanation;
- optional reference-path declaration without exposing secrets;
- component availability milestone and known-large object policy;
- required/optional target coverage semantics;
- platform capacity policy upper bounds and resume UX;
- Monitoring-linked diagnostic reason and exact client endpoint display;
- clear distinction between passive suspicion, ABD confirmation and recommendation;
- no UX path that treats MonitorAssessment as authorization.

## 46. Implementation Validation

Must register:

- `ABD-1…ABD-12`;
- all schemas and APIs;
- all hard gates;
- all release verdicts;
- reference provenance/license checks;
- L0–L8 validation coverage;
- validation-of-validation tests;
- real router/Android evidence requirements;
- A/B guided search report;
- impossible false `PASS` when target validation absent;
- reference-path false-oracle meta-tests;
- partial body-progress and small-object false-positive tests;
- coverage denominator/control-regression meta-tests;
- capacity self-interference and partial-run false-PASS guards;
- Monitoring request/overlay/result schema registry;
- client-resolution and per-address aggregation mutants;
- stage-mismatch observer false-PASS mutants;
- cross-network/config/monitoring-generation result rejection;
- impossible PASS when provisional evidence compiles a profile.

## 47. Detector-Guided Discovery addendum alignment

A future v1.1 of the existing DDI/TGB document SHOULD:

- insert this addendum before DDI in normative order;
- replace raw suite → profile ownership with ABD compiler reference;
- use envelope schema 2;
- name `BlockingProfile` explicitly;
- retain all DDI freshness and planner gates;
- leave `TGB-1…TGB-10` unchanged.

This alignment is documentary; implementation MUST already obey the ownership delta in Section 0.3 of this addendum.

---


## 47.1. Continuous Monitoring addendum alignment

`B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md` remains the owner of:

- passive observation intake;
- monitor subjects and assessments;
- temporal buckets, hysteresis, recovery and decay;
- diagnostic trigger planner and budgets;
- legacy Watchdog compatibility/cutover;
- Monitoring UI and Failure Inbox projection.

This ABD v1.2 owns:

- validation of Monitoring requests;
- overlay → complete target plan compilation;
- exact client-resolution active experiments;
- authoritative evidence and profile compilation;
- structured result delivery.

Neither document MAY define a competing second implementation of the other subsystem.

# Definition of Done

This addendum is complete only when all statements are true:

- Existing B4 Detector capabilities remain regression-tested.
- User can choose needed services and custom domains before diagnostics.
- Service Profiles compile primary targets and independent controls.
- Native/direct probe path is proven and isolated from current bypass strategies.
- Reference path is independently health-checked, exact-target scoped and never treated as routing authorization.
- Path-local reachability suspicion and origin-wide unreachability remain distinct; one failed proxy never proves `host_dead`.
- DNS evidence includes differential controls and does not mistake ordinary CDN variance for spoofing.
- TLS evidence separates version, fingerprint, stage and certificate integrity.
- Component availability beyond headers requires declared body/media progress milestone.
- Partial body progress is retained across inter-chunk stall and small objects cannot become false throttling proof.
- QUIC has a first-class bounded ladder and controls.
- Packet-count and byte-count thresholds are measured independently.
- Dynamic infrastructure selection is bounded, ethical, cached and provenance-aware.
- Evidence graph records support, contradictions, exclusions and controls.
- Confidence cannot increase from duplicate/non-independent evidence.
- Detector compiles immutable `BlockingProfile`.
- DDI wraps it in freshness-aware `NetworkDiagnosticProfile` and revalidates context.
- Discovery receives explainable `DiscoverySearchPrior`.
- Coverage accounting includes every required target and exposes every exclusion.
- Candidate selection preserves negative controls, exact service scope and minimal justified complexity.
- Wide shortlist candidates pass functional, repeated-stability and Android-canary funnel stages before promotion.
- Current target baseline overrides conflicting stored priors.
- Hints may reduce search cost but cannot disable target validation or full bounded fallback.
- White SNI, route fallback and packet actions are never directly promoted from detector evidence.
- Guided and unguided same-seed runs are compared.
- Search savings are measured honestly.
- Keenetic resource/capture validation passes.
- Concurrency is selected by a safety-aware capacity profile or conservative static fallback, never raw throughput alone.
- Cancelled/interrupted deep runs preserve immutable evidence but cannot emit final profile until compatible resume completes all required work.
- Real Android application and negative-control validation passes.
- Field Test, Service Profiles and Implementation Validation are updated.
- Monitoring can submit only typed, scoped, current and budgeted diagnostic requests.
- Monitor overlay cannot remove controls or widen service/component scope.
- Client-observed resolution and independent-current resolution remain separate experiments.
- Every exact-endpoint attempt is bound to a resolution snapshot or explicit independent resolution.
- Per-address failures remain visible even when another address succeeds.
- Passive recurrence never becomes false evidence independence.
- Reference observers are capability-declared and compared only at compatible stages.
- Observer transport failure is represented as no opinion, not target failure.
- Failure code remains distinct from causal attribution and blocking hypothesis.
- Every accepted Monitoring request receives a typed result linked to the same assessment and generations.
- Incomplete, canceled, suppressed or stale requests cannot emit final profile.
- Monitoring-triggered profiles still pass DDI, Discovery and Android canary before any production action.
- `ABD_MONITOR_ADAPTER_READY`, `ABD_CLIENT_RESOLUTION_READY` and `ABD_MULTI_VANTAGE_READY` are issued by umbrella validation.
- All hard gates are zero.
- `DETECTOR_GUIDED_STRATEGY_SEARCH_READY` is issued only after both `ABD_PRODUCTION_READY` and `DDI_PRODUCTION_READY`.
