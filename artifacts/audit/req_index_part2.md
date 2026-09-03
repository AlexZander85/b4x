# Индекс нормативных требований — часть 2 (read-only аудит)

Источник: 4 нормативных companion-документа B4. Нумерация строк — по файлам на диске.
Тип: MUST/SHOULD/MAY = модальность нормы; gate = verification/acceptance gate; deliverable = этап/артефакт.
ID без явного префикса в документе помечены `(derived)`.

## 1. B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md (PPE)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| PPE-01 | 12 | Никакого автоматического global offload disable | MUST |
| PPE-02 | 79 | Per-flow exclusion только при подтверждённой capability | MUST |
| PPE-03 | 80–81 | CPU-окно ограничено первыми N пакетами; bulk не удерживается | MUST |
| PPE-04 | 82–83 | Правила только forwarding path, ограничены транспортом/портом/scope | MUST |
| PPE-05 | 84–85 | IPv4/IPv6 и TCP/QUIC имеют раздельный capability/status | MUST |
| PPE-06 | 86–87 | Наличие PPE target ≠ видимость; обязателен functional self-test; неполная видимость запрещает hold/replay/promotion | MUST |
| PPE-07 | 88 | Ошибка apply деградирует в fail-open/observe-only, не останавливает B4 | MUST |
| PPE-08 | 89–90 | B4 удаляет только свои chains; повторный apply идемпотентен | MUST |
| PPE-09 | 91 | NDM regeneration не должен незаметно снять защиту | MUST |
| PPE-10 | 92 | UI/API не показывают PASS без реального self-test | MUST |
| PPE-11 | 98–160 | Конфиг `offload_policy: detect/exclude/disable-global` с подмоделью ppe | MUST |
| PPE-12 | 155–160, 177 | `disable-global` никогда не включается автоматически; только Advanced | MUST |
| PPE-13 | 181–199 | Effective port set = intersection конфигурации и B4-наборов; запрет hostname-ограничения | MUST |
| PPE-14 | 236–243 | Функциональная проверка PPE target через /proc/net/*_targets | MUST |
| PPE-15 | 245–253 | connskip проверяется функционально (временная chain), не поиском файла | MUST |
| PPE-16 | 262–271 | Предпочитать `iptables -w`/`ip6tables -w`; fallback только при доказанной совместимости | SHOULD |
| PPE-17 | 273–281 | Недостаточные права → `unsupported-or-permission-denied`, не silent success | MUST |
| PPE-18 | 283–293 | Решение по реальным capability, модель роутера — лишь диагностика | MUST |
| PPE-19 | 299–311 | Собственные chains B4_PPE_PRE/B4_PPE_FWD, ровно один owned jump, provenance-комментарии | MUST |
| PPE-20 | 320–340 | TCP (multiport+connskip→PPE) и QUIC (udp) правила | MUST |
| PPE-21 | 342–352 | Source scope до первого payload; запрет широкого LAN→PPE без отображения в UI | MUST |
| PPE-22 | 354–364 | IPv4 — отдельный apply gate; IPv6 best-effort при auto; частичный статус явный | MUST |
| PPE-23 | 366–376 | Порядок правил: до hardware binder, без конфликтов с marks; подтверждается router-тестом | MUST |
| PPE-24 | 382–395 | Apply pipeline: detect→compile→validate→chains→jumps→verify→self-test→status | MUST |
| PPE-25 | 397–404 | Идемпотентность: без дублей, атомарное обновление, previous working generation | MUST |
| PPE-26 | 406–427 | NDM regeneration: нативный hook или event-driven reapply; периодический assert — safety net; после wipe → reapply+verify+light check | MUST |
| PPE-27 | 429–438 | Shutdown удаляет только owned rules/jumps/chains/transient | MUST |
| PPE-28 | 440–447 | Crash recovery: reconcile stale chains, orphan-дубликаты удаляются; stale ≠ успех | MUST |
| PPE-29 | 486–514 | Level 2 controlled A/B — нормативный production gate; split ClientHello + incoming progress | MUST |
| PPE-30 | 516–533 | A/B не меняет production rules для всех клиентов; изоляция через dedicated device/ipset/port/ns | MUST |
| PPE-31 | 566–576 | Verdict INCONCLUSIVE нельзя преобразовывать в PASS | MUST |
| PPE-32 | 578–590 | `offload_suspected=true` только при полном наборе (endpoint healthy + A/B меняет видимость) | MUST |
| PPE-33 | 609–617 | Mode complete: разрешены hold/reassembly/retransmission-idempotency/Discovery/canary | MUST |
| PPE-34 | 619–632 | Outgoing-only/unknown: только observe, stateless mutation, fail-open; запрет hold/promotion | MUST |
| PPE-35 | 634–643 | Incomplete: fail-open release, observe-only flow, event `capture_visibility_incomplete` | MUST |
| PPE-36 | 645–654 | Runtime degradation (rules пропали/NDM) → degraded, блок новых visibility-dependent actions | MUST |
| PPE-37 | 660–712 | API endpoints + mutation safety: auth, idempotency key, config-gen precondition, audit, rollback | MUST |
| PPE-38 | 716–765 | UI: статусы/поля/действия; «Работает» нельзя показывать по наличию правила | MUST |
| PPE-39 | 769–818 | Observability: события, метрики, diagnostic bundle без payload/secrets без явного consent | MUST |
| PPE-40 | 826–837 | PPE-1: audit + capability model, без rule mutations | deliverable |
| PPE-41 | 839–851 | PPE-2: rule compiler, golden iptables-restore fixtures | deliverable |
| PPE-42 | 853–865 | PPE-3: transactional apply/remove, rollback, interrupted-apply тест | deliverable |
| PPE-43 | 867–877 | PPE-4: NDM resilience, simulated table wipe, без reapply storm | deliverable |
| PPE-44 | 879–887 | PPE-5: static/passive diagnostics, не может эмитить PASS | deliverable |
| PPE-45 | 889–903 | PPE-6: controlled self-test; dead endpoint → INCONCLUSIVE | deliverable |
| PPE-46 | 905–918 | PPE-7: runtime safety gate wiring в hold/reassembly/ActionToken/Discovery/canary | deliverable |
| PPE-47 | 920–932 | PPE-8: API/UI/productization, rollback из UI, без заявлений о global offload disable | deliverable |
| PPE-48 | 1029–1046 | Production acceptance: функциональное обнаружение, scoped rules, идемпотентность, раздельные статусы, NDM, controlled test, A/B, fail-open, отсутствие hard-coded PASS | gate |
| PPE-49 | 1052–1086 | PR PPE-A…PPE-F: отдельные PR, не смешивать с fake strategy/profiles/optimizer/UI | deliverable |

## 2. B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md (RST/GSO)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| RG-01 (derived) | 24–31 | Приоритет требований: v2.3 Architecture → этот addendum → Patch Plan → notes | MUST |
| RG-02 (derived) | 33 | Issue #280 — только read-only reference; cherry-pick/blind port/fixed mark запрещены | MUST |
| RG-03 (derived) | 43–44 | Reassembled ClientHello — равноправный evidence; один decision для GSO- и MSS-раскладок | MUST |
| GSO-01 | 45 | NFQA_CFG_F_GSO — capability-gated ускоритель, не замена TCP reassembly | MUST |
| GSO-02 | 46–47 | Нормализация GSO только по требованию ActionPlan; запрет двойной классификации/действий | MUST |
| RST-01 | 48–50 | Passive RST defense в TCP FSM; default observe; suppression только при полной видимости+доказательствах | MUST |
| RST-02 | 51–52 | Автовозврат passive RST в observe при collateral damage; сохранение fail-open/bounded | MUST |
| RST-03 (derived) | 54–67 | Не-цели: без замены reassembly GSO, без global GSO default, без фиксированной mark, без блокировки по IPID, без повторного Stage 1–36 | MUST |
| ADR-H1 | 93–109 | GSO MAY снижать latency, но MUST NOT быть единственным способом получить clear SNI | MUST/MAY |
| ADR-H2 | 111–132 | `EvidenceReassembledTCPSNI`: участие в set matching, provenance, привязка FlowKey/ClientHelloID/ConfigGen, не global learned-IP, не positive при конфликте/truncation/ECH | MUST |
| ADR-H3 | 134–174 | gso_mode off/observe/classify/full + execution.gso_policy; default off/inherit; `full` MUST NOT включаться автоматически | MUST |
| ADR-H4 | 176–197 | Нормализация только при normal-packet technique; accept-only и GSO-safe планы без неё | MUST |
| ADR-H5 | 199–218 | PassiveRSTMode; default observe; никакое повышение до aggressive автоматически | MUST |
| H1 | 224–266 | Stage: reassembled-SNI runtime decision integration; invariant «один ClientHello → один Decision → один ActionToken»; parity-тесты | deliverable |
| H2 | 270–334 | OffloadMetadata из NFQA-атрибутов; Truncated → никогда не полный ClientHello; ChecksumNotReady ≠ invalid; capability-статусы | MUST |
| H3 | 338–371 | GSO observe (только diagnostic scope) / classify (тот же classifier API, без второго ClientHelloID) | MUST |
| H4 | 375–447 | GSOPassToken: bounded, keyed, deterministic, cleanup; first pass MUST NOT обучать/применять; secondary pass не повторяет evidence; token miss → fail-open | MUST |
| H4.1 (derived) | 423–440 | Queue transition: NF_QUEUE_NR или NF_REPEAT с общим allocator, loop detection; mark `0x08000000` запрещена | MUST |
| H5 | 450–496 | Топология очередей — транзакция: validate→reserve→start→prove→switch→drain→commit; rollback восстанавливает last-good | MUST |
| H5.1 (derived) | 480–490 | Требования H5: диапазоны очередей, iptables/nftables parity, IPv4/IPv6 matrix, no global flush, reconciliation | MUST |
| H6 | 500–574 | RST state в TCP FSM, bounded immutable; сигналы (SYN-ACK seen + нет payload + RST, burst, TTL mismatch, SEQ/ACK вне окна, option fingerprint); TTL baseline не из одного пакета | MUST |
| H6.1 (derived) | 551–568 | Baseline: robust center/spread, IPv4 TTL и IPv6 hop-limit отдельно; weak/stale/route-change не основание для drop | MUST |
| H7 | 578–653 | Signal classes strong/corroborating/diagnostic-only; conservative: strong+corroborating → suppress; aggressive — только explicit opt-in с gates | MUST |
| H7.1 (derived) | 633–647 | Safety gates: exact FlowKey, immutable config-gen, полная видимость (иначе observe), budgets, cleanup, легитимные RST проходят, unknown flow не трогается | MUST |
| H8 | 657–723 | Failure Inbox структура; Discovery MAY сравнивать пути, MUST NOT считать suppression успехом/auto-promote; rollback transactional, scope-limited | MUST |
| H9 | 727–833 | API/schema (defaults gso_mode=off, passive_rst.mode=observe; migration), UI (advanced для full/aggressive), метрики, trace-поля | MUST |
| H10 | 837–918 | Combined target validation: GSO-матрица, passive-RST матрица, combined сценарии; gate: no fake PASS, rollback proof, bounded CPU/RAM | gate |
| RST-04 (derived) | 924–940 | Representation contract: ActionPlan обязан объявить packet representation; запрет угадывания GSO-safety по названию | MUST |
| RST-05 (derived) | 942–952 | Mark contract: общий allocator, mask/owner, без конфликтов, очистка на terminal verdict/fail-open, startup reconciliation | MUST |
| RST-06 (derived) | 954–970 | Hold/replay: состояние для final verdict/mark cleanup; любой abort → release unchanged + cleanup | MUST |
| RST-07 (derived) | 972–981 | Backpressure: без новых токенов/hold, suppress unsafe action, accept/fail-open, не повышать RST mode | MUST |
| RST-08 (derived) | 983–989 | Privacy: GSO payload не экспортируется; issue bundle sanitized; token/flow IDs non-reversible | MUST |
| RG-04 (derived) | 995–1003 | Reassembled-SNI DoD: реальное влияние на set/action, parity, один ActionToken, fail-open, multi-client | gate |
| RG-05 (derived) | 1005–1018 | GSO DoD: metadata, off-поведение, classify на Keenetic, нормализация без double processing, `full` disabled | gate |
| RG-06 (derived) | 1020–1033 | Passive RST DoD: default observe, FSM-state, no suppression при неполной видимости, aggressive opt-in, rollback, не success proof | gate |
| RG-07 (derived) | 1035–1047 | Release gate: готово только после H1–H10; UI не заявляет production-ready до прохождения capability gate | gate |
| RG-08 (derived) | 1053–1074 | Последовательность H1→H10; stage без target-проверки → `BLOCKED_TARGET_VALIDATION`, не PASS | deliverable |

## 3. B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md (CSI)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| CSI-01 (derived) | 51–59 | Изоляция = ClientKey+FlowKey+domain evidence+ConfigGen+authorization; IP/порт/ASN/прошлый flow — не доказательство сервиса | MUST |
| CSI-02 (derived) | 74 | Симптом (Gmail/Feed поломан при YouTube set) рассматривать как cross-service, пока trace не докажет иное | MUST |
| CSI-03 (derived) | 184–197 | Цели: YouTube set не влияет на Gmail/Feed; разделение candidate и authorization; явный per-set DomainPolicy; negative controls Gmail/Feed; fail-open при ambiguity | MUST |
| CSI-04 (derived) | 199–213 | Не-цели: без Gmail-branches в packet core, без hard-code доменов, без расширения CIDR, без global QUIC off, без повторного Stage 1–36 | MUST |
| ADR-CSI-1 | 219–275 | CaptureCandidate ≠ ActionAuthorization; IP/CIDR/port → только candidate; clear/reassembled SNI → authorization; ActionPlan требует валидный auth той же FlowKey/SetID/ConfigGen | MUST |
| ADR-CSI-2 | 277–317 | DomainPolicy inherit/strict/scoped-hints/legacy/disabled; managed YouTube sets → scoped-hints; legacy виден как unsafe; compiler/Discovery не генерируют legacy; migration не подписывает молча | MUST |
| ADR-CSI-2.1 (derived) | 319–336 | Legacy safety validation: transactional apply отклоняет unsafe legacy (DomainOnly+IP fallback+mutation) с reason `unsafe_legacy_domain_scope`; UI предлагает миграцию с diff | MUST |
| ADR-CSI-3 | 338–380 | Positive/negative evidence: SNI подтверждает или отменяет (revoke) provisional candidate; ambiguity → no mutation, NF_ACCEPT; disposition eligible/contradicted/ambiguous/insufficient | MUST |
| ADR-CSI-4 | 382–421 | Reassembled SNI = authoritative evidence: единый matcher, отмена provisional candidates, привязка FlowKey/ClientHelloID/ConfigGen, без global IP learning, один decision/token; конфликт packet-local vs reassembled → fail-open + Failure Inbox | MUST |
| ADR-CSI-4.1 (derived) | 412–421 | H1 (RST/GSO) после CSI-4 — только verification/parity, не параллельный matcher path | MUST |
| ADR-CSI-5 | 423–448 | Incomplete evidence → нет ActionAuthorization: bounded hold при полной видимости, иначе NF_ACCEPT + observe-only; запрет mutation «на всякий случай» | MUST |
| ADR-CSI-6 | 454–497 | Legacy learned-IP не authoritative: только diagnostic/low-confidence provisional; запрет final auth/mutation/route/`*SetConfig`; TTL абсолютный, lookup не продлевает | MUST |
| ADR-CSI-7 | 499–558 | State имеет полный scope (ClientKey+IP+port+L4+SetID+DomainKey+ConfigGen): IPBlockDetect только при domain evidence+authorization, запрет `IP:443→blocked`; escalation scoped; RST state exact-FlowKey | MUST |
| ADR-CSI-7.1 (derived) | 558–572 | Failure Inbox: сигналы cross_service_scope_violation, revoked_by_sni, ambiguous и др.; событие не расширяет domain list | MUST |
| ADR-CSI-8 | 574–613 | QUIC action требует service authorization; `FilterQUIC=all` = все QUIC уже авторизованного set/flow, не «все пакеты к IP»; malformed/unknown → fail-open | MUST |
| ADR-CSI-9 | 615–646 | Routing/proxy side effects не destination-global для DomainOnly/shared-IP; только exact-flow/connmark, source+dest+bounded, per-client nftables, userspace handoff; binding хранит owner/scope/ConfigGen/provenance/timeout/txn; rollback удаляет owned bindings | MUST |
| CSI-1 | 652–678 | Stage: effective domain-policy schema + migration guard | deliverable |
| CSI-2 | 682–707 | Stage: CaptureCandidate/ActionAuthorization split; static IP не создаёт action | deliverable |
| CSI-3 | 711–738 | Stage: reassembled-SNI authoritative integration | deliverable |
| CSI-4 | 742–767 | Stage: negative evidence и revocation (YouTube IP + Gmail SNI → no action) | deliverable |
| CSI-5 | 770–795 | Stage: удаление authoritative legacy learned-IP path | deliverable |
| CSI-6 | 798–825 | Stage: scope IPBlockDetect/escalation/RST bookkeeping | deliverable |
| CSI-7 | 829–856 | Stage: domain-authorized QUIC gating | deliverable |
| CSI-8 | 859–886 | Stage: scoped routing/proxy side effects | deliverable |
| CSI-9 | 889–939 | Stage: trace candidate→authorization lifecycle, метрики, `unrelated_control_action_total` = 0, UI | deliverable |
| CSI-10 | 943–1060 | Stage: Gmail/Google negative-control validation; baseline A / candidate B / concurrent C / contamination D; hard gates (никакой YouTube-эффект на unrelated flow); автоматический rollback при failure | gate |
| CSI-10.1 (derived) | 996–1004 | Actual-domain capture rule: фиксировать реальные DNS/SNI/QUIC домены, не hard-code; не добавлять unrelated домены в профиль | MUST |
| CSI-11 (derived) | 1066–1090 | Classifier invariants: shared IP ≠ service; same client ≠ same service; candidate ≠ authorization; SNI revokes; ambiguity → no destructive mutation; один first flight → один decision/token | MUST |
| CSI-12 (derived) | 1092–1112 | State invariants: без long-lived `*SetConfig`, без destination-only cache/route, lookup не продлевает validity, ConfigGen revalidate/removes | MUST |
| CSI-13 (derived) | 1114–1134 | Fail-open invariants: incomplete/conflict/unknown/ambiguity/pressure → no action, NF_ACCEPT, structured trace | MUST |
| CSI-14 (derived) | 1140–1151 | RST/GSO addendum начинается только после CSI-1…CSI-10 или доказанной эквивалентности | MUST |
| CSI-15 (derived) | 1153–1178 | GSOPassToken (последующий) обязан нести Authorization+EffectivePolicy+Disposition; secondary worker не перевыбирает set по IP, не игнорирует negative evidence | MUST |
| CSI-16 (derived) | 1180–1188 | Passive RST integration: exact FlowKey, унаследованный authorized scope, не подавлять RST unrelated flow, scoped rollback по cohorts | MUST |
| CSI-17 (derived) | 1194–1212 | Functional DoD: 15 пунктов (effective policy, legacy guard, candidate≠auth, reassembled SNI, revocation, ambiguity, scoped state, QUIC auth, routing scope, trace, negative controls, rollback) | gate |
| CSI-18 (derived) | 1214–1232 | Acceptance DoD: YouTube usable + Gmail/Feed usable + `unrelated_control_action_total == 0`; не закрывать «визуально работает» | gate |
| CSI-19 (derived) | 1234–1242 | Resource DoD: bounded entries, без goroutine per packet, без global lock, deterministic cleanup, budget CPU/RAM | gate |
| CSI-20 (derived) | 1248–1269 | Deliverables на каждый CSI-* stage + итоговые документы | deliverable |
| CSI-21 (derived) | 1271–1284 | Запрещённые shortcuts: не удалять IP ranges вслепую, не allowlist Gmail, не отключать QUIC/IPBlockDetect глобально, не расширять домены, не broad ACCEPT | MUST |

## 4. B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md (SPF)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| SPF-01 (derived) | 8 | Главный принцип: одиночный timeout/stall/retry никогда не достаточен для авто-fallback | MUST |
| SPF-02 (derived) | 17–55 | Verdict: запрет `rkn_block_confirmed` без differential proof; допустимые формулировки suspected/correlated/differentially_confirmed | MUST |
| SPF-03 (derived) | 71–93 | Порядок реализации: CSI → WARP → RST/GSO → PPE → SPF-1…SPF-10 → Field Test/Profiles/Validation → promotion | MUST |
| SPF-04 (derived) | 113–124 | z2k reference зафиксирован (commit 8cffe4e2); blind port Lua/shell state machine запрещён | MUST |
| SPF-05 (derived) | 132–139 | Полезные уроки z2k: retry gap ≥5s, retry window, несколько attempts, свежий QUIC success подавляет TCP retry, state привязан к scope, отдельный flag | MAY |
| SPF-06 (derived) | 143–170 | Negative requirements из z2k: не вращать по двум ClientHello, не один threshold, не host-wide rotation, не «РКН подтверждён» по эвристике, stale retry expire | MUST |
| SPF-07 (derived) | 180–199 | Цели: unique-range progress, классы failure, positive+suppressing evidence, parallel success учёт, bounded differential probe, точный scope recovery, auto-rollback, observe default, fail-open, минимум ложных срабатываний | MUST |
| SPF-08 (derived) | 201–222 | Не-цели: не гарантировать идентификацию оборудования, не лечить origin/DNS/PMTU через rotation, не мигрировать established flow, не инжектировать RST по умолчанию, не destination-global, не включать WARP глобально | MUST |
| SPF-09 (derived) | 263–267 | Silent Path Failure — inference, не факт DPI | MAY |
| SPF-10 (derived) | 271–295 | Useful Progress = unique byte range/milestone; не считаются duplicate/retransmit/pure ACK/keepalive/локальный counter | MUST |
| SPF-11 (derived) | 299–316 | Suppressing Evidence: fresh same-scope/QUIC success, явные ошибки, backgrounded, grace, preconnect, resource pressure, visibility gaps | MUST |
| SPF-12 (derived) | 318–327 | Differential Proof: current fails + candidate reaches milestone + controls healthy + повторяемость в bounded window | MUST |
| SPF-13 (derived) | 329–331, 400 | Recovery Lease — временное разрешение exact scope; DestinationIP MAY diagnostic, но MUST NOT быть единственным key | MUST |
| SPF-14 (derived) | 469–471 | ProgressObserver принимает только immutable события, не выбирает strategy | MUST |
| SPF-15 (derived) | 473–484 | UniqueRangeTracker: TCP sequence arithmetic; duplicate/retransmit не увеличивают progress; overlap детерминирован; wrap тестируется; GSO/MSS одинаковые totals; bounded; cleanup | MUST |
| SPF-16 (derived) | 486–504 | ProtocolMilestoneTracker: milestones syn/syn_ack/ClientHello/ServerHello/app-data/fin/rst/tls_alert; packet core не расшифровывает payload | MAY |
| SPF-17 (derived) | 506–523 | VisibilityGate: active decision только при complete incoming+outgoing, healthy queue, proven GSO parity и offload; иначе mode=observe | MUST |
| SPF-18 (derived) | 525–539 | SuppressionEvidenceCollector работает до classifier action | MUST |
| SPF-19 (derived) | 541–574 | BaselineModel: bounded/explainable; запрет обучения на unvalidated recovery, смешивания Wi-Fi/WAN, unbounded history, baseline как единственное positive evidence | MUST |
| SPF-20 (derived) | 576–587 | RetryCorrelator: повторный ClientHello учитывается только при exact scope + нет успеха + gap в [min,window] + не parallel/preconnect + нет fresh success | MUST |
| SPF-21 (derived) | 589–602 | DifferentialProbeController: probe после suspicion и budget; exact component, сохранение DNS/IP-family, control probe, budgets, cleanup, causal report | MUST |
| SPF-22 (derived) | 604–617 | RecoveryPlanner не создаёт action из destination IP; только разрешённые binding: next validated/last-good/base WARP/proxy-TUN/fail-open/scoped fail-closed | MUST |
| SPF-23 (derived) | 619–635 | RollbackMonitor срабатывает при: candidate не достиг milestone, control regression, reconnect spike, latency/goodput, cross-service, DNS leak, recursion, budget, visibility loss, user disable, ConfigGen change | MUST |
| SPF-24 (derived) | 641–680 | State machine OBSERVING→SUSPECTED→CORRELATED→CORROBORATING→DIFFERENTIALLY_CONFIRMED→RECOVERY_CANDIDATE→RECOVERY_ACTIVE→PROMOTABLE→PROMOTED; failure paths SUPPRESSED/ROLLED_BACK/OBSERVE_ONLY/COOLDOWN/EXPIRED | MUST |
| SPF-25 (derived) | 696–707 | suspicion: один signal family → только trace/metrics/Inbox | MUST |
| SPF-26 (derived) | 709–725 | correlated: две независимые families → recommendation и differential probe; auto fallback запрещён | MUST |
| SPF-27 (derived) | 727–736 | differential: current fails + candidate succeeds + controls pass + no suppressors → временный scoped lease при policy opt-in | MUST |
| SPF-28 (derived) | 738–742 | recurrent-validated: только он MAY промоутиться как automatic policy для cohort | MAY |
| SPF-29 (derived) | 744–758 | Независимость evidence families; два таймера/счётчика одной причины не независимы | MUST |
| SPF-30 (derived) | 764–770 | Главный safety invariant: `single_signal_auto_fallback == forbidden` | MUST |
| SPF-31 (derived) | 772–788 | Suppression gate: flow моложе minimum_grace (floor ≥5s) → recovery запрещён | MUST |
| SPF-32 (derived) | 790–796 | Suppression: fast parallel/prefetch pattern → `likely_parallel_or_prefetch` | MUST |
| SPF-33 (derived) | 798–816 | Suppression: fresh same-scope success и compatible-protocol (QUIC) success; outgoing Initial не считается; bypass TTL bounded | MUST |
| SPF-34 (derived) | 818–828 | Suppression: явный server/application response (FIN/RST/TLS Alert/HTTP) — не silent failure | MUST |
| SPF-35 (derived) | 830–840 | Suppression: device/app lifecycle (background/Doze/network switch/cancel); без маркеров — conservative | MUST |
| SPF-36 (derived) | 842–852 | Suppression: visibility degradation (PPE/NFQUEUE/truncation/GSO parity) → active action запрещён | MUST |
| SPF-37 (derived) | 854–863 | Suppression: resource pressure (CPU/memory/queue/probe budget) | MUST |
| SPF-38 (derived) | 865–867 | Suppression: без final ActionAuthorization recovery запрещён | MUST |
| SPF-39 (derived) | 869–871 | Suppression: control failure (unrelated flow деградирует) → общий WAN/router outage | MUST |
| SPF-40 (derived) | 873–892 | Quarantine-before-action: после CORRELATED wait 2–10s, собрать parallel/control, затем probe; не блокирует трафик | MUST |
| SPF-41 (derived) | 894–919 | Per-service adaptive thresholds: static threshold только observe cold-start; active mode требует validated baseline или profile milestone | MUST |
| SPF-42 (derived) | 921–941 | Conservative defaults: mode=observe, minimum_grace 5s, retry_window 120s, 2 families, differential for auto, complete visibility, control probe, success_bypass 30s, max_attempts 2, cooldown 120s, lease_ttl 300s, fail_open | MUST |
| SPF-43 (derived) | 943–961 | False-positive budget: max_rollbacks/hour 2, control regressions 0, user reverts/day 1; breach → observe + promotion revoked | MUST |
| SPF-44 (derived) | 963–978 | User feedback «ложное срабатывание»: rollback exact lease, negative outcome, counter, без hardcoded exception, trace IDs | MUST |
| SPF-45 (derived) | 984–1073 | Detection contracts: handshake silence (24), after-ServerHello (25, без вывода по отсутствию decrypted HTTP), early-body (26, byte threshold — diagnostic), midstream stall (27, idle исключён), throughput collapse (28, не сам по себе), transport path (29, TUN exists ≠ health) | MUST |
| SPF-46 (derived) | 1078–1092 | Scope invariant: ClientKey+SetID+ComponentID+DomainKey+ConfigGen+IP family+TransportPath; lease для будущих eligible flows, не destination IP | MUST |
| SPF-47 (derived) | 1094–1105 | Authorization: active recovery требует ActionAuthorization + profile capability + prevalidated binding + exact ConfigGen; detector не создаёт identity | MUST |
| SPF-48 (derived) | 1107–1121 | Recovery order: retry same generation → next direct → last-good → base WARP (если разрешён) → proxy/TUN → fail-open → scoped fail-closed; не arbitrary strategy | MUST |
| SPF-49 (derived) | 1123–1133 | Existing flows не мигрируются; lease для retry/new flow/probe; controlled RST для retry запрещён по умолчанию | MUST |
| SPF-50 (derived) | 1135–1161 | Lease rules: bounded TTL/attempts, immutable candidate gen, известный rollback target, monitor, no recursive lease; direct→WARP допустим, WARP→WARP запрещён | MUST |
| SPF-51 (derived) | 1163–1196 | WARP interaction: direct failure → temporary base-WARP lease при здоровом L4+profile+leak policy+probe; WARP failure → last-good/alternate/fail-closed; detector не включает `require_non_ru` сам | MUST |
| SPF-52 (derived) | 1201–1257 | Config schema: секции evidence/visibility/timing/recovery/safety; per-profile upper bounds; profile не может ослабить global safety gates | MUST |
| SPF-53 (derived) | 1259–1338 | API: capabilities/status/assessments/recovery endpoints; assessment показывает scope/confidence/evidence/suppressors/differential; mutations с Idempotency-Key + request ID + scope | MUST |
| SPF-54 (derived) | 1340–1370 | Events (suspicion→rollback→revoke) без secrets/plaintext; псевдонимные ID, ConfigGen, binding, reason | MUST |
| SPF-55 (derived) | 1372–1410 | UI: beginner карточка без «РКН заблокировал сайт» без differential evidence; expert показывает evidence/suppressor таблицы | MUST |
| SPF-56 (derived) | 1416–1432 | Metrics без raw hostname/MAC/token | MUST |
| SPF-57 (derived) | 1434–1461 | Hard gates: 21 счётчиков = 0 (action без auth, incomplete visibility, destination-only, cross-client/service/component/generation, single-signal fallback, suppressor ignored, GSO/MSS mismatch, recursion, budget…); ненулевое блокирует promotion | gate |
| SPF-58 (derived) | 1463–1474 | Invariants: observe не меняет verdict/route; recommend не ставит lease; suspicion не auto-recovers; lease не переживает ConfigGen; visibility loss revokes auto mode | MUST |
| SPF-59 (derived) | 1478–1652 | Тесты: unit (unique progress, independence, suppressors, scope), fuzz, packet-path fixtures (HLS/prefetch/parallel/blackhole…), differential, same-client negative controls (Gmail/Google, `unrelated_control_action_total==0`), fault injection, performance ceilings (max_tracked_flows 4096 и др.) | gate |
| SPF-60 | 1658–1685 | SPF-1: taxonomy, threat model, reference freeze | deliverable |
| SPF-61 | 1687–1713 | SPF-2: unique TCP progress accounting, GSO/MSS parity | deliverable |
| SPF-62 | 1715–1741 | SPF-3: protocol milestones + visibility gate | deliverable |
| SPF-63 | 1743–1773 | SPF-4: suppression evidence и false-positive controls | deliverable |
| SPF-64 | 1775–1804 | SPF-5: classifier, confidence ladder, adaptive baselines, quarantine | deliverable |
| SPF-65 | 1806–1836 | SPF-6: differential shadow validation | deliverable |
| SPF-66 | 1838–1869 | SPF-7: scoped recovery planner и leases | deliverable |
| SPF-67 | 1871–1901 | SPF-8: rollback, FP budget, Failure Inbox | deliverable |
| SPF-68 | 1903–1932 | SPF-9: API/UI/Profiles/observability | deliverable |
| SPF-69 | 1934–1971 | SPF-10: router/Android/fault-injection/release gate; verdicts silent-observe/recommend/auto-canary-ready | deliverable |
| SPF-70 (derived) | 1977–2015 | Mode gates: observe-ready (SPF-1…5), recommend-ready (+SPF-6, без авто-lease), auto-canary-ready (SPF-1…10 + все hard gates zero), cohort promoted (recurrent proof, budget intact) | gate |
| SPF-71 (derived) | 2017–2029 | Automatic demotion в observe: WAN fingerprint change, engine/config change, visibility change, profile update, budget breach, repeated rollback, user report, control regression | MUST |
| SPF-72 (derived) | 2035–2073 | Синхронизация: Field Test suites после SPF-10; Profiles per-component policy; umbrella validation регистрирует SPF-1…10; CSI не нуждается в редакции | deliverable |
| SPF-73 (derived) | 2079–2100 | DoD (20 пунктов): observe не меняет runtime, GSO/MSS parity, active невозможен без видимости, suppressors до recovery, no destination-only state, controls чисты, WARP не рекурсивен, все hard gates = 0 | gate |
| SPF-74 (derived) | 2181–2203 | Agent execution contract: per-stage implement→tests→report→gates→commit→push; без target доступа → `IMPLEMENTED_NOT_TARGET_VALIDATED`, не PASS | MUST |

---

## Сводка

- PPE: 49 требований (инварианты, конфиг, capability, rule model, lifecycle, self-test, safety gate, API/UI/obs, 8 этапов, acceptance gate)
- RST/GSO: 34 требования (ADR-H1…H5, этапы H1…H10, mark/representation/backpressure/privacy, DoD-гейты)
- CSI: 32 требования (ADR-CSI-1…9, этапы CSI-1…10, инварианты, RST/GSO compatibility, DoD)
- SPF: 74 требования (термины, runtime-компоненты, confidence ladder, 10 suppression gates, recovery/scope, API/UI, hard gates, этапы SPF-1…10, promotion)
- Итого: 189 требований; явные ID: PPE-1…8, PR PPE-A…F, ADR-H1…H5, H1…H10, ADR-CSI-1…9, CSI-1…10, SPF-1…10; остальные — (derived)
