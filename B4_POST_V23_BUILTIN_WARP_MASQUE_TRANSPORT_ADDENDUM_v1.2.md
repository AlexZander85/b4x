# B4 Post-v2.3 Built-in WARP/MASQUE Transport Addendum

**Версия:** 1.2  
**Дата:** 2026-07-30  
**Статус:** обязательный post-v2.3 companion addendum для встроенного transport subsystem  
**База:** завершённые `B4_FORK_PATCH_PLAN.md` Stage 1–36 и `B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md`  
**Область:** встроенный Cloudflare WARP/MASQUE transport, `usque`-derived data plane, Keenetic/NDM lifecycle, scoped policy routing, transactional apply, health/self-heal, специальный WARP Transport Camouflage на основе ограниченных B4 strategy primitives и optional experimental nested WARP с hard gate `observed country != RU`  
**Пользовательская установка дополнительных пакетов:** запрещена; всё необходимое поставляется, обновляется и удаляется вместе с B4  
**Изменения v1.2:** добавлен нормативный causal transport tracing contract для base WARP, `WARP+WARP` и experimental `НЕ РФ`: generation-aware `TransportTraceEnvelope`, parent/child dependency graph, route/path proof с counter deltas, подробный MASQUE/CONNECT-IP lifecycle, geo quorum и route-gate events, DNS/IPv6 path proof, Android forwarded-flow correlation, resource ownership/cleanup proof, layer-specific performance attribution, trace completeness hard gates и validation-of-observability.  
**Изменения v1.1:** добавлен нормативный `WARP Transport Camouflage`: отдельная авторизация control flow, cover-SNI, handshake-only strategy adapter, CONNECT-IP cutoff, auto-selection, outer/inner isolation, bounded Passive RST defense, stages `WARP-C1`–`WARP-C10` и соответствующие hard gates  

---

## 0. Нормативный статус и место в проекте

Этот addendum добавляет в B4 generic transport capability:

```text
cloudflare-warp-masque
```

Transport не является DPI technique и не подменяет packet strategies.

Нормативное разделение:

```text
direct-strategy
→ B4 изменяет форму/порядок/содержимое выбранного packet path

cloudflare-warp-masque
→ B4 направляет уже авторизованный scoped traffic в альтернативный L3 path
```

Этот addendum:

- не переоткрывает Stage 1–36;
- не переоткрывает завершённый PPE addendum;
- не превращает WARP в глобальный default route;
- не требует установки `usque`, `usque-keenetic` или другой библиотеки пользователем;
- вводит companion stages `WARP-1`–`WARP-12` и `WARP-C1`–`WARP-C10`;
- требует commit, validation report и push после каждого stage;
- запрещает production promotion до target-side router и Android validation;
- считает optional `НЕ РФ` отдельным experimental capability, а не свойством базового WARP transport;
- запрещает применять к MASQUE control flow обычную service strategy без точной `TransportControlAuthorization`;
- разрешает только специализированный bounded camouflage до подтверждённого CONNECT-IP, после чего established data plane получает обязательный bypass.

### 0.1. Обязательный порядок реализации

```text
B4_FORK_ARCHITECTURE.md v2.4
→ завершённый B4_FORK_PATCH_PLAN.md Stage 1–36
→ завершённый B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md (CSI-1…CSI-10)
→ этот addendum:
   WARP-1…WARP-8
   → WARP-C1…WARP-C6
   → WARP-9…WARP-10
   → WARP-C7…WARP-C10
   → WARP-11…WARP-12
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_FIELD_TEST_AUTOMATION_ADDENDUM
→ B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM
→ B4_IMPLEMENTATION_VALIDATION_ADDENDUM
→ production promotion
```

CSI выполняется до WARP, потому что transport binding должен получать уже корректный:

```text
ClientKey
+ FlowKey
+ SetID
+ domain/service evidence
+ ConfigGen
+ ActionAuthorization
```

Destination IP, CIDR, ASN, порт `443`, прежний flow или shared CDN address не дают автоматического разрешения отправлять новый flow в WARP.

### 0.2. Приоритет требований

```text
B4_FORK_ARCHITECTURE.md v2.4
→ Cross-Service Isolation Addendum для authorization/scope
→ этот addendum для WARP/MASQUE, bounded transport camouflage и nested non-RU transport
→ RST/GSO Addendum для direct packet execution
→ Field Test / Service Profiles / Implementation Validation как consumers и gates
→ read-only reference repositories
```

---

# Часть I. Reference design и границы заимствования

## 1. Закреплённые read-only references

Агент MUST использовать следующие references только после проверки commit SHA.

### 1.1. z2k WARP implementation

```text
repository: necronicle/z2k
reference commit: e4e978dd9a2d9f7ec164654c695bf6e30142b83d
primary files:
- files/init.d/S51z2k-warp
- files/z2k-warp.sh
- tests/test_warp_init.sh
- tests/test_warp_live_why.sh
- tests/test_warp_addr_and_setup.sh
```

Из z2k берутся проверенные field lessons:

- lifecycle принадлежит продукту, а не стороннему init script;
- supervisor PID проверяется через ownership/`kill(0)`, а не name matching;
- имя TUN выбирается один раз и сохраняется;
- чужой `opkgtunN` никогда не усыновляется без доказанного ownership;
- NDM настраивается только после появления kernel netdev;
- assigned WARP address читается из session config;
- MTU `1280` применяется до первого payload packet;
- `TUN exists` и `address exists` не являются liveness proof;
- liveness проверяется реальным HTTPS request через interface;
- sleeping/idle session не объявляется dead после одной короткой пробы;
- endpoint variants не переписывают primary session config;
- endpoint rotation запускается только при соответствующем failure class;
- failed variant имеет TTL и автоматически снимается;
- routing активируется только при доказанном usable path;
- sustained failure снимает route и сохраняет recovery loop;
- destination lists загружаются через temporary set и atomic swap;
- NAT/MSS ownership проверяется, double NAT запрещён;
- control endpoint исключается из generic DPI mutation и рекурсивного routing; dedicated camouflage допускается только по exact transport authorization;
- self-heal ограничен cooldown и failure budgets;
- diagnostics должны называть конкретный failed layer.

### 1.2. Upstream usque

```text
repository: Diniboy1123/usque
reference commit: 6aa03fc97d12848dce34eedbd187fb1077b5d1ea
license: MIT
```

Из upstream берутся:

- Cloudflare WARP MASQUE / Connect-IP data-plane implementation;
- native TUN mode;
- HTTP/2 over TCP+TLS support;
- HTTP/3 over QUIC support как optional capability;
- endpoint public-key pinning;
- device registration/enrollment schema;
- `MaintainTunnel` reconnect model;
- connect/disconnect lifecycle events;
- assigned IPv4/IPv6 fields;
- protocol-level status code validation;
- packet pump semantics;
- default official MASQUE SNI;
- fixed default MTU `1280` warning semantics;
- architecture cross-build inputs.

Upstream `usque` MUST NOT использоваться как плавающая runtime dependency.

### 1.3. usque-keenetic

```text
repository: side-effect-tm/usque-keenetic
reference commit: 8071a4d98525bcf5ae46a4a431aa25356eb87b3b
reference package version: 0.3.0
bundled upstream version in that commit: 4.2.0
```

Из `usque-keenetic` берутся как reference:

- Entware/Keenetic architecture mapping;
- NDM interface naming conventions;
- `ip global auto` integration;
- `ip tcp adjust-mss pmtu` integration;
- NDM MTU and `/32` address setup;
- opkg packaging layout lessons;
- HTTP/2 configuration exposure;
- cleanup/uninstall expectations.

Следующие behaviours `usque-keenetic` MUST NOT переноситься буквально:

- поиск interface как `max(opkgtunN)+1` без ownership registry;
- автоматическое придумывание адреса `172.16.1.100–200` вместо assigned WARP IP;
- настройка NDM до доказанного появления TUN;
- `CONFIG_FILE.run` как неограниченный override source;
- PID ownership через `pgrep` comparison;
- stop, который отказывается чистить state, если daemon уже умер;
- отсутствие end-to-end liveness gate;
- отдельная пользовательская установка пакета;
- runtime download неподписанного latest binary.

### 1.4. z2k camouflage baseline и граница улучшения B4

Актуальный z2k использует две разные политики:

```text
enrollment к api.cloudflareclient.com
→ может использовать общий zapret2/desync bypass path

рабочий MASQUE control connection
→ custom outer SNI
→ endpoint помещается в nozapret
→ generic zapret2 packet mutation не применяется
```

Такое решение безопаснее, чем безусловно применять generic desync к долгоживущему transport flow. Оно предотвращает самоповреждение туннеля, но оставляет только SNI-level маскировку и не умеет автоматически подобрать минимальную рабочую B4 strategy.

B4 v1.1 сохраняет исходный safety invariant z2k:

```text
никакая обычная service strategy
не может захватить MASQUE control flow
```

и добавляет отдельный более строгий capability:

```text
exact TransportControlAuthorization
→ dedicated camouflage queue/path
→ handshake-only bounded strategy
→ protocol-confirmed cutoff
→ established-flow bypass
```

Цель capability:

- обойти DPI-блокировку enrollment или MASQUE handshake;
- уменьшить очевидность стандартного WARP SNI/ClientHello pattern;
- выбрать минимально агрессивный рабочий вариант;
- не изменять зашифрованный established MASQUE data plane;
- не обещать полную невидимость от статистического/поведенческого DPI.

## 2. Reference freeze и upgrade policy

Каждый reference update MUST быть отдельным reviewed change.

```yaml
warp_engine_reference:
  upstream_repo: Diniboy1123/usque
  upstream_commit: 6aa03fc97d12848dce34eedbd187fb1077b5d1ea
  source_tree_hash: <generated>
  local_patch_series_hash: <generated>
  resulting_binary_hashes:
    mipsle: <generated>
    mips: <generated>
    arm64: <generated>
    amd64: <generated>
```

Запрещено:

- `go get ...@latest` в release pipeline;
- runtime `curl` GitHub latest release;
- автоматический переход на новый upstream commit;
- замена engine без SBOM и validation report;
- скрытый update independent от B4 update channel;
- загрузка бинарника по URL без signature/hash verification.

---

# Часть II. Product contract

## 3. Два независимых пользовательских режима

### 3.1. Основной режим: надёжный WARP/MASQUE transport

UI label:

```text
WARP-туннель (MASQUE TCP 443)
```

Назначение:

- обход IP-level блокировок;
- альтернативная маршрутизация;
- доступ к выбранным IP/CIDR/service sets;
- работа через TCP `443`, когда UDP WARP/WireGuard/QUIC недоступны;
- per-device/per-service split tunnel;
- fail-open или scoped fail-closed policy;
- не гарантирует конкретную страну выхода.

Default:

```yaml
warp:
  enabled: false
  protocol: masque-h2
  port: 443
  mode: scoped
  require_non_ru: false
```

### 3.2. Отдельная experimental option: `НЕ РФ`

UI checkbox:

```text
Требовать выход не из РФ (экспериментально)
```

Семантика:

```text
checkbox off
→ используется один production WARP/MASQUE tunnel
→ country не является gate

checkbox on
→ запускается bounded nested WARP discovery
→ selected traffic активируется только при fresh geo attestation country != RU
→ RU / unknown / conflicting / stale result не разрешает route
```

Эта option не обещает, что Cloudflare всегда выдаст non-RU egress.

Она обещает другой, более строгий инвариант:

```text
B4 не активирует experimental route,
пока собственная fresh multi-provider проверка
не подтверждает observed IPv4 egress != RU.
```

Если non-RU egress не найден, availability может отсутствовать.

### 3.3. Нельзя смешивать названия

Запрещены UI labels:

```text
Выбрать страну WARP
WARP Germany
Гарантированная Польша
Location lock
```

Допустимы:

```text
Observed exit: NL
Requirement: not RU
Attestation age: 37s
Availability: experimental
```

### 3.4. Геолокационная гарантия ограничена evidence

Даже при generic geo attestation отдельный сервис MAY иметь другую IP geolocation database или блокировать Cloudflare/VPN ranges.

Поэтому B4 MUST различать:

```text
generic_non_ru_attested
service_geo_probe_passed
```

Service Profile MAY требовать оба условия.

### 3.5. WARP Transport Camouflage — отдельная transport policy

Camouflage не является свойством пользовательского tunneled traffic и не использует обычный Service Profile decision path.

```text
Service ActionAuthorization
→ разрешает направить пользовательский flow в WARP

TransportControlAuthorization
→ разрешает ограниченную обработку внешнего WARP control flow
```

UI режимы:

```text
DPI-совместимость WARP:
- off
- SNI cover only
- auto (recommended)
- custom validated policy (advanced)
```

`auto` MUST начинать с наименее агрессивного candidate и повышать уровень только после доказанного failure текущего candidate.

Название `невидимый`, `stealth`, `анонимный` или аналогичное запрещено. Допустимая формулировка:

```text
Защита подключения WARP от DPI
```

B4 не может скрыть от провайдера сам факт долгоживущего TCP/443 flow к Cloudflare address space, его объём и timing characteristics.

---

# Часть III. Встроенная поставка, а не отдельная библиотека

## 4. ADR-WARP-1 — B4 поставляет engine как first-party bundled component

Пользователь устанавливает только B4.

Рекомендуемый layout:

```text
/usr/sbin/b4
/usr/libexec/b4/b4-warpd
/usr/share/b4/warp/engine-manifest.json
/usr/share/licenses/b4/usque-MIT.txt
/opt/etc/b4/secrets/warp/
/opt/var/lib/b4/warp/
/opt/var/run/b4/warp/
```

В source tree:

```text
third_party/usque/
third_party/usque/PINNED_COMMIT
third_party/usque/LICENSE.md
third_party/usque/patches/
src/transport/warp/
cmd/b4-warpd/
```

`b4-warpd`:

- собирается B4 CI из pinned source;
- получает B4 version metadata;
- распространяется внутри B4 package;
- не регистрируется как отдельный opkg dependency;
- не имеет отдельного user-facing update channel;
- удаляется вместе с B4;
- не принимает unrestricted config от shell/environment;
- запускается только B4 supervisor;
- не является публичной system service для сторонних клиентов.

## 5. Почему отдельный внутренний process лучше in-process library

Требование «встроен в B4» не означает, что весь MASQUE code должен работать внутри основного daemon address space.

Нормативная модель:

```text
b4 main daemon
→ policy, config, secrets authorization, routes, marks, API, UI, rollback

b4-warpd
→ MASQUE protocol, TUN packet pumps, structured lifecycle events
```

Преимущества:

- panic/crash data plane не убивает B4 control plane;
- resource limits применяются отдельно;
- process can be restarted transactionally;
- upstream source можно обновлять изолированно;
- no unstable Go package API leaks into core;
- secrets передаются минимально;
- B4 остаётся единственным product owner.

Пользователь не видит и не устанавливает helper отдельно.

## 6. ADR-WARP-2 — IPC вместо log parsing

Основной lifecycle API MUST быть structured.

Unix socket:

```text
/opt/var/run/b4/warp/control.sock
```

Пример event:

```json
{
  "schema": 1,
  "instance_id": "warp-base-1",
  "generation": 42,
  "event": "masque_connected",
  "endpoint": "162.159.198.2:443",
  "protocol": "h2",
  "tun_ifname": "b4warp0",
  "assigned_ipv4": "172.16.0.2",
  "monotonic_ns": 1234567890
}
```

Required events:

```text
process_started
tun_created
tun_ready
masque_connecting
masque_connected
masque_rejected
packet_pumps_started
packet_pump_failed
masque_disconnected
reconnect_scheduled
process_stopping
process_stopped
fatal_config_error
```

Log parsing MAY использоваться только как secondary diagnostics.

## 7. ADR-WARP-3 — upstream hooks не являются policy engine

Upstream connect/disconnect hooks полезны как lifecycle signal, но B4 MUST NOT запускать user-provided shell hooks.

Требования:

- hook path fixed at build/runtime owner boundary;
- preferred path — direct IPC from patched engine;
- no shell command strings;
- no inherited arbitrary environment;
- no PATH-based executable lookup;
- hook timeout and process count bounded;
- route changes выполняет только B4 RouteManager.

---

# Часть IV. Security, enrollment и secrets

## 8. Secret model

Sensitive fields:

```text
private_key
license
access_token
registration backup
optional WARP+ license supplied by user
```

Storage requirements:

```text
owner: root/B4 service account
mode: 0600 files, 0700 directories
encrypted at rest when platform key is available
never in config export
never in issue bundle
never in trace payload
never in UI DOM
never in logs
```

Config redaction test MUST fail build if a sensitive JSON field reaches report artifacts.

## 9. Enrollment

Enrollment is explicit and requires acceptance of Cloudflare terms.

```text
user enables WARP first time
→ UI displays third-party service notice
→ user accepts
→ B4 creates pending enrollment transaction
→ exact registration traffic receives bounded control-plane bypass
→ config is validated and atomically committed
```

B4 MUST NOT:

- ship shared account credentials;
- ship third-party registration proxy credentials;
- silently accept terms on behalf of user before consent;
- re-register on every failure;
- burn working identity without backup;
- automatically attach unknown WARP+ license;
- expose registration endpoint through an open proxy.

## 10. Enrollment path without external VPS

Base enrollment MAY use existing B4 DPI-bypass capability for the exact router-origin registration flow.

Normative scope:

```text
process = b4-warpd enrollment worker
+ destination = Cloudflare registration API
+ TCP 443
+ short TTL
+ exact ConfigGen
```

No broad router OUTPUT mutation is permitted.

If direct enrollment fails:

```text
retry under bounded B4 control-flow strategy matrix
→ preserve exact scope
→ no external proxy fallback bundled
→ final BLOCKED_ENROLLMENT if still unavailable
```

For experimental inner identity, enrollment MAY be attempted through verified base WARP, but only after base transport is live.

## 11. Re-enrollment

Re-enrollment is last resort.

```text
copy current secret generation to rollback slot
→ create candidate generation
→ validate required fields and key material
→ start candidate without changing active route
→ prove path
→ commit candidate OR restore previous generation
```

Cooldown:

```yaml
re_enroll:
  automatic: false
  minimum_interval: 24h
  max_retained_generations: 2
```

Automatic repeated registration for searching non-RU country is forbidden.

---

# Часть V. Base WARP transport architecture

## 12. ADR-WARP-4 — Base transport uses one native TUN

Base topology:

```text
selected LAN flow
→ B4 ActionAuthorization
→ transport binding mark
→ dedicated routing table
→ b4warp0
→ b4-warpd MASQUE Connect-IP
→ HTTP/2 over TCP+TLS 443
→ Cloudflare WARP
→ Internet
```

Default:

```text
outer protocol = HTTP/2
outer endpoint family = IPv4
outer TCP port = 443
inner tunnel family = IPv4
MTU = 1280
IPv6 = disabled until separately validated
```

HTTP/3 MAY be exposed later as capability, but must not replace HTTP/2 fallback automatically on networks where UDP is blocked.

## 13. TUN identity

B4 owns interface registry.

```go
type TunOwnership struct {
    TransportID string
    InstanceID  string
    IfName      string
    ConfigGen   uint64
    CreatedByB4 bool
    AssignedV4  netip.Addr
    AssignedV6  netip.Addr
}
```

Rules:

- deterministic preferred name `b4warp0`;
- fallback names allocated by B4 registry;
- recorded ownership survives restart;
- existing foreign TUN is never reconfigured;
- stale B4-owned interface MAY be reclaimed after proof;
- foreign `opkgtunN` is untouched;
- cleanup deletes only generation-owned objects.

## 14. Assigned address

Primary address MUST come from validated WARP session config.

```text
session assigned IPv4
→ validate unicast and expected format
→ check exact collision
→ apply /32
```

B4 MUST NOT silently invent a different address.

If assigned address collides:

```text
base transport = BLOCKED_ADDRESS_CONFLICT
```

A fallback invented address is not production-safe because Cloudflare may reject packets whose inner source was not assigned.

Experimental nested mode handles duplicate assigned addresses through namespace isolation, not address substitution.

## 15. NDM apply order

```text
start b4-warpd candidate
→ wait for exact owned TUN netdev
→ set MTU 1280 immediately
→ read and validate assigned address
→ configure NDM object
→ verify address/link/MTU by reading actual kernel state
→ verify NDM NAT/MSS capability
→ run route-bound liveness probe
→ stage PBR
→ canary
→ commit
```

NDM command exit code alone is insufficient; resulting state MUST be re-read.

If NDM refuses address:

- B4 MAY apply temporary `iproute2` fallback;
- fallback is marked non-persistent;
- no flash save marker is written;
- self-heal retries proper NDM ownership later;
- status exposes `ndm_degraded=true`;
- production profile promotion requires target validation.

## 16. MTU/MSS

HTTP/2 mode uses:

```text
TUN MTU = 1280
```

MTU MUST be applied before packet pumps become eligible for routed traffic.

MSS policy:

```text
NDM adjust-mss pmtu present and effective
→ B4 does not add duplicate clamp

NDM unavailable/ineffective
→ B4 installs one generation-owned TCPMSS clamp
```

No unconditional double clamp.

PMTU tests MUST include:

```text
1280 byte packet
1281 byte packet
1500 byte original LAN frame
TCP SYN MSS
large HTTPS response
UDP datagram near path MTU
ICMP fragmentation-needed handling where available
```

## 17. Endpoint and recursive routing protection

Base MASQUE control connection MUST stay outside its own TUN.

```text
base control socket
→ B4-assigned SO_MARK: warp-control-direct
→ dedicated rule to physical WAN/main table
→ excluded from NFQUEUE strategy execution
→ excluded from WARP data binding
```

Endpoint address-only bypass is insufficient because endpoint can rotate.

Control token:

```go
type TransportControlAuthorization struct {
    TransportID string
    InstanceID  string
    ConfigGen   uint64
    RouteClass  string // direct-wan | via-base-warp
    ExpiresAt   time.Time
}
```

## 18. Required bundled engine patch: socket routing policy

Upstream HTTP/2 path creates a plain `net.Dialer` and does not expose a first-class per-instance socket mark/bind-device contract.

B4 vendored patch MUST add:

```go
type DialPolicy struct {
    FwMark       uint32
    BindDevice   string
    SourceIPv4   netip.Addr
    SourceIPv6   netip.Addr
    DisableProxy bool
}
```

For Linux/Keenetic:

```text
net.Dialer.ControlContext
→ SO_MARK
→ optional SO_BINDTODEVICE
→ optional source address
```

Requirements:

- exact errors surfaced as structured events;
- no silent fallback to unmarked socket;
- environment proxy disabled by default;
- proxy use requires explicit B4-owned config;
- production forbids `insecure` endpoint mode;
- endpoint public-key pin remains mandatory;
- HTTP/3 path receives equivalent mark support before being declared supported.

## 19. Supervisor

B4 supervisor owns child process group.

Required properties:

```text
single start lock per instance
parent-death handling
exact PID/process-group ownership
bounded exponential backoff
stable-run backoff reset
stop kills process group and helper tasks
no orphan keepalive
no orphan setup job
no flash writes on respawn loop
```

Default reconnect:

```yaml
reconnect:
  always: true
  initial_delay: 1s
  minimum_delay: 5s
  maximum_delay: 30s
  reset_after_stable: 60s
```

## 20. Keepalive

Engine protocol keepalive MAY not keep an HTTP/2 session active in all implementations.

B4 therefore uses an application-level path keepalive:

```text
small HTTPS request
forced through exact TUN/route
IPv4 only by default
interval less than observed idle timeout
```

Defaults:

```yaml
keepalive:
  interval: 120s
  timeout: 5s
  endpoint: pinned numeric-IP HTTPS trace endpoint
```

ICMP ping alone is not accepted as keepalive proof.

---

# Часть VI. Scoped routing and authorization

## 21. ADR-WARP-5 — CaptureCandidate does not route traffic

Transport route is installed only for an authorized binding.

```text
CaptureCandidate
→ classify/reassemble/evaluate evidence
→ ActionAuthorization
→ TransportAuthorization
→ generation-owned route token
```

Required key:

```text
ClientKey
+ FlowKey or bounded destination scope
+ SetID
+ DomainHash when available
+ TransportID
+ ConfigGen
```

## 22. Static IP/CIDR lists

Explicit user-selected IP/CIDR lists MAY authorize transport routing without hostname evidence, because the user intentionally selected destination networks.

Guardrails:

- private, loopback, multicast, link-local and router management ranges rejected;
- default route prefixes `/0` rejected;
- broad prefixes below configured minimum require advanced override;
- IPv4 and IPv6 sets separate;
- provenance and list source retained;
- temporary set + atomic swap;
- preview diff and maximum entry count;
- rollback to last-good generation.

## 23. Domain/service routing

For domain-scoped profiles:

```text
clear SNI
OR reassembled SNI
OR fresh source-scoped DNS evidence allowed by scoped-hints
→ TransportAuthorization
```

Shared IP alone remains candidate-only.

Negative SNI MUST revoke provisional transport candidate before route state is promoted.

Destination-only persistent route for shared CDN IP is forbidden.

## 24. Mark allocation

No fixed `0x989` or other hard-coded mark.

MarkAllocator allocates non-overlapping masks for:

```text
warp-base-data
warp-base-control-direct
warp-nonru-data
warp-inner-control-via-base
warp-health-probe
warp-geo-probe
warp-fail-closed
```

Every rule uses masked write:

```text
--set-xmark value/mask
```

Never clobber unrelated Keenetic/B4 mark bits.

## 25. PREROUTING and OUTPUT

LAN data:

```text
PREROUTING only
```

Router-origin traffic:

```text
not routed through WARP by generic destination rule
```

Exceptions:

- B4-owned health probes;
- B4-owned enrollment flows;
- base/inner MASQUE control sockets;
- explicit advanced router-origin binding.

OUTPUT exceptions use socket marks, not broad destination iptables rules.

## 26. Transactional PBR

Apply sequence:

```text
compile candidate destination sets
→ allocate marks/tables/priorities
→ create candidate rules with generation tag
→ keep data rule inactive
→ prove TUN path
→ enable canary scope
→ observe
→ atomic promote
→ retire previous generation
```

Rollback removes only candidate generation.

Keenetic firewall reload/WAN flap reconciliation MUST reassert desired generation idempotently.

## 27. NAT

Exactly one effective NAT owner.

Detection:

```text
NDM global interface NAT present and functional
→ use NDM

NDM NAT absent or nonfunctional
→ install B4 generation-owned MASQUERADE/SNAT
```

Forwarded-flow validation MUST distinguish:

```text
router-origin interface-bound probe passes
but LAN client flow fails
```

This state is `DEGRADED_FORWARDING`, not `HEALTHY`.

---

# Часть VII. Health, self-heal and failure policy

## 28. State machine

```text
NOT_CONFIGURED
→ PROVISIONING
→ ENROLLMENT_REQUIRED
→ STARTING
→ TUN_CREATED
→ INTERFACE_CONFIGURED
→ MASQUE_CONNECTING
→ MASQUE_CONNECTED
→ ROUTER_PATH_VERIFIED
→ CANARY_ROUTING
→ FORWARDED_PATH_VERIFIED
→ ACTIVE
```

Failure states:

```text
DEGRADED
COOLDOWN
BLOCKED_ENROLLMENT
BLOCKED_ADDRESS_CONFLICT
BLOCKED_NDM
BLOCKED_PATH
FAILED
```

## 29. Layered liveness

### L0 — process

```text
owned supervisor alive
owned engine child alive
```

### L1 — interface

```text
owned TUN exists
link UP
assigned address present
MTU <= 1280
```

### L2 — protocol

```text
latest Connect-IP response status == 200
masque_connected event belongs to current ConfigGen
```

A generic log line like `Tunnel established` is not sufficient.

### L3 — router path

```text
HTTPS probe forced through exact route/TUN
response proves WARP active
public IP differs from direct WAN where observable
```

### L4 — forwarded path

```text
actual selected LAN client
→ scoped PBR
→ WARP
→ remote response
```

Production Profile `Healthy` requires L4.

Base transport MAY enter limited canary after L3 to obtain L4 evidence.

## 30. Retry semantics

Single probe failure does not immediately declare dead because first packet MAY wake/reconnect session.

```text
probe 1
→ short wait
→ probe 2
→ optional slower probe only in interactive enable path
```

Background probes remain cheap.

## 31. Failure streak

```yaml
health:
  fail_threshold: 3
  success_threshold: 2
  probe_interval: 60s
  route_remove_after: 3 failures
  restart_cooldown: 300s
```

## 32. Base failure policies

### fail-open

```text
WARP unavailable
→ remove scoped WARP route
→ direct path resumes
```

Default for ordinary IP-block bypass.

### fail-closed-scoped

```text
WARP unavailable
→ block only selected transport scope
→ unrelated traffic unaffected
```

No global kill switch by default.

## 33. Recovery ladder

```text
1. reassert interface/link/MTU
2. reassert endpoint control bypass
3. reassert current PBR generation
4. wait for wake-up and retry probe
5. restart owned engine under cooldown
6. classify endpoint failure
7. try bounded approved endpoint variant
8. clear failed variant after TTL
9. require explicit re-enrollment if identity suspected
10. remain fail-open or scoped fail-closed
```

Endpoint rotation is forbidden when current session is already protocol-connected and failure is clearly inside data path.

## 34. Endpoint variants

Primary secret config is immutable.

```text
primary session config
→ read-only

candidate endpoint variant
→ derived copy
→ validated required fields
→ generation/TTL
→ automatic clear on failure
```

Candidate catalog MUST be versioned and tested. Random Cloudflare IP scanning is forbidden.

---

# Часть VIII. Experimental nested `НЕ РФ`

## 35. ADR-WARP-6 — Optional non-RU mode is a second isolated WARP session

Conceptual topology:

```text
selected client traffic
→ inner WARP data path
→ inner MASQUE TCP 443 control connection
→ forced through verified base WARP path
→ Cloudflare network again
→ observed public egress
```

The checkbox does not replace base WARP.

It depends on it:

```text
base WARP ACTIVE
→ nested discovery eligible

base WARP not ACTIVE
→ nested disabled
```

## 36. Why isolation is mandatory

Two personal WARP sessions frequently receive identical or overlapping internal addresses.

B4 MUST NOT assign the same WARP address to two TUN interfaces in one routing namespace and hope policy routing resolves it.

Preferred backend:

```text
dual-netns-native-tun
```

Fallback backend:

```text
base-native-tun + inner-full-proxy adapter
```

Same-namespace dual-TUN backend is forbidden unless a dedicated validation proves no address/local-route ambiguity.

## 37. Backend A — dual network namespace native TUN

Precondition:

```text
kernel network namespaces supported
iproute2 netns support available
veth supported
conntrack/NAT namespaces validated
```

Topology:

```text
main namespace:
  b4warp0 = base WARP TUN
  veth-nonru-main

b4-warp-inner namespace:
  veth-nonru-inner
  b4warp1 = inner WARP TUN
  inner session address
```

Data path:

```text
main scoped client flow
→ veth-nonru-main
→ inner namespace
→ generation-owned SNAT to inner assigned WARP IP
→ b4warp1
```

Inner control path:

```text
inner b4-warpd TCP socket
→ SO_MARK warp-inner-control-via-base
→ veth to main
→ base WARP routing table
→ b4warp0
```

Outer control path remains direct WAN.

Cleanup MUST remove:

- namespace;
- veth pair;
- namespace routes;
- namespace NAT;
- inner engine process;
- generation-owned marks;
- no foreign namespace or interface.

## 38. Backend B — inner full proxy adapter

When netns is unavailable, experimental mode MAY use:

```text
base native TUN
+ inner bundled usque full SOCKS/HTTP-stack mode
+ B4 transparent transport adapter
```

Requirements:

- inner listener bound only to loopback/Unix socket;
- no unauthenticated LAN listener;
- TCP and UDP capability reported separately;
- resource limits lower than router total;
- DNS follows inner proxy;
- inner control sockets still marked via base WARP;
- performance status shown as degraded/experimental;
- unsupported protocols fail closed within selected scope.

L4 TCP-only proxy is insufficient for generic UDP/QUIC profiles and MUST report that limitation.

## 39. Inner identity pool

Nested discovery uses a small persistent pool.

```yaml
non_ru:
  identity_slots: 2
  max_identity_slots: 3
  auto_create_new_identity: false
```

Rules:

- identities created only with explicit consent;
- no registration brute force;
- no per-attempt new device;
- old identities retained securely;
- rotation among existing identities bounded;
- account/license pairing optional and user-supplied only.

## 40. Search dimensions

Allowed bounded dimensions:

```text
inner reconnect
approved endpoint_h2_v4 candidates
approved TCP ports
approved cover-SNI candidates
existing inner identity slot
```

Forbidden dimensions:

```text
random IP scanning
unbounded SNI generation
continuous re-registration
parallel hundreds of sessions
Cloudflare endpoint public-key bypass
```

## 41. Search budget

```yaml
non_ru:
  max_attempts_per_cycle: 4
  max_cycles_per_hour: 2
  attempt_timeout: 45s
  cycle_cooldown: 300s
  success_hold_minimum: 120s
  failure_backoff_max: 1h
```

Clock uncertainty fails safe: no unbounded loop.

## 42. ADR-WARP-7 — Geo attestation is a hard route gate

Verdicts:

```text
PASS_NON_RU
FAIL_RU
INCONCLUSIVE
STALE
```

Route eligibility:

```text
PASS_NON_RU only
```

Anything else:

```text
no non-RU data route
```

## 43. Probe requirements

Each geo probe MUST prove:

- socket/packet forced through inner path;
- current inner generation counters increased;
- public IPv4 observed;
- country code observed;
- response freshness;
- HTTPS certificate validation;
- provider identity;
- no direct fallback.

At least two independent providers are required.

Cloudflare trace MAY be one provider but cannot be the only provider.

## 44. Quorum

Strict default:

```text
at least 2 providers report same non-RU country
AND no provider reports RU
AND no provider observes direct WAN IP
AND route proof is current
→ PASS_NON_RU
```

Disagreement:

```text
INCONCLUSIVE
```

One provider says RU:

```text
FAIL_RU
```

## 45. Attestation TTL

```yaml
geo_attestation:
  ttl: 120s
  refresh_interval: 60s
  refresh_on_reconnect: true
  refresh_on_public_ip_change: true
  grace_on_probe_failure: 0s
```

For strict non-RU mode no stale grace is allowed.

## 46. IPv6 and DNS

Experimental non-RU v1 default:

```text
IPv6 disabled for selected scope
DNS resolved through inner path
```

Reason:

- IPv6 may egress through a different country;
- direct DNS may reveal RU location or return RU-specific answers;
- partial family routing creates leaks.

IPv6 MAY be enabled only after independent IPv6 geo, DNS and direct-leak validation.

## 47. Non-RU failure policy

Default checkbox semantics:

```text
require_non_ru = true
→ fail_closed_scoped
```

If attestation becomes RU/unknown/stale:

```text
remove inner route immediately
→ block only selected non-RU scope
→ keep base WARP available for other bindings
→ start bounded rediscovery
```

Optional advanced policy:

```text
fallback_to_base_warp
```

UI MUST warn that this policy no longer guarantees non-RU.

## 48. Availability versus safety

The experimental mode provides:

```text
safety property:
route only while observed non-RU
```

It does not provide:

```text
liveness property:
Cloudflare will always offer non-RU egress
```

Required UI status:

```text
Non-RU requirement: enabled
Current result: unavailable
Selected traffic: blocked
Base WARP: active
Next bounded retry: <time>
```

## 49. Target-service geo probe

A Service Profile MAY add:

```yaml
geo_constraint:
  forbidden_countries: [RU]
  generic_quorum_required: true
  target_probe_required: true
```

Target probe MUST be read-only and safe.

Generic `PASS_NON_RU` alone does not guarantee that every target service accepts the egress IP.

---

# Часть IX. DPI/PPE integration

## 50. B4 packet engine integration boundary

MASQUE control flows MUST be registered before socket connect using exact transport-owned identity.

Default state:

```text
registered control flow
+ no TransportCamouflageAuthorization
→ exact bypass from all ordinary B4 service strategies
```

Ordinary `ActionAuthorization`, destination IP, port `443`, SNI guess, shared Cloudflare CIDR or Service Profile MUST NOT authorize camouflage.

A control flow MAY enter a dedicated camouflage path only when all fields exist:

```text
TransportID
+ InstanceID
+ Purpose
+ exact socket/FlowKey identity
+ selected endpoint
+ ConfigGen
+ CamouflagePolicyID
+ expiry/cutoff state
```

Even with camouflage authorization it MUST NOT receive:

- Controlled RST;
- QUIC block or mutation unrelated to the selected outer protocol;
- post-handshake disorder/fake injection;
- passive RST suppression state from unrelated service;
- service profile route recursion;
- learned-IP promotion;
- Discovery candidate action;
- indefinite mutation of the established encrypted MASQUE stream.

The packet engine MUST provide separate verdict classes:

```text
TRANSPORT_CONTROL_BYPASS
TRANSPORT_CONTROL_CAMOUFLAGE
TRANSPORT_CONTROL_ESTABLISHED_BYPASS
```

## 51. PPE integration

Completed PPE subsystem MUST support transport-owned flow classes:

```text
warp-control-direct
warp-control-via-base
warp-data-canary
warp-data-active
```

Requirements:

- exact connskip request where visibility/routing setup requires it;
- no global PPE disable;
- control and canary windows bounded;
- state removed after route/token expiry;
- inability to guarantee required visibility blocks promotion, not all router traffic;
- PPE reconciliation after WAN/firewall reload.

## 52. GSO/RST interaction

WARP TUN traffic and MASQUE control traffic are not normal candidates for direct packet strategy execution.

Later RST/GSO implementation MUST preserve:

```text
TransportControlAuthorization
TransportCamouflageAuthorization
TransportAuthorization
```

For a handshake candidate, normalization is allowed only when its `ActionPlan` requires logical ClientHello positioning and only before the camouflage cutoff. Normalized or replayed representations MUST retain instance, policy, authorization and ConfigGen.

GSO normalizer MUST NOT accidentally normalize, repeat-process or leak a pass token across outer/inner control instances.

Passive RST handling:

```text
default: observe only
scope: exact MASQUE FlowKey + instance + ConfigGen
promotion: separate canary and validation
```

Dropping all RST packets from Cloudflare is prohibited. A genuine endpoint RST must be able to terminate a dead session and trigger reconnect.

---

# Часть IX-A. WARP Transport Camouflage

## C.1. Threat model and non-goals

Camouflage protects only the outer transport establishment path against blocking or simple fingerprint rules.

Observable to the ISP even after successful camouflage:

- Cloudflare destination IP/ASN;
- long-lived TCP/443 flow;
- packet sizes and timing;
- traffic volume;
- reconnect frequency;
- nested mode overhead.

Therefore the subsystem MUST NOT claim cryptographic anonymity or statistical invisibility.

Primary threats:

```text
SNI block
TLS ClientHello pattern block
first-packet/first-record DPI classification
injected spoofed RST during establishment
provider-specific disruption of MASQUE TCP 443
```

## C.2. Transport control identity and authorization

```go
type TransportControlPurpose string

const (
    PurposeEnrollment   TransportControlPurpose = "enrollment"
    PurposeOuterMASQUE  TransportControlPurpose = "outer-masque"
    PurposeInnerMASQUE  TransportControlPurpose = "inner-masque"
    PurposeHealthProbe  TransportControlPurpose = "health-probe"
    PurposeGeoProbe     TransportControlPurpose = "geo-attestation"
)

type TransportControlAuthorization struct {
    TransportID         string
    InstanceID          string
    Purpose             TransportControlPurpose
    FlowKey             FlowKey
    SocketCookie        uint64
    Endpoint            netip.AddrPort
    OuterPath           string
    ConfigGen           uint64
    CamouflagePolicyID  string
    AuthorizedAt        time.Time
    ExpiresAt           time.Time
}
```

`SocketCookie` or equivalent kernel-verifiable identity is preferred over destination-only matching.

Authorization MUST be inserted before the first SYN and removed on:

- process generation change;
- endpoint change;
- socket close;
- ConfigGen retirement;
- timeout;
- rollback.

## C.3. Dedicated camouflage path

Camouflage MUST NOT reuse the generic Service Strategy queue without an explicit transport envelope.

Recommended path:

```text
b4-warpd creates socket
→ B4 applies SO_MARK / route ownership
→ socket identity registered
→ exact mangle/NFQUEUE selector
→ TransportCamouflageAdapter
→ direct WAN or authorized base-WARP path
```

Required envelope:

```go
type TransportCamouflageEnvelope struct {
    TransportID      string
    InstanceID       string
    Purpose          TransportControlPurpose
    FlowKey          FlowKey
    SocketCookie     uint64
    PolicyID         string
    CandidateID      string
    Phase            CamouflagePhase
    ConfigGen        uint64
    Deadline         time.Time
}
```

The packet path MUST fail closed with respect to camouflage execution: inability to verify the envelope means bypass or candidate failure, never guessed mutation.

## C.4. Camouflage phases and mandatory cutoff

```text
NEW
→ SYN_PHASE
→ CLIENT_HELLO_PHASE
→ CONNECT_IP_PENDING
→ MASQUE_ESTABLISHED
→ CLOSED
```

Only `SYN_PHASE` and `CLIENT_HELLO_PHASE` may receive packet shaping.

`MASQUE_ESTABLISHED` is entered only after structured `b4-warpd` confirmation of successful HTTP CONNECT-IP response, not after a generic log string or TCP connect.

At transition to `MASQUE_ESTABLISHED`:

```text
remove camouflage queue eligibility
→ install exact established bypass token
→ clear pending fake/split state
→ reject any delayed candidate action
```

Hard maximum cutoff also applies by packet count, byte count and wall-clock deadline so a missing lifecycle event cannot leave mutation enabled indefinitely.

Recommended ceilings:

```yaml
max_packets: 24
max_payload_bytes: 16384
max_duration: 10s
```

Values are capability defaults and require target validation before change.

## C.5. Candidate catalog

Candidates MUST be ordered from least invasive to most invasive:

```text
C0 direct, canonical SNI, no packet mutation
C1 cover SNI only
C2 deterministic ClientHello split
C3 bounded multisplit
C4 one bounded fake + split
C5 SYN/preopen shaping where validated
C6 bounded disorder, experimental last resort
```

Every candidate has explicit supported protocols, limits and rollback.

Allowed B4 primitives:

- preopen/SYN shaping with bounded attempts;
- deterministic split based on reassembled ClientHello coordinates;
- small bounded multisplit;
- one or strictly bounded fake sequence with proven remote discard;
- limited disorder only before cutoff;
- per-flow jitter only during candidate establishment and within a strict ceiling.

Forbidden:

- Controlled RST;
- mutation after `MASQUE_ESTABLISHED`;
- indefinite fake repeats;
- generic `any-protocol` strategy;
- global strategy selected by endpoint IP alone;
- modification of encrypted HTTP/2 DATA frames;
- application payload padding inside established Connect-IP unless separately designed and audited;
- strategy that requires disabling endpoint public-key pinning.

## C.6. Cover SNI policy

`b4-warpd` supports a configured outer SNI independently from the endpoint IP, while endpoint public-key pinning remains mandatory.

```yaml
cover_sni:
  mode: canonical | builtin-validated | user-explicit
  value: <optional>
```

Rules:

- canonical upstream SNI is always retained as fallback candidate;
- no hard-coded third-party hostname is treated as permanently safe;
- built-in candidates are versioned data with validation metadata;
- user-explicit value requires syntax validation and a warning;
- changing cover SNI does not change endpoint identity or trust pin;
- `insecure=true` remains forbidden;
- successful TLS alone is not promotion evidence.

## C.7. Auto-selection and scoring

`auto` MUST run candidates in increasing invasiveness and within a bounded total budget.

Candidate evidence:

```text
TCP connected
TLS completed
CONNECT-IP returned success
router path probe passed
forwarded LAN probe passed
stability window passed
reconnect rate acceptable
packet loss/latency regression acceptable
```

Promotion key:

```text
WAN identity
+ ISP/network fingerprint
+ endpoint
+ outer protocol
+ address family
+ engine build hash
+ ConfigGen
```

A promoted candidate expires on meaningful network or implementation change.

The first candidate satisfying all gates wins; B4 MUST NOT select the most aggressive candidate merely because it also works.

## C.8. Outer and inner isolation

Outer and inner WARP sessions have independent:

- socket marks;
- routing paths;
- policies;
- candidate state;
- cutoffs;
- metrics;
- failure streaks;
- established bypass tokens.

```text
outer MASQUE control
→ direct WAN camouflage policy

inner MASQUE control
→ base-WARP path camouflage policy
```

A candidate or token from one instance MUST NOT authorize the other.

For `НЕ РФ`, inner candidate promotion is valid only when:

```text
base path healthy
+ inner CONNECT-IP healthy
+ inner forwarded path healthy
+ fresh non-RU attestation healthy
```

## C.9. Enrollment camouflage

Enrollment is a short HTTPS control operation and has a separate policy from MASQUE.

Candidate order:

```text
direct canonical
→ cover SNI where protocol-compatible
→ standard safe B4 TLS strategy
→ report failure
```

No embedded external registration proxy or credentials are permitted.

Enrollment camouflage MUST use its own SetID/policy ID, bounded retry budget and secret-safe diagnostics. It cannot promote a MASQUE strategy automatically without running the MASQUE validation pipeline.

## C.10. Passive RST defense

The subsystem MAY observe inbound RST targeting an authorized MASQUE control flow.

Observation record:

```go
type MasqueRSTObservation struct {
    InstanceID       string
    FlowKey          FlowKey
    SequenceClass    string
    WindowClass      string
    TimingClass      string
    EndpointState    string
    ConfigGen        uint64
}
```

Enforcement remains off by default.

Promotion requires:

- repeated evidence of injected/spoofed class;
- exact flow visibility;
- no conflict with genuine endpoint closure;
- bounded suppression window;
- automatic rollback when reconnect health worsens;
- target router and ISP validation.

## C.11. Failure semantics

Camouflage failure is distinct from tunnel failure.

```text
candidate failed
→ rollback candidate-specific state
→ try next bounded candidate

all candidates failed
→ base WARP follows configured base failure policy

inner candidates failed
→ non-RU strict route remains inactive
```

No candidate failure may leave stale queue, fake/replay state, established bypass for a new generation, unsuccessful endpoint pin or route promotion without liveness.

## C.12. Security and observability contract

Every camouflage action MUST be explainable through structured trace fields:

```text
transport_id
instance_id
purpose
policy_id
candidate_id
phase
authorization_source
flow_key_hash
endpoint_hash
config_gen
action
cutoff_reason
verdict
```

Raw SNI, endpoint or user identity MAY be redacted according to diagnostics policy. Secrets are never emitted.

---

# Часть X. Configuration schema

## 53. Base config

```yaml
transports:
  - id: warp-main
    kind: cloudflare-warp-masque
    enabled: true

    engine:
      implementation: builtin-b4-warpd
      protocol: h2
      endpoint_family: ipv4
      port: 443
      mtu: 1280
      always_reconnect: true
      insecure: false

    camouflage:
      mode: auto                       # off | sni-cover | auto | custom
      canonical_fallback: true
      handshake_only: true
      established_bypass: required
      candidate_budget: 6
      total_budget: 90s
      stability_window: 120s
      max_packets: 24
      max_payload_bytes: 16384
      max_duration: 10s
      passive_rst:
        mode: observe                  # off | observe | canary | enforce

    scope:
      clients:
        - android-main
      sets:
        - blocked-game-servers
        - blocked-hosting
      router_origin: false

    dns:
      policy: follow-binding

    failure:
      mode: fail-open
      failure_threshold: 3
      restart_cooldown: 300s

    non_ru:
      enabled: false
```

## 54. Experimental non-RU config

```yaml
    non_ru:
      enabled: true
      backend: auto                 # auto | dual-netns-tun | inner-proxy
      failure_mode: fail-closed-scoped
      forbidden_countries:
        - RU
      identity_slots: 2
      max_attempts_per_cycle: 4
      cycle_cooldown: 300s

      attestation:
        minimum_providers: 2
        ttl: 120s
        refresh_interval: 60s
        require_same_country: true
        reject_on_any_ru: true
        ipv6: disabled
        dns_via_inner: required
```

## 54A. Custom camouflage policy

Advanced policy example:

```yaml
    camouflage:
      mode: custom
      policy_id: warp-h2-ru-safe-v1
      cover_sni:
        mode: builtin-validated
      candidates:
        - direct
        - cover-sni
        - clienthello-split
        - bounded-fake-split
      cutoff:
        event: masque-connected
        max_packets: 24
        max_payload_bytes: 16384
        max_duration: 10s
      selection:
        require_forwarded_probe: true
        stability_window: 120s
        max_reconnects: 1
      passive_rst:
        mode: observe
```

Custom policy MUST reference only catalog primitives allowed by this addendum. Arbitrary raw strategy strings are rejected.

## 55. Effective capability

```go
type WarpCapability struct {
    BuiltInEngine          bool
    HTTP2                  bool
    HTTP3                  bool
    NativeTUN              bool
    SocketMark             bool
    BindDevice             bool
    NDMIntegration         bool
    NetNS                  bool
    Veth                   bool
    InnerProxy             bool
    IPv4                   bool
    IPv6Validated          bool
    ForwardedProbe         bool
    GeoAttestation         bool
    NestedNonRU            bool
    TransportControlID     bool
    StructuredCutoff       bool
    CoverSNI               bool
    HandshakeCamouflage    bool
    CamouflageAutoSelect   bool
    CamouflageRSTObserve   bool
    PPEReconciliation      bool
}
```

No UI option is enabled when required capability is false.

---

# Часть XI. API and UI

## 56. API

```text
GET    /api/v1/transports/warp/capabilities
GET    /api/v1/transports/warp/status
POST   /api/v1/transports/warp/enroll
POST   /api/v1/transports/warp/import
POST   /api/v1/transports/warp/enable
POST   /api/v1/transports/warp/disable
POST   /api/v1/transports/warp/probe
POST   /api/v1/transports/warp/recover
GET    /api/v1/transports/warp/camouflage/catalog
GET    /api/v1/transports/warp/camouflage/status
POST   /api/v1/transports/warp/camouflage/test
POST   /api/v1/transports/warp/camouflage/select
POST   /api/v1/transports/warp/camouflage/reset
POST   /api/v1/transports/warp/non-ru/enable
POST   /api/v1/transports/warp/non-ru/disable
POST   /api/v1/transports/warp/non-ru/discover
GET    /api/v1/transports/warp/non-ru/attestation
GET    /api/v1/transports/warp/diagnostics
GET    /api/v1/transports/warp/traces
GET    /api/v1/transports/warp/traces/{trace_id}
POST   /api/v1/transports/warp/traces/export
```

All write endpoints are transactional and generation-aware.

Trace endpoints MUST:

- require authenticated local/admin access;
- return bounded, paginated results;
- redact secrets, raw identity, raw domains, full public IP and endpoint credentials by default;
- expose `schema_version`, `boot_id_hash`, `process_start_id`, `session_gen`, `route_gen` and completeness verdict;
- never allow a trace export request to block packet processing;
- use a bounded export snapshot rather than unbounded live tail;
- attach artifact hash and redaction-policy version to every exported bundle.

## 57. Status response

```json
{
  "transport_id": "warp-main",
  "engine": "builtin-b4-warpd",
  "state": "ACTIVE",
  "session_generation": 42,
  "route_generation": 17,
  "protocol": "h2",
  "port": 443,
  "tun": "b4warp0",
  "mtu": 1280,
  "masque_connected": true,
  "router_path_verified": true,
  "forwarded_path_verified": true,
  "path_proof_id": "pp-7f3c…",
  "trace": {
    "schema": 2,
    "required_event_completeness": "PASS",
    "last_sequence": 1842,
    "dropped_required_events": 0,
    "generation_mismatches": 0
  },
  "failure_policy": "fail-open",
  "camouflage": {
    "mode": "auto",
    "state": "PROMOTED",
    "candidate": "clienthello-split",
    "phase": "MASQUE_ESTABLISHED",
    "established_bypass": true,
    "last_cutoff_reason": "connect-ip-success",
    "passive_rst": "observe"
  },
  "non_ru": {
    "enabled": true,
    "state": "PASS_NON_RU",
    "base_instance_id": "warp-base-1",
    "inner_instance_id": "warp-inner-1",
    "parent_link_state": "HEALTHY",
    "observed_country": "NL",
    "observed_ipv4": "198.51.100.10",
    "attestation_age_seconds": 37,
    "attestation_id": "ga-91f2…",
    "geo_route_proof": "PASS",
    "dns_path_proof": "PASS",
    "strict_route_active": true,
    "ipv6": "disabled"
  }
}
```

## 58. Beginner UI

Primary card:

```text
WARP-туннель
MASQUE по TCP 443

[ Enable ]
Scope: выбранные устройства и сервисы
Failure: direct fallback
Status: работает
DPI compatibility: Auto — ClientHello split
```

Advanced transport control:

```text
Защита подключения WARP от DPI
[ Auto (recommended) ]

B4 сначала пробует обычное подключение и повышает уровень
только при подтверждённой проблеме. После установления MASQUE
пакетные изменения автоматически прекращаются.

Current candidate: ClientHello split
Established stream mutation: off
```

UI MUST NOT use `невидимый`, `необнаружимый` or `анонимный`.

Separate advanced checkbox:

```text
[ ] Требовать выход не из РФ (экспериментально)

B4 попробует дополнительный вложенный WARP-путь.
Трафик выбранных сервисов будет разрешён только при свежем
подтверждении, что наблюдаемый IPv4-выход находится не в РФ.
Доступность не гарантируется; задержка и нагрузка могут вырасти.
```

When enabled:

```text
Observed exit: NL
Verified: 37 seconds ago
Providers: 2/2 agree
IPv6: disabled to prevent leak
Failure action: block selected traffic
```

## 59. Diagnostics

Must distinguish:

```text
engine missing
secret missing
enrollment blocked
TUN not created
assigned address conflict
NDM refused
link down
MTU drift
MASQUE TCP connect failed
control-flow authorization missing
camouflage candidate timeout
cover SNI rejected
ClientHello split failed
camouflage cutoff missing
established bypass missing
CONNECT-IP non-200
protocol connected but data path dead
router probe failed
forwarded client probe failed
NAT missing
DNS leak
geo providers unavailable
geo disagreement
RU egress observed
attestation stale
netns unavailable
inner proxy resource limit
trace required event missing
trace event generation mismatch
trace ordering violation
route proof counter did not increase
inner-parent dependency stale
inner control leaked to direct WAN
geo quorum event does not match provider events
non-RU gate state does not match active route
DNS path not proven
IPv6 path not proven
cleanup left generation-owned resource
trace buffer overflow or required-event drop
```

One generic message `tunnel not ready` is insufficient.

---

# Часть XII. Observability and causal transport tracing

## 60. Цель трассировки

WARP observability MUST доказывать не только локальное состояние отдельного process/TUN, но и причинную цепочку:

```text
authorized client/service flow
→ exact TransportBinding
→ generation-owned route token
→ selected base or inner data path
→ current MASQUE control session
→ current parent dependency where nested
→ path-bound application progress
→ geo/DNS/IPv6 policy proof where required
→ promote, retain, revoke or rollback decision
```

Наличие отдельных сообщений:

```text
warp_inner_connected
warp_geo_attestation_passed
warp_nonru_route_promoted
```

само по себе не доказывает, что:

- inner control socket прошёл через **текущее** base WARP generation;
- geo provider request не ушёл direct WAN;
- DNS и IPv6 следовали выбранной policy;
- route promotion относится к тому же attestation и route generation;
- реальный Android/LAN flow прошёл через доказанную nested chain;
- после reconnect не использовались stale tokens или delayed events.

Поэтому v1.2 вводит generation-aware causal tracing как обязательную runtime capability.

### 60.1. Разделение trace, audit и metrics

```text
structured trace
→ high-cardinality causal evidence для одной сессии/flow/probe

audit record
→ bounded immutable запись security-sensitive decision:
   authorization, promotion, revocation, rollback, cleanup

metrics
→ low-cardinality агрегаты для health/alerting
```

Prometheus labels MUST NOT содержать:

- `FlowKey`;
- `ClientKey`;
- domain;
- endpoint;
- public IP;
- identity slot;
- `TraceID`;
- `AttestationID`;
- raw reason text.

Эти поля MAY присутствовать только в redacted structured trace.

### 60.2. Trace completeness is a release gate

Каждая операция, которая может активировать или сохранить production route, MUST иметь полный required-event set.

```text
state says ACTIVE
+ required trace events missing
→ TRACE_INCOMPLETE
→ no production promotion

route state differs from trace-derived state
→ TRACE_STATE_MISMATCH
→ rollback or observe-only
```

Telemetry MAY be sampled only for non-required progress events. Security, routing, attestation, cutoff and cleanup events MUST NOT be sampled.

## 61. `TransportTraceEnvelope`

Все WARP events используют один versioned envelope:

```go
type TransportTraceEnvelope struct {
    SchemaVersion uint16

    EventID       string
    TraceID       string
    ParentEventID string
    Sequence      uint64

    WallTime      time.Time
    MonotonicNS   uint64
    BootIDHash    string
    ProcessStartID string

    ConfigGen     uint64
    RouteGen      uint64
    SessionGen    uint64

    TransportID      string
    InstanceID       string
    ParentInstanceID string
    InstanceRole     string // base | inner | enrollment | probe | proxy-fallback
    TunnelDepth      uint8

    TestSessionID string
    DeviceRole   string
    ClientKeyHash string
    FlowKeyHash   string
    SetID         string
    ServiceProfileID string
    ComponentID  string
    BindingID    string
    RouteTokenID string

    EventType   string
    Phase       string
    StateBefore string
    StateAfter  string
    ReasonCode  string
    Result      string

    PathProofID    string
    AttestationID  string
    AuthorizationID string
    PolicyID       string
    CandidateID    string

    Payload any
}
```

### 61.1. Ordering and generation rules

Required identity:

```text
BootIDHash
+ ProcessStartID
+ InstanceID
+ SessionGen
+ Sequence
```

Rules:

- `Sequence` strictly increases within one `(BootIDHash, ProcessStartID, InstanceID, SessionGen)`;
- wall clock is informational; deadlines and event ordering use monotonic time;
- delayed event from retired `SessionGen` MUST be stored as `stale-generation` but MUST NOT change current state;
- a `masque_connected` event MUST match current `ConfigGen`, `RouteGen`, `SessionGen`, endpoint and instance;
- parent/child event links MUST reference existing or explicitly externalized parent records;
- process restart increments `ProcessStartID`;
- reconnect increments `SessionGen`;
- route transaction increments `RouteGen`;
- config activation increments `ConfigGen`;
- sequence wrap or reset within a live generation is fatal for trace completeness.

### 61.2. Required event durability

The event pipeline MUST provide:

```text
bounded in-memory ring
→ non-blocking writer
→ bounded persistent segment
→ atomic segment rotation
→ checksum
→ retention/eviction by policy
```

Priority classes:

```text
P0 — authorization, route promotion/revocation, geo gate, cutoff, cleanup ownership
P1 — lifecycle phase and failure transitions
P2 — progress/performance samples
```

Rules:

- P0 MUST survive process restart whenever persistent storage is writable;
- P0/P1 cannot be evicted in favor of P2;
- storage failure MUST emit an in-memory `trace_storage_degraded` state and block promotion requiring missing proof;
- packet path MUST NOT block on trace I/O;
- dropped P0 event increments a hard-gate counter;
- exported trace includes segment hashes and continuity status.

### 61.3. Privacy and redaction

Default trace MUST store only:

```text
hash/domain class
hash/public IP
hash/endpoint
hash/client identity
bounded enum reason codes
```

Never emit:

- private keys;
- access tokens;
- WARP license;
- raw registration config;
- raw session config;
- full device identity;
- HTTP authorization headers;
- unredacted query/body;
- secret-bearing environment;
- endpoint public-key private material.

`warp_trace_secret_leak_total > 0` is immediate `FAIL`.

## 62. Required event taxonomy

### 62.1. Process, session and MASQUE lifecycle

Required events:

```text
warp_engine_provisioned
warp_process_started
warp_process_stopping
warp_process_stopped
warp_process_crashed

warp_session_created
warp_session_generation_started
warp_session_generation_retired
warp_reconnect_scheduled
warp_reconnect_started

warp_tun_created
warp_tun_ready
warp_interface_configured
warp_ndm_fallback
warp_packet_pumps_started
warp_packet_pump_progress
warp_packet_pump_stalled
warp_packet_pump_failed

warp_control_socket_created
warp_control_socket_marked
warp_control_socket_bound
warp_control_connect_started
warp_control_connect_succeeded
warp_tls_started
warp_tls_succeeded
warp_h2_negotiated
warp_connect_ip_request_sent
warp_connect_ip_response_received
warp_masque_connected
warp_masque_rejected
warp_masque_disconnected
warp_keepalive_sent
warp_keepalive_failed
warp_session_draining
```

Phase payload MUST distinguish:

```go
type MasquePhaseTrace struct {
    Attempt          uint16
    EndpointVariantID string
    AddressFamily    string
    LocalAddressHash string
    RemoteAddressHash string

    StartedMonotonicNS   uint64
    CompletedMonotonicNS uint64
    DurationMS           uint64

    HTTPStatus        uint16
    ProtocolErrorCode string
    BackoffMS         uint64
    FailureClass      string
}
```

Required failure classes include:

```text
dial-policy-apply-failed
tcp-connect-failed
tls-alert
tls-pin-mismatch
tls-timeout
h2-negotiation-failed
connect-ip-rejected
connect-ip-timeout
packet-pump-failed
packet-pump-stall
idle-disconnect
parent-path-lost
route-proof-failed
```

A generic `connect failed` MUST NOT replace a known layer-specific reason.

### 62.2. Route and path proof

Route/rule existence is not path proof. Significant probes MUST record counter deltas:

```go
type TransportPathProof struct {
    ProofID   string
    ProofKind string // router | forwarded | inner-control | geo | dns | ipv6 | target

    ExpectedInstanceID string
    ExpectedSessionGen uint64
    ExpectedRouteGen   uint64

    InputInterfaceHash  string
    OutputInterfaceHash string
    NamespaceHash       string

    RulePriority   uint32
    RoutingTableID uint32
    MarkBefore     uint32
    MarkAfter      uint32

    CounterBeforePackets uint64
    CounterAfterPackets  uint64
    CounterBeforeBytes   uint64
    CounterAfterBytes    uint64

    ObservedSourceIPHash string
    ObservedPublicIPHash string

    DirectWANObserved      bool
    RecursiveRouteObserved bool
    ParentPathObserved     bool

    Passed        bool
    FailureReason string
}
```

Required events:

```text
warp_path_probe_started
warp_path_proof_captured
warp_path_probe_passed
warp_path_probe_failed

warp_forwarded_probe_started
warp_forwarded_binding_observed
warp_forwarded_probe_passed
warp_forwarded_probe_failed

warp_route_staged
warp_route_token_created
warp_route_promoted
warp_route_revocation_started
warp_route_removed
warp_route_rollback
```

Promotion requirements:

```text
proof counter delta > 0
+ expected session/route generation
+ no direct WAN
+ no recursion
+ expected interface/namespace
+ exact binding correlation
```

### 62.3. Forwarded Android/LAN flow correlation

Real client proof MUST form one causal chain:

```text
TestSessionID
→ DeviceRole
→ ClientKeyHash
→ ServiceProfileID
→ ComponentID
→ BindingID
→ RouteTokenID
→ PathProofID
→ base/inner SessionGen
→ application milestone
```

```go
type ForwardedFlowCorrelation struct {
    TestSessionID   string
    DeviceRole      string
    ClientKeyHash   string
    FlowKeyHash     string

    ServiceProfileID string
    ComponentID      string
    ControlRole      string // target | same-client-control | unrelated-control

    BindingID     string
    RouteTokenID  string
    PathProofID   string

    InstanceID string
    SessionGen uint64
    ParentInstanceID string
    ParentSessionGen uint64

    ApplicationProbeID string
    ApplicationMilestone string
    Passed bool
}
```

A router-origin probe cannot satisfy forwarded-client proof.

### 62.4. Nested WARP dependency graph

`WARP+WARP` MUST maintain explicit parent/child links:

```go
type TunnelDependencyLink struct {
    LinkID string

    ChildInstanceID string
    ChildSessionGen uint64

    ParentInstanceID string
    ParentSessionGen uint64

    DependencyKind string
    // inner-control-via-base
    // inner-data-via-inner-tun
    // geo-probe-via-inner
    // dns-via-inner
    // ipv6-via-inner

    ParentRouteTokenID string
    ParentHealthState  string
    ParentPathProofID  string

    EstablishedAt time.Time
    RevokedAt     *time.Time
    RevocationReason string
}
```

Required events:

```text
warp_instance_created
warp_instance_parent_linked
warp_instance_parent_revalidated
warp_instance_parent_unlinked

warp_inner_namespace_created
warp_inner_veth_created
warp_inner_nat_installed
warp_inner_route_installed

warp_inner_control_mark_applied
warp_inner_control_entered_base
warp_inner_control_exited_base
warp_inner_control_direct_leak_blocked

warp_parent_health_changed
warp_nested_dependency_degraded
warp_nested_dependency_lost
warp_nested_route_revoked
```

Rules:

- child promotion requires current healthy parent link;
- parent reconnect invalidates child link until revalidated against new parent `SessionGen`;
- child cannot use parent route token from retired generation;
- same endpoint/port on outer and inner MUST remain distinguishable by instance/session/socket identity;
- loss of parent proof revokes strict non-RU route before starting rediscovery;
- outer failure and inner failure have distinct reason codes and counters.

### 62.5. Geo attestation and `НЕ РФ` gate

Each provider result is an independent event:

```go
type GeoProviderTrace struct {
    AttestationID string
    ProviderID    string
    ProviderClass string

    InstanceID string
    SessionGen uint64
    RouteProofID string

    ObservedIPHash  string
    ObservedCountry string
    ResponseTimestamp time.Time

    TLSVerified      bool
    DirectWANMatched bool
    DNSPathID        string

    Result        string
    FailureReason string
}
```

Quorum is a separate decision event:

```go
type GeoQuorumTrace struct {
    AttestationID string

    RequiredProviders   uint8
    SuccessfulProviders uint8

    CountriesObserved []string
    AnyRU               bool
    AnyDirectWAN        bool
    ProviderDisagreement bool

    GenericVerdict       string
    TargetServiceVerdict string

    ValidFrom  time.Time
    ValidUntil time.Time

    RouteGateBefore string
    RouteGateAfter  string
    DecisionReason  string
}
```

Required events:

```text
warp_geo_probe_started
warp_geo_probe_path_proven
warp_geo_provider_result
warp_geo_provider_failed
warp_geo_quorum_evaluated
warp_geo_attestation_issued
warp_geo_attestation_expired
warp_geo_public_ip_changed
warp_geo_target_service_probe_result

warp_nonru_gate_opened
warp_nonru_gate_closed
warp_nonru_route_promoted
warp_nonru_route_revocation_started
warp_nonru_route_revoked
warp_nonru_fail_closed_activated
warp_nonru_fallback_to_base_activated
```

Required gate-close reasons:

```text
provider-ru
provider-disagreement
attestation-stale
public-ip-changed
parent-reconnected
dns-path-failed
ipv6-path-failed
direct-wan-observed
inner-path-lost
target-service-geo-failed
manual-disable
config-generation-change
```

A single summary event without provider events and path proof is invalid.

### 62.6. DNS and IPv6 path proof

```go
type DNSPathTrace struct {
    PathID       string
    QueryIDHash  string
    DomainHash   string
    QType        string

    ResolverID          string
    ResolverAddressHash string

    ExpectedPath string
    ObservedPath string

    InstanceID string
    SessionGen uint64
    RouteProofID string

    DirectWANObserved bool
    Passed            bool
    FailureReason     string
}
```

```go
type IPFamilyPathTrace struct {
    PathID  string
    Family  string
    Policy  string

    ExpectedInstanceID string
    ExpectedSessionGen uint64

    ObservedEgressIPHash string
    ObservedCountry      string
    DirectWANObserved    bool

    Passed        bool
    FailureReason string
}
```

Required events:

```text
warp_dns_query_started
warp_dns_path_proven
warp_dns_path_failed
warp_dns_leak_detected

warp_ipv4_path_proven
warp_ipv6_path_proven
warp_ipv6_path_failed
warp_ipv6_leak_detected
```

Strict non-RU route requires current DNS path proof and either:

```text
IPv6 disabled for exact selected scope
OR
current independent IPv6 path + geo + leak proof
```

### 62.7. Camouflage trace and cutoff proof

```go
type CamouflageTrace struct {
    PolicyID     string
    CandidateID  string
    CandidateGen uint64

    TechniqueFamily string
    CoverSNIClass   string

    ClassificationSource string
    AuthorizationID      string
    AuthorizationExpiresAt time.Time

    LogicalClientHelloHash string
    GSOLayout              string
    NormalizationApplied   bool

    PacketsObserved uint32
    PacketsModified uint32
    BytesObserved   uint64
    BytesModified   uint64
    FakePacketsSent uint32

    ConnectIPConfirmed bool
    CutoffSource       string
    CutoffAtSequence   uint64

    PostCutoffPacketsObserved uint64
    PostCutoffMutations       uint64
}
```

Required events:

```text
warp_camouflage_authorized
warp_camouflage_candidate_started
warp_camouflage_action_applied
warp_camouflage_candidate_failed
warp_camouflage_candidate_promoted
warp_camouflage_phase_changed
warp_camouflage_cutoff
warp_camouflage_established_bypass
warp_camouflage_delayed_action_rejected
warp_masque_rst_observed
warp_masque_rst_suppressed
```

Hard invariant:

```text
CONNECT-IP confirmed
→ camouflage cutoff emitted
→ established bypass installed
→ post_cutoff_mutations == 0
```

### 62.8. Resource ownership and cleanup proof

```go
type OwnedResourceTrace struct {
    ResourceType string
    ResourceHash string

    OwnerInstanceID string
    OwnerSessionGen uint64
    CreatedByConfigGen uint64

    Foreign bool
    CreateResult string
    RemoveResult string
}
```

Tracked resource classes:

```text
process-group
control-socket
TUN
NDM object
route rule
routing table
mark allocation
destination set
NAT rule
MSS rule
network namespace
veth pair
inner listener
bypass token
camouflage token
attestation lease
```

Required cleanup events:

```text
warp_cleanup_started
warp_route_token_removed
warp_rule_removed
warp_nat_removed
warp_veth_removed
warp_namespace_removed
warp_process_stopped
warp_mark_released
warp_cleanup_completed
warp_cleanup_failed
```

Cleanup is complete only when all generation-owned resources have terminal removal records or an explicit verified already-absent record.

Foreign resource MUST never receive a successful `removed-by-b4` event.

### 62.9. Performance attribution by layer

Performance samples MUST identify:

```text
outer-control
outer-data
inner-control
inner-data
forwarded-application
```

```go
type TransportPerformanceTrace struct {
    Layer string
    InstanceID string
    SessionGen uint64
    WindowStart time.Time
    WindowEnd   time.Time

    RXBytes uint64
    TXBytes uint64
    RXPackets uint64
    TXPackets uint64

    RTTMedianMS float64
    RTTP95MS    float64
    JitterMS    float64
    PacketLoss  float64

    QueueBacklog uint64
    NFQueueDrops uint64
    CPUSeconds   float64
    RSSBytes     uint64
    SoftIRQLoad  float64

    MTU uint32
    MSS uint32
    FragmentationEvents uint64
}
```

Derived reports SHOULD include:

```text
outer overhead ratio
inner overhead ratio
total nested overhead ratio
CPU per forwarded Mbps
reconnect recovery time
geo-gate downtime
route revocation latency
```

No nested performance claim without per-layer attribution.

### 62.10. Required trace reason enums

Free-form text MAY accompany a trace, but gates operate only on versioned enums.

Minimum groups:

```text
session/*
route/*
path-proof/*
parent-dependency/*
geo/*
dns/*
ipv6/*
camouflage/*
cleanup/*
resource/*
privacy/*
trace-pipeline/*
```

Unknown reason enum is preserved but cannot satisfy a known positive gate.

## 63. Metrics, cardinality and retention

Low-cardinality metrics:

```text
warp_state
warp_session_generation
warp_masque_connect_total
warp_masque_disconnect_total
warp_session_phase_duration_seconds
warp_reconnect_total
warp_reconnect_backoff_seconds

warp_packet_pump_stall_total
warp_probe_pass_total
warp_probe_fail_total
warp_forwarded_probe_fail_total

warp_route_active
warp_route_rollback_total
warp_route_proof_failure_total
warp_route_recursion_prevented_total

warp_parent_dependency_loss_total
warp_nested_route_revocation_total
warp_nested_control_direct_leak_total

warp_selfheal_restart_total
warp_endpoint_variant_total
warp_nat_fallback_active
warp_mtu_drift_total

warp_nonru_attempt_total
warp_nonru_success_total
warp_nonru_ru_total
warp_nonru_inconclusive_total
warp_nonru_route_active
warp_geo_attestation_age_seconds
warp_geo_provider_result_total
warp_geo_quorum_failure_total
warp_geo_direct_wan_observed_total
warp_geo_public_ip_change_total
warp_nonru_gate_transition_total
warp_nonru_revocation_latency_seconds
warp_nonru_fail_closed_seconds

warp_dns_leak_total
warp_dns_path_proof_failure_total
warp_ipv6_leak_total
warp_ipv6_path_proof_failure_total

warp_engine_cpu_seconds
warp_engine_rss_bytes
warp_tunnel_rx_bytes
warp_tunnel_tx_bytes

warp_camouflage_action_total
warp_camouflage_candidate_failure_total
warp_camouflage_promotion_total
warp_camouflage_cutoff_failure_total
warp_camouflage_established_mutation_total
warp_camouflage_cross_instance_total
warp_masque_rst_observed_total
warp_masque_rst_suppressed_total

warp_cleanup_failure_total
warp_owned_resource_leak_total

warp_trace_dropped_event_total
warp_trace_dropped_required_event_total
warp_trace_generation_mismatch_total
warp_trace_event_order_violation_total
warp_trace_storage_degraded
warp_trace_required_event_missing_total
warp_trace_state_mismatch_total
warp_trace_secret_leak_total
```

Allowed bounded labels:

```text
instance_role = base | inner | enrollment | probe | proxy-fallback
phase = tcp | tls | h2 | connect-ip | packet-pump | route | geo | cleanup
result = success | fail | timeout | stale | revoked
reason = versioned bounded enum
family = ipv4 | ipv6
policy = fail-open | fail-closed-scoped | fallback-base
backend = base-tun | dual-netns-tun | inner-proxy
```

### 63.1. Retention defaults

```yaml
warp_trace:
  enabled: true
  schema_version: 2
  memory_events: 4096
  persistent_segments: 8
  segment_max_bytes: 1048576
  retention_hours: 24
  required_event_retention_hours: 72
  performance_sample_interval: 10s
  export_max_bytes: 16777216
  hash_domains: true
  hash_public_ips: true
  redact_endpoints: true
```

Target router capability MAY reduce retention but MUST NOT disable required-event completeness for active promotion windows.

### 63.2. Trace-derived status

Status API MUST be cross-checked against trace:

```text
runtime state
vs
trace-derived state
```

Mismatch examples:

```text
runtime says non-RU route active
but latest gate event is closed

runtime says MASQUE established
but CONNECT-IP event belongs to retired SessionGen

runtime says cleanup complete
but generation-owned namespace has no removal proof
```

Any mismatch becomes explicit `TRACE_STATE_MISMATCH`, not a hidden warning.

---

# Часть XIII. Tests

## 64. Unit tests

Required:

- source pin and patch hash verification;
- engine manifest architecture selection;
- secret redaction;
- session config validation;
- assigned address extraction;
- collision rejection;
- interface ownership registry;
- mark allocation conflict rejection;
- route generation cleanup;
- SO_MARK application failure is fatal for that instance;
- environment proxy disabled by default;
- endpoint pin cannot be disabled in production;
- exact control-flow authorization before first SYN;
- destination-only camouflage authorization rejected;
- outer/inner policy and token isolation;
- legal camouflage phase transitions;
- structured CONNECT-IP cutoff;
- packet/byte/time cutoff fallback;
- delayed action rejected after cutoff;
- established bypass generation ownership;
- candidate ordering from least invasive;
- candidate promotion requires forwarded probe;
- promoted candidate invalidated on WAN/endpoint/build change;
- cover SNI does not alter endpoint pin;
- generic service strategy cannot capture control flow;
- passive RST enforcement default off;
- lifecycle event generation;
- `TransportTraceEnvelope` schema compatibility;
- strictly monotonic event sequence per session generation;
- delayed stale-generation event cannot mutate current state;
- parent/child link generation validation;
- route proof requires positive packet/byte counter delta;
- forwarded Android binding correlation completeness;
- geo provider events and quorum event consistency;
- DNS/IPv6 path proof generation ownership;
- cleanup ownership closure;
- required-event durability priority over performance samples;
- trace redaction and artifact hash;
- trace-derived status equals runtime state;
- state machine legal transitions;
- cooldown under clock skew;
- no loop when clock unavailable;
- endpoint variant primary config immutability;
- atomic destination set swap;
- private/special prefix rejection;
- fail-open and fail-closed-scoped semantics;
- attestation quorum;
- any-RU rejection;
- stale attestation rejection;
- geo provider disagreement;
- direct WAN IP detected in inner probe;
- IPv6 leak gate;
- DNS leak gate;
- no automatic identity creation loop.

## 65. Mutant/negative tests

The suite MUST catch implementations that:

- enable route merely because TUN exists;
- use arbitrary invented TUN address;
- configure NDM before netdev exists;
- accept `Tunnel established` log as protocol success;
- authorize camouflage only by Cloudflare destination IP;
- reuse a normal service strategy for MASQUE control flow;
- mutate packets after CONNECT-IP success;
- leave camouflage active when lifecycle event is missing;
- select the most aggressive working candidate instead of the least invasive;
- reuse outer token/candidate for inner instance;
- accept cover SNI while endpoint pin is disabled;
- suppress every inbound RST;
- route endpoint into its own tunnel;
- mark router OUTPUT globally;
- use fixed mark and overwrite other bits;
- flush live ipset before validating replacement;
- retain failed endpoint variant forever;
- restart every scheduler tick;
- delete foreign `opkgtunN`;
- save flash config on every respawn;
- expose SOCKS listener to LAN without auth;
- accept one geo provider;
- accept stale non-RU result;
- allow data while a provider reports RU;
- let IPv6 go direct in strict mode;
- silently fallback to base WARP under strict non-RU;
- create a new WARP identity per search attempt;
- include secrets in issue bundle;
- report `ACTIVE` without complete required-event chain;
- accept delayed `masque_connected` from retired `SessionGen`;
- open non-RU gate without provider-level geo events;
- open non-RU gate without route counter delta;
- keep child route after parent reconnect without revalidation;
- treat route/rule existence as proof that a probe traversed it;
- let inner control socket bypass base WARP directly;
- report forwarded success from router-origin probe;
- report DNS/IPv6 policy from config instead of observed path;
- mark cleanup complete while namespace, veth, rule or token remains;
- drop a P0 event silently when trace storage is full;
- put high-cardinality flow/domain/attestation IDs into metrics labels.

## 66. Integration tests with fake MASQUE server

Test server MUST produce:

```text
TCP connect failure
TLS pin mismatch
HTTP/2 negotiation failure
CONNECT-IP 403
CONNECT-IP 429
CONNECT-IP 500
successful 200 then disconnect
successful 200 with delayed structured event
successful 200 followed by genuine RST
spoof-like early RST fixture
ClientHello fragmentation tolerance matrix
one packet pump failure
idle disconnect
slow wake-up
malformed packet
oversized packet
delayed CONNECT-IP event from old session generation
out-of-order lifecycle event
event sequence reset
trace storage unavailable
required-event ring overflow
parent base reconnect while inner packet pump remains alive
geo provider response after attestation expiry
route rule present but counter delta remains zero
cleanup failure for one generation-owned resource
```

Verify reconnect/backoff, route state, trace ordering, required-event completeness and cleanup ownership.

## 67. Keenetic/NDM tests

- NDM accepts all commands;
- NDM returns success code but does not apply address;
- NDM refuses interface;
- NDM object exists without netdev;
- netdev exists without NDM object;
- assigned address held by foreign interface;
- stale B4-owned object;
- stale usque-keenetic object;
- foreign sing-box/xray/Amnezia interface;
- firewall reload deletes route/rule;
- WAN flap changes gateway;
- NDM NAT present;
- NDM NAT absent;
- double NAT detection;
- MSS clamp present/absent;
- MTU restored to 1500 by external subsystem;
- read-only/full filesystem;
- configuration save write budget;
- route/rule counter snapshot before and after exact probe;
- namespace/veth/NAT ownership event reconciliation;
- trace persistent segment rotation on read-only/full filesystem;
- reboot with stale trace and live kernel resource reconciliation.

## 68. Base field validation

Network matrix:

```text
UDP available
UDP blocked, TCP 443 available
TCP 443 intermittent
registration API direct available
registration API needs B4 DPI bypass
WAN IPv4 only
WAN dual stack
PPE enabled
PPE connskip active for exact control flow
canonical SNI blocked, cover SNI works
cover SNI blocked, bounded split works
all camouflage candidates fail
middlebox changes MSS/GSO representation
injected early RST observation fixture
```

Traffic matrix:

```text
HTTPS API
large downloads
HTTP/2 websites
HTTP/3 target carried as inner UDP
DNS/DoH
UDP game flow
long-lived TCP
reconnect during active transfer
multiple LAN clients
same-client unrelated service controls
Android TestSession → BindingID → RouteTokenID → PathProofID correlation
base reconnect during forwarded transfer
trace segment rotation under sustained traffic
cleanup after crash/reboot/WAN flap
```

## 69. Non-RU field validation

Scenarios:

1. base WARP active, inner cannot connect;
2. inner connects, all providers say RU;
3. inner connects, two providers say same non-RU;
4. one provider non-RU, one RU;
5. one provider unavailable;
6. public IP changes after reconnect;
7. attestation expires during active traffic;
8. DNS accidentally direct;
9. IPv6 accidentally direct;
10. inner endpoint recursively routed;
11. outer tunnel drops while inner active;
12. inner identity slot rotation;
13. endpoint variant succeeds;
14. all attempts exhausted;
15. strict fail-closed-scoped;
16. optional fallback-to-base warning path;
17. target service still reports RU despite generic non-RU;
18. target service blocks VPN/Cloudflare egress;
19. parent reconnect invalidates child dependency link;
20. stale parent route token presented by inner session;
21. inner control packet attempts direct WAN escape;
22. geo provider events disagree with generated quorum event;
23. geo route counter does not increase;
24. strict route revocation latency under active Android traffic;
25. DNS follows base instead of inner path;
26. IPv6 disabled in config but observed direct;
27. public IP changes before next scheduled refresh;
28. namespace/veth/NAT cleanup failure;
29. delayed old-generation attestation arrives after new session;
30. trace required-event loss blocks promotion.

## 70. Performance tests

Measure:

```text
base direct
single WARP H2 without camouflage
single WARP H2 with promoted camouflage candidate
nested WARP H2→H2 without inner camouflage
nested WARP H2→H2 with independent outer/inner candidates
inner proxy fallback
```

Metrics:

- CPU per Mbps;
- RSS;
- throughput;
- median and p95 latency;
- UDP jitter;
- packet loss;
- TCP HOL impact;
- reconnect interruption;
- router load average;
- flash writes;
- NFQUEUE/PPE interaction;
- Android battery/network effect where observable;
- outer-control versus outer-data overhead;
- inner-control versus inner-data overhead;
- total nested encapsulation overhead;
- CPU per forwarded Mbps by layer;
- geo-gate downtime;
- route revocation latency;
- trace pipeline CPU/RAM/write overhead;
- event-drop rate under maximum supported concurrency.

No performance claim without target router data and per-layer trace attribution.

## 71. Privacy tests

- issue bundle redacts secrets;
- logs redact endpoint credentials/tokens;
- geo probe stores only required country/IP hash by default;
- UI access controlled;
- API cannot export raw session config without explicit secret-export flow;
- backup encrypted;
- uninstall removes secret only after explicit policy/backup choice;
- default trace hashes domain/public IP/client/endpoint;
- raw authorization headers and request bodies never enter trace;
- exported bundle records redaction-policy version;
- metrics labels contain no high-cardinality identifiers;
- corrupted or truncated trace segment is reported, not silently accepted.

---

# Часть XIV. Hard gates

## 72. Base transport hard gates

```text
warp_secret_leak_total == 0
warp_foreign_interface_modified_total == 0
warp_recursive_control_route_total == 0
warp_mark_collision_total == 0
warp_route_without_liveness_total == 0
warp_destination_set_partial_apply_total == 0
warp_unbounded_restart_total == 0
warp_unbounded_registration_total == 0
warp_unrelated_control_action_total == 0
warp_rollback_failure_total == 0
```

## 73. Non-RU hard gates

```text
nonru_route_active_without_fresh_attestation == 0
nonru_route_active_while_any_provider_ru == 0
nonru_route_active_with_provider_disagreement == 0
nonru_route_active_with_direct_dns == 0
nonru_route_active_with_unvalidated_ipv6 == 0
nonru_route_active_after_attestation_expiry == 0
nonru_strict_direct_fallback_total == 0
nonru_identity_creation_budget_exceeded == 0
```

## 73A. Transport camouflage hard gates

```text
masque_camouflage_without_control_authorization_total == 0
masque_camouflage_destination_only_authorization_total == 0
masque_established_payload_mutation_total == 0
masque_camouflage_cutoff_failure_total == 0
masque_control_route_recursion_total == 0
masque_camouflage_cross_instance_total == 0
masque_strategy_promoted_without_forwarded_probe_total == 0
masque_strategy_promoted_without_stability_window_total == 0
masque_insecure_tls_total == 0
masque_endpoint_pin_failure_accepted_total == 0
masque_unbounded_candidate_retry_total == 0
masque_rst_suppression_without_exact_authorization_total == 0
```

## 73B. Causal trace hard gates

```text
warp_route_promoted_without_path_proof_event_total == 0
warp_forwarded_success_without_binding_trace_total == 0
warp_direct_fallback_without_trace_total == 0

warp_nested_missing_parent_link_total == 0
warp_nested_parent_generation_mismatch_total == 0
warp_nested_control_direct_leak_total == 0
warp_nested_route_active_without_parent_health_total == 0
warp_nested_stale_parent_token_total == 0

warp_geo_attestation_without_route_counter_delta_total == 0
warp_geo_quorum_without_provider_events_total == 0
warp_geo_route_gate_state_mismatch_total == 0
warp_nonru_revocation_exceeded_deadline_total == 0
warp_nonru_public_ip_change_without_refresh_total == 0

warp_dns_path_unproven_total == 0
warp_ipv6_path_unproven_total == 0

warp_connect_ip_event_wrong_generation_total == 0
warp_post_cutoff_mutation_total == 0

warp_cleanup_incomplete_total == 0
warp_owned_resource_leak_total == 0
warp_foreign_resource_removed_total == 0

warp_trace_secret_leak_total == 0
warp_trace_required_event_missing_total == 0
warp_trace_dropped_required_event_total == 0
warp_trace_event_order_violation_total == 0
warp_trace_generation_mismatch_total == 0
warp_trace_state_mismatch_total == 0
```

Release verdict:

```text
WARP_CAUSAL_TRACE_READY
```

`WARP_CAUSAL_TRACE_READY` — **узкий composable verdict** (FB-14 решение 9), подтверждающий только полную причинную связь:

```text
TransportAuthorization
→ BindingID
→ RouteTokenID
→ route/rule/mark ownership
→ socket/TUN/MASQUE path
→ target flow
→ required control flows
→ cleanup/rollback events
```

Обязательные условия:

- все required events присутствуют;
- ordering непротиворечив;
- IDs и ConfigGeneration согласованы;
- trace-derived state совпадает с runtime/API state;
- target и controls различимы;
- route/path counters подтверждают выбранный path;
- cleanup/rollback закрывает все owned resources;
- missing/skipped/unknown/stale evidence не считается PASS.

Nested WARP, geo/non-RU, camouflage и Android field validation имеют отдельные verdicts (`WARP_BASE_TRANSPORT_READY`, `WARP_CAMOUFLAGE_READY`, `WARP_NESTED_READY`, `WARP_NON_RU_READY`, `WARP_ANDROID_VALIDATED`) и в causal-trace verdict автоматически не входят; `WARP_PRODUCTION_READY` агрегирует только применимые verdicts для заявленного release scope.

> **superseded (FB-14 решение 9):** прежний расширенный состав verdict (Android forwarded-flow correlation, nested parent/child и geo-gate causal chain как обязательные условия causal verdict) заменён узким causal-trace составом настоящего пункта.

## 74. Promotion verdict

Base WARP production, including enabled `auto` camouflage capability, requires:

```text
WARP_CAUSAL_TRACE_READY
+ all base transport gates
+ all enabled camouflage gates
→ PASS
```

Camouflage MAY remain disabled by effective capability only as a declared limitation. It cannot be reported as implemented when its hard gates or target validation are absent.

Experimental non-RU MAY be released as:

```text
PASS_EXPERIMENTAL
```

only when all safety and causal-trace hard gates pass.

Availability failure to find non-RU is not implementation failure when route remains safely inactive.

Unsafe activation is `FAIL`.

---

# Часть XV. Companion stages

## WARP-1 — Reference freeze, license and threat model

Tasks:

- pin z2k, usque and usque-keenetic commits;
- archive source hashes;
- copy MIT notice;
- write dependency/SBOM manifest;
- document Cloudflare trust and privacy model;
- document no country guarantee for base WARP;
- document experimental non-RU safety/liveness distinction;
- reject separate runtime package dependency.

Tests:

- source hash mismatch fails build;
- missing license fails packaging;
- floating reference fails CI;
- B4 package contains required notices.

Deliverable:

```text
docs/reports/warp/WARP_1_REFERENCE_AUDIT.md
```

Commit:

```text
warp: freeze bundled MASQUE engine references and threat model
```

## WARP-2 — Bundled `b4-warpd` build and packaging

Tasks:

- vendor pinned source;
- apply reviewed patch series;
- create `cmd/b4-warpd`;
- static builds for target architectures;
- package inside B4;
- no separate opkg dependency;
- binary smoke test;
- version/SBOM output;
- resource and sandbox profile.

Tests:

- clean install has engine;
- upgrade replaces engine transactionally;
- rollback restores prior binary;
- uninstall removes B4-owned binary;
- no network download required at runtime.

Deliverable:

```text
docs/reports/warp/WARP_2_BUNDLED_ENGINE.md
```

Commit:

```text
warp: bundle pinned MASQUE engine as b4-warpd
```

## WARP-3 — Secret store and enrollment

Tasks:

- encrypted/0600 secret store;
- consent flow;
- direct bounded registration;
- exact B4 control-flow bypass;
- import/export with redaction;
- candidate generation and rollback;
- no bundled proxy credentials.

Tests:

- blocked registration;
- malformed config;
- truncated config;
- re-enroll rollback;
- secret leak scan.

Deliverable:

```text
docs/reports/warp/WARP_3_ENROLLMENT_AND_SECRETS.md
```

Commit:

```text
warp: add transactional enrollment and protected secret store
```

## WARP-4 — Structured engine IPC and supervisor

Tasks:

- Unix socket protocol;
- structured lifecycle events;
- process group ownership;
- parent death;
- capped backoff;
- start lock;
- no orphan jobs;
- no primary log parsing decisions;
- `TransportTraceEnvelope`;
- BootID/process/session/route/config generation identity;
- monotonic event sequence;
- bounded priority trace pipeline;
- required-event persistence and checksums;
- trace-derived state projection.

Tests:

- crash/restart;
- double start;
- stale lock;
- killed parent;
- hung child;
- malformed IPC event;
- envelope schema version compatibility;
- sequence monotonicity and stale-generation rejection;
- P0/P1/P2 event priority behavior;
- persistent segment checksum and rotation;
- trace pipeline storage failure without packet-path blocking;
- runtime state versus trace-derived state.

Deliverables:

```text
docs/reports/warp/WARP_4_SUPERVISOR_IPC.md
docs/reports/warp/WARP_4_TRACE_ENVELOPE.md
docs/runtime/warp-trace-schema-v2.md
```

Commit:

```text
warp: add owned supervisor and structured engine lifecycle IPC
```

## WARP-5 — TUN/NDM lifecycle

Tasks:

- ownership registry;
- deterministic interface;
- assigned address from session;
- exact collision rejection;
- netdev-before-NDM ordering;
- state verification;
- MTU 1280 before route;
- NDM fallback without false persistence;
- safe stale-object reconciliation.

Tests:

- all NDM/foreign/stale cases from sections 64–67.

Deliverable:

```text
docs/reports/warp/WARP_5_TUN_NDM.md
```

Commit:

```text
warp: implement verified Keenetic TUN and NDM lifecycle
```

## WARP-6 — Socket marks and recursive-route protection

Tasks:

- vendored `DialPolicy` patch;
- SO_MARK/SO_BINDTODEVICE;
- direct base control route;
- proxy env disabled;
- endpoint pin mandatory;
- MarkAllocator integration;
- PPE control flow class;
- NFQUEUE action bypass token.

Tests:

- mark application error;
- route lookup proof;
- recursive route mutant;
- mark conflict;
- proxy env injection;
- pin mismatch.

Deliverable:

```text
docs/reports/warp/WARP_6_CONTROL_SOCKET_ROUTING.md
```

Commit:

```text
warp: add generation-owned control socket routing and recursion guards
```

## WARP-7 — Scoped PBR, NAT, MSS and DNS

Tasks:

- TransportAuthorization;
- PREROUTING scoped routing;
- atomic destination sets;
- transactional route generations;
- NAT owner detection;
- conditional MSS clamp;
- DNS follow-binding;
- negative-evidence revocation;
- firewall/WAN reconciliation.

Tests:

- cross-service controls;
- multiple clients;
- shared IP;
- static IP lists;
- NDM reload;
- rollback;
- DNS leak.

Deliverable:

```text
docs/reports/warp/WARP_7_SCOPED_ROUTING.md
```

Commit:

```text
warp: add transactional scoped routing and forwarding correctness
```

## WARP-8 — Liveness, self-heal and base failure policy

Tasks:

- layered health state;
- WARP path probe;
- forwarded-client canary;
- retry semantics;
- keepalive;
- failure streak;
- cooldown;
- endpoint variant TTL;
- fail-open/fail-closed-scoped;
- reasoned diagnostics.

Tests:

- idle wake-up;
- protocol up/data dead;
- sustained failure;
- no curl/probe tooling uncertainty;
- restart storm prevention;
- variant expiry;
- forwarded NAT failure.

Deliverable:

```text
docs/reports/warp/WARP_8_HEALTH_SELFHEAL.md
```

Commit:

```text
warp: add end-to-end health gates and bounded self-heal
```

## WARP-C1 — Transport control identity and authorization

Dependencies:

```text
WARP-1…WARP-8
```

Tasks:

- introduce `TransportControlPurpose` and `TransportControlAuthorization`;
- register exact socket/FlowKey identity before first SYN;
- maintain authorization lifetime by process generation and ConfigGen;
- create explicit bypass/camouflage/established verdict classes;
- reject destination-only or SNI-only authorization.

Tests:

- socket identity ownership;
- stale generation rejection;
- endpoint change revocation;
- normal Service Strategy negative controls;
- Cloudflare shared-IP collision fixtures.

Deliverable:

```text
docs/reports/warp/WARP_C1_CONTROL_AUTHORIZATION.md
```

Commit:

```text
warp: authorize exact MASQUE transport control flows
```

## WARP-C2 — Enrollment camouflage

Tasks:

- separate enrollment policy and retry budget;
- route registration through the direct path with B4-safe TLS candidates;
- redact enrollment diagnostics;
- forbid embedded proxies and credentials;
- prove enrollment policy cannot authorize MASQUE data-plane camouflage.

Tests:

- direct success;
- DPI-blocked registration fixture;
- bounded strategy escalation;
- secret leakage negative tests;
- no identity creation loop.

Deliverable:

```text
docs/reports/warp/WARP_C2_ENROLLMENT_CAMOUFLAGE.md
```

Commit:

```text
warp: add bounded enrollment DPI compatibility path
```

## WARP-C3 — Cover SNI and endpoint trust

Tasks:

- implement canonical/builtin-validated/user-explicit cover-SNI modes;
- retain endpoint public-key pinning for every mode;
- version built-in cover data;
- expose candidate-specific diagnostics;
- prohibit `insecure` fallback.

Tests:

- canonical fallback;
- rejected cover SNI;
- pin mismatch under every cover mode;
- user input validation;
- endpoint identity unchanged.

Deliverable:

```text
docs/reports/warp/WARP_C3_COVER_SNI_PINNING.md
```

Commit:

```text
warp: support pinned cover SNI candidates
```

## WARP-C4 — Handshake-only B4 strategy adapter

Tasks:

- create dedicated `TransportCamouflageAdapter`;
- expose only approved B4 primitives;
- derive ClientHello positions from logical reassembled payload;
- carry authorization and instance metadata through GSO normalization;
- implement packet/byte/time ceilings;
- forbid established encrypted-stream mutation.

Tests:

- deterministic split coordinates;
- segmented and GSO representation parity;
- bounded fake discard proof fixtures;
- post-cutoff delayed action rejection;
- no ordinary service-side effects.

Deliverable:

```text
docs/reports/warp/WARP_C4_HANDSHAKE_ADAPTER.md
```

Commit:

```text
warp: adapt bounded B4 strategies to MASQUE handshake
```

## WARP-C5 — CONNECT-IP cutoff and established bypass

Tasks:

- consume structured `masque_connected` event from `b4-warpd`;
- transition camouflage state machine;
- atomically remove queue eligibility;
- install generation-owned established bypass;
- clear candidate/fake/replay state;
- apply hard fallback cutoff when event is absent.

Tests:

- success response versus mere TCP/TLS success;
- delayed/missing/duplicate event;
- process restart during cutoff;
- event from wrong instance/generation;
- zero established payload mutation.

Deliverable:

```text
docs/reports/warp/WARP_C5_CONNECT_IP_CUTOFF.md
```

Commit:

```text
warp: stop camouflage after verified CONNECT-IP
```

## WARP-C6 — Automatic candidate selection and scoring

Tasks:

- implement C0–C6 ordered catalog;
- run candidates in separate candidate generations;
- require protocol, router, forwarded and stability evidence;
- key promotion by WAN/ISP/endpoint/build/ConfigGen;
- expire promotion on meaningful path change;
- preserve last-good and rollback.

Tests:

- least-invasive winner;
- false one-shot success;
- reconnect and packet-loss regression;
- bounded global budget;
- WAN and endpoint invalidation;
- all candidates failed.

Deliverable:

```text
docs/reports/warp/WARP_C6_AUTO_SELECTION.md
```

Commit:

```text
warp: select least invasive stable MASQUE camouflage
```

## WARP-9 — Experimental nested backend

Tasks:

- capability detection;
- dual-netns TUN backend;
- veth/NAT lifecycle;
- inner control via base SO_MARK;
- inner identity slots;
- proxy fallback backend;
- exact cleanup;
- resource limits;
- explicit `TunnelDependencyLink`;
- current parent-session health proof;
- inner control path counter proof;
- generation-owned namespace/veth/NAT/resource events;
- parent reconnect invalidation and revalidation.

Tests:

- duplicate assigned IPs;
- netns absent;
- outer failure;
- inner failure;
- namespace leak;
- proxy listener exposure;
- UDP capability reporting;
- missing/stale parent link;
- parent reconnect while inner remains up;
- inner direct-WAN leak prevention;
- stale parent route token;
- cleanup ownership closure.

Deliverables:

```text
docs/reports/warp/WARP_9_NESTED_BACKEND.md
docs/reports/warp/WARP_9_DEPENDENCY_TRACE.md
```

Commit:

```text
warp: add isolated nested WARP experimental backend
```

## WARP-10 — Non-RU discovery and geo hard gate

Tasks:

- multi-provider geo probes;
- exact inner route proof;
- strict quorum;
- attestation TTL;
- RU/unknown/disagreement revocation;
- DNS through inner;
- IPv6 disabled by default;
- bounded search and cooldown;
- strict scoped failure policy;
- target-service probe hook;
- per-provider geo events and separate quorum event;
- path proof counter deltas;
- public-IP change event and immediate refresh;
- DNS and IPv6 observed-path proof;
- gate transition/revocation causal events;
- bounded revocation latency.

Tests:

- all section 69 scenarios;
- false-pass fixtures;
- stale/disagreement/RU cases;
- route race during reconnect;
- quorum/provider event mismatch;
- geo event from retired session generation;
- direct-WAN observation;
- missing counter delta;
- DNS/IPv6 path mismatch;
- gate-state versus kernel-route mismatch;
- active-flow revocation latency.

Deliverables:

```text
docs/reports/warp/WARP_10_NON_RU_ATTESTATION.md
docs/reports/warp/WARP_10_GEO_ROUTE_PROOF.md
```

Commit:

```text
warp: gate experimental nested routing on fresh non-RU attestation
```

## WARP-C7 — Outer/inner camouflage isolation

Dependencies:

```text
WARP-9…WARP-10
```

Tasks:

- allocate independent marks, policies and state;
- route outer control direct and inner control through base WARP;
- isolate cutoffs and established bypass tokens;
- revoke inner promotion when base or non-RU evidence fails;
- add cross-instance negative controls;
- correlate outer and inner session generations;
- trace parent link revocation before strict-route revocation;
- preserve distinct route proof and cutoff IDs per instance.

Tests:

- outer candidate cannot authorize inner flow;
- inner failure cannot remove outer bypass;
- duplicate endpoint/port with different instance;
- base reconnect while inner candidate pending;
- stale non-RU attestation revokes inner route.

Deliverable:

```text
docs/reports/warp/WARP_C7_INSTANCE_ISOLATION.md
```

Commit:

```text
warp: isolate outer and inner camouflage state
```

## WARP-C8 — Passive RST observation and bounded defense

Tasks:

- record exact MASQUE RST observations;
- classify timing/sequence/window evidence;
- keep enforcement disabled by default;
- implement separate canary suppression capability;
- rollback on reconnect or availability regression.

Tests:

- genuine endpoint RST closes session;
- spoof-like early RST observation;
- wrong-flow RST ignored;
- enforcement without visibility rejected;
- bounded suppression expiration.

Deliverable:

```text
docs/reports/warp/WARP_C8_RST_DEFENSE.md
```

Commit:

```text
warp: observe and canary MASQUE reset defense
```

## WARP-C9 — Camouflage API, UI and observability

Tasks:

- expose catalog, status, test, selection and reset API;
- add `Защита подключения WARP от DPI` UI control;
- show current candidate and established bypass;
- expose structured events, trace queries and metrics;
- implement trace schema v2 and causal envelope;
- expose completeness, generation mismatch and trace-state mismatch;
- correlate camouflage authorization, action, cutoff and established bypass;
- prohibit invisibility/anonymous claims;
- add privacy-safe issue bundle fields.

Tests:

- API generation conflicts;
- UI capability projection;
- diagnostics for every failure layer;
- secret/SNI redaction policy;
- status cannot report promotion without gate evidence;
- trace export size/redaction/access controls;
- delayed old-generation CONNECT-IP event;
- missing cutoff event;
- post-cutoff mutation counter;
- metrics cardinality audit;
- required-event loss blocks promotion.

Deliverables:

```text
docs/reports/warp/WARP_C9_PRODUCT_OBSERVABILITY.md
docs/reports/warp/WARP_C9_CAUSAL_TRACE_VALIDATION.md
```

Commit:

```text
warp: expose MASQUE DPI compatibility controls
```

## WARP-C10 — Camouflage target validation and release gate

Tasks:

- target Keenetic MediaTek runs;
- canonical/cover/split/fake candidate matrix;
- segmented/GSO parity;
- WAN flap and reconnect;
- outer/inner nested validation;
- Passive RST observe/canary matrix;
- throughput, CPU, latency and reconnect report;
- all hard gates and mutant fixtures;
- rollback from every candidate phase;
- trace completeness under GSO/segmentation;
- CONNECT-IP generation/order validation;
- outer/inner causal link validation;
- route/path proof counter validation;
- required-event loss and storage-degraded mutants.

Deliverables:

```text
docs/reports/warp/WARP_CAMOUFLAGE_IMPLEMENTATION_REPORT.md
docs/reports/warp/WARP_CAMOUFLAGE_VALIDATION_REPORT.md
docs/validation/warp-camouflage-field-matrix.md
```

Commit:

```text
warp: validate bounded MASQUE transport camouflage
```

If physical target validation is unavailable:

```text
BLOCKED_TARGET_VALIDATION
```

## WARP-11 — API, UI, Service Profiles and Field Test integration

Tasks:

- API endpoints;
- beginner UI card;
- separate experimental checkbox;
- camouflage policy selector and status;
- status/diagnostics;
- bounded trace query/export API;
- user-facing causal diagnostic projection;
- Service Profile `cloudflare-warp-masque` transport kind;
- `forbidden_countries: [RU]` constraint;
- Field Test scenarios;
- report artifacts;
- no misleading country selection language.

Required companion document deltas:

```text
B4_FIELD_TEST_AUTOMATION_ADDENDUM
→ add base WARP, camouflage, non-RU, causal trace completeness,
  nested dependency, path-proof and cleanup scenarios

B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM
→ add built-in WARP capability, transport camouflage policy, geo constraint,
  redacted trace status and actionable failure-layer explanation

B4_IMPLEMENTATION_VALIDATION_ADDENDUM
→ register WARP-1…WARP-12, WARP-C1…WARP-C10,
  WARP_CAUSAL_TRACE_READY and validation-of-observability meta-tests
```

Deliverable:

```text
docs/reports/warp/WARP_11_PRODUCT_INTEGRATION.md
```

Commit:

```text
warp: expose built-in MASQUE transport and opt-in non-RU controls
```

## WARP-12 — Full router/Android validation and release gate

Tasks:

- full unit/integration/mutant suite;
- target Keenetic MediaTek validation;
- official Android YouTube and ReVanced where profile uses WARP;
- Gmail and Google Feed negative controls;
- IP-blocked/game/hosting sets;
- TCP/UDP/QUIC traffic;
- WAN flap and reboot;
- PPE enabled;
- fail-open and strict fail-closed;
- nested non-RU availability/safety matrix;
- camouflage candidate and cutoff matrix;
- outer/inner cross-instance negative controls;
- Passive RST observe/canary matrix;
- performance and resource report;
- causal trace completeness and event-order report;
- real Android `TestSession → Binding → RouteToken → PathProof → milestone` proof;
- base/inner parent-generation dependency proof;
- geo provider/quorum/gate consistency proof;
- DNS/IPv6 observed-path proof;
- crash/reboot/rollback cleanup ownership proof;
- trace storage degradation and required-event loss mutants;
- rollback from every phase.

Deliverables:

```text
docs/reports/warp/WARP_IMPLEMENTATION_REPORT.md
docs/reports/warp/WARP_VALIDATION_REPORT.md
docs/reports/warp/WARP_NON_RU_EXPERIMENT_REPORT.md
docs/reports/warp/WARP_CAMOUFLAGE_VALIDATION_REPORT.md
docs/reports/warp/WARP_CAUSAL_TRACE_REPORT.md
docs/runtime/warp-transport-contract.md
docs/runtime/warp-trace-schema-v2.md
docs/validation/warp-field-matrix.md
```

Commit:

```text
warp: validate and gate built-in WARP MASQUE transport
```

If physical target validation is unavailable:

```text
BLOCKED_TARGET_VALIDATION
```

No production claim is permitted.

---

# Часть XVI. Definition of Done

## 75. Base WARP DoD

- user installs only B4;
- `b4-warpd` is bundled and version-pinned;
- no runtime binary download;
- MIT notice and SBOM included;
- session secrets protected;
- explicit enrollment consent;
- base HTTP/2 TCP 443 connects;
- endpoint public key pin enforced;
- control socket direct and nonrecursive;
- TUN identity stable;
- assigned address correct;
- MTU 1280 enforced before route;
- NDM state verified, not assumed;
- destination sets atomic;
- marks allocated and masked;
- routing source/service scoped;
- unrelated same-client services unaffected;
- NAT/MSS owner correct;
- route activated only after liveness;
- forwarded client validated before profile promotion;
- sustained failure removes/blocks only selected scope;
- self-heal bounded;
- rollback proven;
- PPE remains globally enabled;
- current session/route/config generations are present in required events;
- route activation has packet/byte counter path proof;
- forwarded client has binding-to-path causal trace;
- required-event completeness is `PASS`;
- runtime and trace-derived states agree;
- cleanup ownership is proven;
- no secret in diagnostics.

## 76. Experimental non-RU DoD

- separate checkbox, default off;
- base WARP works independently;
- nested backend isolated;
- inner control demonstrably traverses base WARP;
- duplicate WARP addresses cannot collide;
- search attempts bounded;
- no registration brute force;
- two-provider geo quorum;
- any RU result revokes route;
- unknown/disagreement/stale revokes route;
- strict mode never silently falls back direct/base;
- DNS follows inner path;
- IPv6 disabled until validated;
- selected traffic blocked when no verified non-RU path;
- unrelated traffic unaffected;
- observed country and freshness visible;
- target-service mismatch reported honestly;
- explicit current parent/child generation link;
- per-provider geo events and separate quorum event;
- non-RU gate transition matches active kernel route;
- DNS and IPv6 observed-path proof;
- public-IP change invalidates or refreshes attestation;
- revocation latency measured under active flow;
- no claim of country selection or permanent availability;
- safe result under every failure fixture.

## 76A. WARP Transport Camouflage DoD

- ordinary Service Strategies cannot match MASQUE control by endpoint alone;
- exact control authorization exists before first SYN;
- enrollment, outer and inner purposes are distinct;
- endpoint pinning remains enabled for every SNI candidate;
- `auto` starts with least-invasive candidate;
- escalation and total budgets are bounded;
- ClientHello actions are based on logical/reassembled coordinates;
- GSO/segmentation representations produce equivalent decision;
- structured CONNECT-IP success triggers cutoff;
- packet/byte/time fallback cutoff exists;
- established encrypted MASQUE stream receives no mutation;
- outer and inner candidates/tokens cannot cross;
- candidate promotion requires forwarded probe and stability window;
- promotion expires on WAN/endpoint/build/ConfigGen change;
- failure cleans queue, fake, replay and token state;
- Passive RST enforcement is off by default;
- genuine endpoint RST remains functional;
- target router validation and rollback reports exist;
- UI does not claim invisibility or anonymity;
- authorization/action/cutoff/bypass events form one causal chain;
- delayed old-generation CONNECT-IP cannot trigger cutoff;
- post-cutoff mutation count is zero;
- all camouflage and causal-trace hard gates equal zero.

## 76B. Causal transport trace DoD

- one versioned `TransportTraceEnvelope` is used across core and `b4-warpd`;
- BootID, process start, ConfigGen, RouteGen and SessionGen are distinct;
- event sequence is monotonic per active session generation;
- delayed retired-generation events cannot change current runtime state;
- P0 required events are not sampled;
- trace I/O cannot block packet processing;
- route promotion has positive exact counter delta;
- forwarded Android/LAN proof cannot be substituted by router-origin probe;
- WARP+WARP has explicit parent/child dependency link;
- parent reconnect invalidates child dependency until revalidated;
- geo provider results and quorum decision are separately traceable;
- non-RU gate state equals actual route state;
- DNS and IPv6 policy are based on observed path, not config alone;
- cleanup records every generation-owned resource;
- foreign resources are never recorded as removed by B4;
- trace-derived state equals runtime state;
- exported artifact has redaction-policy version, continuity status and hashes;
- `WARP_CAUSAL_TRACE_READY` is PASS.

## 77. Final invariant

Base transport invariant:

```text
Only authorized scoped traffic uses a verified WARP path.
```

Transport camouflage invariant:

```text
Only an exact, generation-owned MASQUE control flow may receive a bounded
camouflage action, and every such action stops after verified CONNECT-IP
or a stricter packet/byte/time cutoff. Established MASQUE payload is bypassed.
```

Causal trace invariant:

```text
No WARP, nested WARP, camouflage or non-RU route is reported as production-ready
unless its current authorization, session generation, parent dependency,
path proof, gate decision and cleanup ownership are reconstructable from
a complete, generation-consistent and privacy-safe required-event chain.
```

Experimental non-RU invariant:

```text
When `Требовать выход не из РФ` is enabled,
selected traffic is never intentionally routed through the experimental path
unless current multi-provider evidence says observed IPv4 egress is not RU.
If that evidence is absent, conflicting, RU or stale,
the selected scope is not allowed to use that path.
```

---

# Appendix A. Recommended repository layout

```text
cmd/
  b4/
  b4-warpd/

src/transport/warp/
  manager.go
  config.go
  capability.go
  supervisor.go
  ipc.go
  secret_store.go
  enrollment.go
  interface_registry.go
  ndm.go
  dial_policy.go
  mark_policy.go
  routing.go
  destination_sets.go
  nat.go
  dns.go
  health.go
  selfheal.go
  endpoint_variants.go
  tracing/
    envelope.go
    sequence.go
    writer.go
    segment_store.go
    completeness.go
    path_proof.go
    forwarded_correlation.go
    dependency_graph.go
    geo_trace.go
    dns_trace.go
    cleanup_trace.go
    redaction.go
    metrics.go
  camouflage/
    authorization.go
    registry.go
    envelope.go
    adapter.go
    catalog.go
    cover_sni.go
    phase.go
    cutoff.go
    selector.go
    scoring.go
    established_bypass.go
    rst_observer.go
  nonru/
    manager.go
    backend.go
    netns_backend.go
    proxy_backend.go
    identity_pool.go
    geo_probe.go
    attestation.go
    route_gate.go
    trace_contract.go

third_party/usque/
  PINNED_COMMIT
  LICENSE.md
  UPSTREAM_TREE_HASH
  patches/
    0001-b4-structured-events.patch
    0002-b4-dial-policy-so-mark.patch
    0003-b4-disable-env-proxy-default.patch
    0004-b4-context-shutdown.patch
    0005-b4-instance-metadata.patch
    0006-b4-control-socket-identity.patch
    0007-b4-connect-ip-structured-cutoff.patch
    0008-b4-generation-aware-trace-envelope.patch
    0009-b4-masque-phase-events.patch
```

# Appendix B. Required reports per stage

Every stage report MUST contain:

```text
stage ID
baseline commit
result commit
files changed
requirements implemented
tests added
tests run
router target status
known limitations
security review
camouflage authorization/cutoff evidence where applicable
trace schema and event completeness
session/route/config generation evidence
path-proof counter deltas
parent/child dependency proof where applicable
geo provider/quorum/gate consistency where applicable
DNS/IPv6 observed-path proof where applicable
cleanup ownership proof
trace artifact hashes and continuity status
rollback proof
artifact hashes
final verdict
```

# Appendix C. Explicitly forbidden shortcuts

- installing `usque-keenetic` as prerequisite;
- asking user to install `usque` manually;
- downloading current release during first enable;
- copying z2k fixed mark values;
- importing z2k embedded proxy credentials;
- using arbitrary Cloudflare endpoint scans;
- applying global default route;
- routing router-origin traffic broadly;
- trusting TUN/address as health;
- using one geo service;
- treating Cloudflare colo as guaranteed exit country;
- claiming non-RU while IPv6/DNS leaks direct;
- keeping route during stale attestation;
- auto-creating identities until country changes;
- hiding experimental unavailability behind base WARP fallback;
- modifying foreign TUN/NDM objects;
- disabling global PPE/offload;
- enabling insecure TLS/pin bypass in production;
- applying a generic service strategy to all Cloudflare TCP/443;
- authorizing camouflage from destination IP/SNI alone;
- mutating the established encrypted MASQUE stream;
- claiming that camouflage makes WARP invisible or anonymous;
- using one hard-coded third-party cover SNI as a permanent dependency;
- suppressing every inbound RST;
- sharing candidate, cutoff or bypass tokens between outer and inner instances;
- reporting route success from rule existence without counter/path proof;
- accepting delayed lifecycle or geo event from retired session generation;
- reporting WARP+WARP without explicit current parent/child dependency;
- reporting non-RU from a summary verdict without provider events and route proof;
- inferring DNS/IPv6 path only from configured policy;
- substituting router-origin probe for forwarded Android/LAN proof;
- sampling or silently dropping required P0 trace events;
- blocking packet processing on trace storage;
- reporting cleanup complete while any generation-owned resource remains;
- exporting secrets or high-cardinality identifiers through metrics labels.

# Appendix D. Release ordering after this addendum

```text
CSI-1…CSI-10
→ WARP-1…WARP-8
→ WARP-C1…WARP-C6
→ WARP-9…WARP-10
→ WARP-C7…WARP-C10
→ WARP-11…WARP-12
→ WARP_CAUSAL_TRACE_READY
→ H1…H10
→ FT updated implementation
→ SP updated implementation
→ IV updated umbrella validation
→ full release gate
```

The validation documents MAY be supplied to the agent from the beginning as acceptance references, but their executable final phases run only after all runtime and product components exist.
