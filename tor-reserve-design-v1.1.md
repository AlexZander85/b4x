# E-TOR design v1.1 — review-corrected canonical delta

Дата: 2026-09-15.

Этот документ является **каноничным исправлением** `tor-reserve-design.md` v1.
При конфликте между v1 и этим документом приоритет имеет v1.1. Исторический v1
сохранён только для traceability TT1–TT10.

## 1. Tor wire facts

### 1.1 Control socket

Канон torrc:

```text
ControlSocket /absolute/path/control.sock
CookieAuthentication 1
CookieAuthFile /absolute/path/control.cookie
```

`unix:/path` относится к синтаксису `ControlPort`, но не к `ControlSocket`.

### 1.2 SOCKS5 egress proxy

Канон Tor:

```text
Socks5Proxy 127.0.0.1:PORT
Socks5ProxyUsername RANDOM_USER
Socks5ProxyPassword RANDOM_PASSWORD
```

Combined URI `user:pass@host:port` запрещён для renderer-а.

### 1.3 Vanilla bridges

Внутренний transport label `vanilla` допустим в модели b4x, но в torrc vanilla
bridge всегда address-first:

```text
Bridge IP:ORPORT FINGERPRINT
```

Leading token перед адресом для Tor означает имя pluggable transport. Поэтому
`Bridge vanilla ...` недопустим без plugin `vanilla` и никогда не рендерится.

### 1.4 Relay scanner

Legacy CREATE/CREATED probe из v1 удалён. Command `0x04` — DESTROY, а не CREATED;
legacy CREATE/CREATED не является допустимым современным health proof.

Канон scanner v1.1:

1. TLS с random SNI;
2. VERSIONS, negotiation link protocol v4/v5;
3. bounded parse `CERTS`;
4. bounded parse `AUTH_CHALLENGE`;
5. bounded parse `NETINFO`;
6. client `NETINFO`.

Этого достаточно, чтобы доказать Tor-specific application framing и
DPI-transparency без построения circuit. Если в будущем потребуется deep circuit
probe, он должен быть отдельной стадией на CREATE2/ntor с корректными relay keys,
а не synthetic legacy CREATE.

Scanner выбирает top-bandwidth cohort, делает shuffle только внутри cohort и
ведёт persistent per-OR-address cooldown (минимум 6h).

## 2. Egress policy v1.1

Есть два разных режима:

- `through=auto` — availability profile: direct/failover согласно policy;
- `through=<named-carrier>` — **strict profile**: никакого silent direct bypass.

Named carrier является privacy/no-leak обещанием. Если выбранный transport
нуждается в capability, которой carrier не имеет, transport fail-closed.

### 2.1 Snowflake

Текущий `reserve.Carrier` поддерживает stream/TCP, но не UDP. Snowflake WebRTC
нуждается в ICE/STUN/DTLS packet sockets. Поэтому:

- `through=none|auto`: marked direct packet path разрешён;
- `through=<named carrier>`: direct packet path запрещён;
- pinned Snowflake честно недоступен (`tor_carrier_unsupported`) до появления
  packet-capable carrier API;
- auto ladder при pinned carrier пропускает Snowflake, не делает direct leak;
- active Snowflake broker/front относится к `pt-rendezvous` и наследует pinned
  policy, а не принудительный bootstrap-source `auto`.

Bootstrap metadata sources (Onionoo/Moat/mirrors) остаются anti-loop class и не
ходят через Tor.

## 3. Entry ladder v1.1

`race_window` — **глобальный** максимум heads в mixed-set, не per-transport.
Mixed-set round-robin берёт webtunnel/obfs4/snowflake, если transport допустим
текущей egress policy.

`meek_lite` — manual-only и не участвует в auto.

После mixed-set failure runtime обязан выбрать явный sequential candidate;
пустой entry не является состоянием ladder.

Winner memory:

- transport winner записывается только при доказанной attribution;
- сохраняется stable bridge identity (`transport|fingerprint|endpoint`);
- неоднозначность/ошибка GETINFO => `tor_entry_attribution_unknown`;
- unknown не обучает memory и не подменяется первым bridge из set.

## 4. Process lifecycle v1.1

Единственный допустимый lifecycle live C-Tor:

`owned handle -> graceful SHUTDOWN -> guarded TERM -> guarded KILL -> confirmed dead -> handle cleared -> replacement may spawn`.

Правила:

- `torrc-defaults` существует до exec;
- Tor native pid-file и b4 ownership metadata — разные файлы;
- перед TERM/KILL обязательно pid + `/proc/<pid>/exe` ownership proof;
- runtime restart, bootstrap failure, entry change, liveness restart используют
  один retirement path;
- process handle нельзя занулять до подтверждённого retirement;
- если ownership proof не позволяет безопасно завершить child, runtime уходит в
  backoff и **не** запускает второй Tor;
- уже умерший child обрабатывается death path без повторного kill.

## 5. Liveness v1.1

- probe interval: 60s;
- 2 failures: ACTIVE + NEWNYM;
- 4 failures: фиксируется `deadSince`;
- teardown разрешён только после >=30s непрерывного dead-state;
- успешный probe очищает fail/deadSince и возвращает established.

## 6. Control protocol v1.1

GETINFO parser хранит wire boundary multiline values:

```text
250+key=
<body>
.
250-other=value
250 OK
```

Dot terminator не теряется между low-level roundtrip и structured parse.
Соседние keys не могут быть частью multiline body.

## 7. Resource envelope

Cross-compile не доказывает runtime feasibility на 32–128MB роутерах. Status
экспортирует как минимум:

- Tor RSS (Linux);
- FD used / RLIMIT_NOFILE;
- low-memory classification;
- effective Conflux UX;
- разрешён ли Snowflake direct packet path.

`conflux=auto` выбирает `throughput_lowmem` на low-memory Linux и обычный
`throughput` на остальных. Unsupported SETCONF остаётся soft-degradation.

Renderer имеет seams для `ConnLimit`/`MaxMemInQueues`, но значения не угадываются
без полевых измерений.

## 8. Transport scope

Release claim: **все Nova UI entry modes + manual meek_lite**.

`conjure`, `dnstt`, full `meek`, obfs2/obfs3/scramblesuit` не являются скрытым
gap текущего E-TOR. Это отдельные будущие этапы и требуют отдельного owner decision
по dependencies/infrastructure.

## 9. Mandatory gates

До field:

1. unit/race regression;
2. opt-in real `tor --verify-config` for direct/vanilla/PT/mixed;
3. strict Snowflake unit proof;
4. process retirement/no-double-spawn unit proof;
5. modern relay handshake fixtures;
6. conflict-free integration with current classifier branch.

В поле дополнительно обязательны vanilla-through-carrier no-leak и отдельный
Snowflake+pinned-carrier fail-closed pcap из `FIELD_TEST_TOR_PROMPT.md`.
