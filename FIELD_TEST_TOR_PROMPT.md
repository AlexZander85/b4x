# FIELD TEST E-TOR — review-hardened gate

> Каноничный полевой пакет для E-TOR после независимого review. Запускать
> только с разрешения владельца и по правилам AGENTS.md. Живые `/opt/sbin/b4`
> и `/opt/etc/b4/b4.json` не заменять; тестовый бинарь и конфиг — только копии.

## 0. До поля

Полевой прогон разрешён только если выполнены все пункты:

1. Ветка содержит review-fixes после `tor-reserve-review.md`.
2. `go vet ./...`, `go test ./...` и race-набор новых Tor-пакетов зелёные в
   воспроизводимой среде.
3. На машине с реальным C-Tor выполнен:

```sh
B4X_TOR_INTEGRATION=1 B4X_TOR_BINARY=/path/to/tor \
  go test ./transport/tor -run VerifyConfig -v
```

4. На Keenetic установлен Entware Tor; записана точная `tor --version`.
5. Есть `tcpdump` на WAN и возможность измерять RSS/FD обоих процессов.

## 1. Исправленные инварианты, которые поле должно доказать

### 1.1 torrc/control

- `ControlSocket` — реальный Unix path без `unix:` prefix.
- vanilla/direct proxy рендерится как `Socks5Proxy host:port` + отдельные
  `Socks5ProxyUsername`/`Socks5ProxyPassword`.
- vanilla Bridge — address-first, без фиктивного transport token `vanilla`.
- control GETINFO multiline не смешивает соседние keys.

### 1.2 process ownership

- одновременно существует не более одного E-TOR C-Tor;
- любой runtime restart сначала завершает старый owned process, затем допускает
  новый spawn;
- TERM/KILL разрешены только после pid+`/proc/<pid>/exe` ownership check;
- Tor и b4 используют разные pid files;
- смерть b4 убивает owned Tor через `__OwningControllerProcess`/graceful stop;
- системный Entware Tor, если он существует отдельно, не трогается.

### 1.3 strict carrier policy

`egress.through=<named carrier>` (`proton`, `warp`, ...) означает **strict
fail-closed**, а не availability fallback. Прямой WAN egress запрещён.
`egress.through=auto` — отдельный availability profile и может использовать
marked direct-first/failover согласно policy.

Сегодня reserve.Carrier — TCP-only. Поэтому Snowflake, которому нужен UDP
ICE/STUN/DTLS, при pinned named carrier должен честно быть недоступен/пропущен
auto-ladder, а не выходить UDP напрямую.

### 1.4 scanner

Relay scanner больше не создаёт legacy CREATE cells. Глубокая проверка —
современный Tor link-channel proof:

`TLS(random SNI) -> VERSIONS(v4/v5) -> CERTS -> AUTH_CHALLENGE -> NETINFO -> client NETINFO`.

Сканирование идёт по top-bandwidth cohort, с shuffle внутри cohort и
персистентным cooldown одного OR-address минимум 6 часов.

## 2. Базовая конфигурация

```json
{
  "system": {
    "tor": {
      "enabled": true,
      "entry": {"mode": "auto", "race_window": 2},
      "bridges": {"builtin_snowflake": true, "country": "ru"},
      "egress": {"through": "none", "bait_profile": "none"},
      "speed": {"conflux": "auto", "padding": "reduced", "geoip": false},
      "relay_scan": {"enabled": true, "ports": [443, 9001], "goal": 6}
    }
  }
}
```

`race_window` — глобальный лимит голов mixed-set, а не лимит на каждый
transport. `meek_lite` manual-only и в auto mixed-set не участвует.

## 3. Шаг A — process/control smoke

1. `egress.through=none`, entry = рабочий PT или direct там, где direct жив.
2. Запустить тестовый b4.
3. Проверить `/api/tor/status`:
   - `running=true`;
   - переход starting/bootstrapping/established;
   - после bootstrap `listening=true`;
   - `resources.fd_limit`, `resources.fd_used`, `resources.rss_bytes` доступны
     на Linux;
   - `entry.winner_bridge` появляется только при доказанной атрибуции.
4. Проверить generated torrc и control socket path.

FAIL: invalid torrc, control unavailable после появления socket, fabricated
winner при неизвестном ORConn.

## 4. Шаг B — DPI profile входов

Поочерёдно pin: `webtunnel`, `obfs4`, `snowflake`, при наличии owner line —
`meek`; для каждого снять WAN pcap от старта до 1 минуты полезного стрима.

Ожидания:

- webtunnel: нормальный HTTPS к front-domain + WebSocket upgrade;
- obfs4: неразбираемый шум;
- snowflake при `through=none/auto`: broker/front HTTPS + WebRTC/DTLS;
- meek_lite: обычный HTTPS/CDN, только manual pin;
- vanilla direct — лишь документирование поведения ISP, не release path в
  блокирующей сети.

## 5. Шаг C — ключевой no-leak: vanilla through carrier

Установить `egress.through=proton` (либо другой живой named carrier),
`entry=vanilla`, использовать verified relay lines scanner-а.

Минимум 10 минут трафика + pcap.

PASS одновременно:

- Tor established;
- наружу виден только carrier protocol;
- **ноль** прямых TCP к Tor relay/bridge;
- exit probe `is_tor=true`;
- carrier остаётся жив при restart Tor;
- throughput/TTFB записаны.

Любой прямой relay packet = CRITICAL stop.

## 6. Шаг D — отдельный Snowflake strict-carrier gate

Это обязательный тест, которого не было в первой версии field packet.

1. `egress.through=proton`, `entry=snowflake`.
2. Начать pcap до попытки старта.
3. Ожидание текущей TCP-only архитектуры: E-TOR **fail-closed** с
   `tor_carrier_unsupported`/честным backoff; не должен открываться direct UDP.
4. В pcap должно быть:
   - ноль прямого STUN/ICE/DTLS Snowflake;
   - ноль direct broker/front HTTPS от E-TOR;
   - ноль Tor relay bypass.

Если pinned Snowflake внезапно bootstrap-ится через прямой UDP — **FAIL/CRITICAL**.
Packet-capable carrier может изменить этот expected result только отдельным
архитектурным этапом.

## 7. Шаг E — auto ladder и winner memory

`entry=auto`, `race_window=2`.

PASS:

- mixed-set одновременно не превышает глобальный budget;
- meek_lite отсутствует из auto;
- после mixed failure выбирается явный sequential entry, не пустая строка;
- exact bridge/fingerprint attribution записывает `winner` и
  `winner_bridge`;
- если control data не позволяет однозначно определить мост, событие
  `tor_entry_attribution_unknown`, а winner-memory **не обучается**;
- при pinned named carrier Snowflake пропускается как unsupported, а не
  пытается утечь напрямую.

## 8. Шаг F — lifecycle / kill semantics

### F1. Убить Tor

Убить только pid из ownership metadata. b4 остаётся жив, carrier остаётся жив,
событие `tor_process_died`, restart guard действует.

### F2. Runtime restart во время bootstrap

Это новый обязательный P0-тест.

1. Во время bootstrap вызвать `/api/tor/restart` или сменить entry.
2. В цикле 1–2 секунды считать `ps`, `/proc/*/exe`, fd/listeners.
3. До нового spawn старый owned Tor обязан исчезнуть.
4. Никогда не должно быть двух owned Tor одновременно.

FAIL: orphan, два Tor, конфликт control/data path.

### F3. Liveness grace

Индуцировать 4 последовательных liveness failures.

- 2 failures => ACTIVE + NEWNYM;
- на 4-м failure teardown **не мгновенный**;
- только после >=30 секунд непрерывного dead-state старый process retire + restart.

### F4. Убить b4

После SIGTERM b4 не остаётся owned Tor, PT/egress listeners закрыты. Чужой
системный Tor не затронут.

## 9. Шаг G — scanner safety/speed

Запустить `/api/tor/scan`.

PASS:

- проверяются все подходящие `or_addresses`;
- verified line address-first (`IP:port FINGERPRINT`);
- probe — modern channel handshake, без CREATE/CREATED legacy;
- второй немедленный scan показывает cooldown-skipped endpoints и не повторяет
  активные handshakes;
- после cooldown адрес снова eligible;
- top-bandwidth cohort сохраняет приоритет скорости, shuffle только внутри него.

Сохранить количество candidates/probed/skipped и WAN pcap.

## 10. Шаг H — ресурсы и soak

На ARM и, если есть, MIPS:

- RSS b4 и Tor;
- `fd_used/fd_limit`;
- goroutines;
- CPU;
- bootstrap time;
- first-stream TTFB;
- throughput каждого входа.

При low-memory platform `conflux=auto` должен выбирать low-memory UX, если Tor
его поддерживает; отказ SETCONF остаётся честной soft-degradation.

Soak 24–48 часов запускать только после прохождения A–G. FAIL: растущий без
плато RSS/FD, orphan process, restart storm, direct leak.

## 11. Финальный PASS

E-TOR можно считать field-ready только если одновременно доказаны:

- real `tor --verify-config` gate;
- vanilla-through-carrier no-leak;
- Snowflake pinned-carrier fail-closed;
- runtime restart без orphan/double-Tor;
- exact/unknown winner semantics;
- modern scanner + persistent cooldown;
- stable RSS/FD soak;
- regression тесты остальных резервов после интеграции с актуальной base branch.
