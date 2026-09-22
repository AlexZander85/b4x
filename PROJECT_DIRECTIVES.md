# PROJECT DIRECTIVES — единственный источник истины (b4x)
LIVE: **b4.exp-p35b `cfc4afe9…`** (-tags "l5ppe echflow ggcdisc qbp vnb ja4 storm") = l5ppe PPE-окно(self-heal×2) + наблюдательные слои Части 3: tcp_has_ech, GGC-shard discovery, QUIC-bypass гвардия, JA4-лог, VN-проба, шторм-гейдж. cfg md5 `6e792623` НЕ ТРОНУТ. UX-вердикт 23.08 ~15:00+05: НЕГАТИВНЫЙ (ReVanced тормоза в просмотре + ваниль seek, оба клиента) — атрибуция форензикой: внешний шторм ротации эджа Google; повторная проверка на штиле (gauge CALM<40) обязательна до принятия стека как якоря.
Лестница: L0–L6 ЗАКРЫТА (23.08). Router-side против ECH-стены ИСЧЕРПАН; интерференция с doomed-TCP ЗАКРЫТА. Часть 3 обвязка ЗАВЕРШЕНА 23.08 (bd b4x-2pq). **СЛЕДУЮЩАЯ ФАЗА: WARP/туннельный класс (P1+)** — единственный ответ и на стену, и на штормы ротации эджа Google (23.08: 105 уникальных endpoint'ов/час, POP-коды менялись 4 раза, fra16s31 мёртв; жалобы на обоих ванильных клиентах).
Откат: флешка `$F/bin/b4.exp-{p35b cfc4afe9, p35a 52974536, ggcdisc 6b514b77, l5ppe 4ff57114=v4, holdch3 666eb175}`; порядок: S99b4 stop СНАЧАЛА, чистка B4_PPE_* только после остановки. НЕ google /16, не exclude-persist.
Карта YouTube: `YOUTUBE_DATAPLANE.md`. State: `.ag/summaries/state_packet.md`. Правила: `AGENTS.md`.

---

Как читать остальное: **PRODUCT TARGET** — куда идём (ещё не факт). **REFERENCE BASELINE** — что доказано, живое не трогать. **LADDER** — один слой за сессию. **YOUTUBE_DATAPLANE.md** — как устроен обход YouTube и что уже доказано по seek. Если агент включает PPE + новый бинарь + новый конфиг + логи + YouTube в одном деплое — это день сурка.

---

## 1. PRODUCT TARGET (хотим, не равно «уже так»)

Стабильный YouTube на `.152` (телефон) и `.40` (ПК): ваниль и ReVanced, интерфейс сразу, видео сразу, перемотка сразу, без поломки Gmail/News.

| # | Цель | Статус на 18.08.2026 | Это отдельный слой |
|---|---|---|---|
| T1 | Логи на флешку (`system.logging.directory` + GUI) | Код в HEAD (`5cea6109`). В baseline-конфиге **нет**. GUI-бинар с этим сломал FD. | L1 |
| T2 | PPE per-flow: окно рукопожатия на CPU (`-j PPE` + connskip), bulk потом в железо | Код в HEAD (`8583f511`). На baseline **выключен** (rc9 без ppe-кода). `offload_policy=exclude` ломает маскировку. | L5, только после L2 |
| T3 | Fake SNI Desync (badsum **или** AutoTTL) + L4 Multisplit/Disorder только на первый ClientHello | На поле живёт **AutoTTL + combo**, не badsum. `sni_mutation` запрещён (ломает TLS 1.3). «Строка в логе» ≠ доказательство. | L4 |
| T4 | Три набора YouTube получают стратегию: API / `googlevideo.com` / UI | Handoff поле: TCP на уже виденный QUIC-IP получает `youtube-video`. Новый IP / гонка первых пакетов — ещё дыра. | L3 |
| T5 | UX: мгновенно и на ванили, и в ReVanced, seek не виснет | Причина доказана: ТСПУ режет по ECH-ext (`YOUTUBE_DATAPLANE.md` §2); C закрыта. Следующий слой **L-steer** `bd b4x-p0.8`. | результат L3 |

Брошюра «Fake SNI + PPE offload после первого CH» — целевой дизайн. Сейчас это не описание живого стека.

### Путь к продукту (YouTube — не боковой квест)

Итог, который хочет владелец: форк **сам** видит, что YouTube/другой сайт недоступен или медленный, и **сам** ищет и включает решение.

Это уже описано, новый архитектуры не выдумывать:

```text
реальный трафик клиента
→ Continuous Monitoring (src/monitor)
→ гипотеза / health drop
→ ABD (детектор, BlockingProfile)
→ guided Discovery (бюджет, не ручной перебор)
→ canary на .152
→ promote или rollback
```

Нормативы: `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_*`, `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_*`, `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_*`.

Полевая пачка `B4X_FIELD_VALIDATION_AGENT_PACK` — это **сертификация релиза** (потом). Сейчас она сужена: полигон = YouTube, потому что там болит. Это не отмена продукта, это единственный честный E2E для capture/classifier/desync/PPE.

Фазы:

| Фаза | Что доказываем | Пока рано |
|---|---|---|
| **P0** лестница L0–L6 | Дата-плоскость: логи, бинарь не хуже rc9, классификатор видит 3 сета, Fake SNI по pcap, PPE-окно, изоляция Gmail | Discovery «подбери стратегию», WARP, uTLS, substitute |
| **P1** | Тот же цикл monitor→ABD→discovery→canary **только на 3 наборах YouTube** | Включать авто-promote на все сайты |
| **P2** | Те же механизмы на остальные сайты + изоляция | — |
| **P3** | Полный L0–L8 из field pack как сертификат релиза | Использовать pack как план отладки |

Пока L3 не PASS (первый flow `.152` классифицирован до backoff), автономный поиск стратегий только усилит круг: программа будет крутить pastseq/timestamp на невыбранном сете.

---

## 2. REFERENCE BASELINE (не ломать)

Зафиксировано 18.08.2026. Видео идёт, интерфейс быстрый. Ревизия только после успешного слоя лестницы.

- **Бинарь**: `$F/bin/b4` = **rc9**, sha256 `2820b208e6eb2d4c2b5b4e708be67603b34f16056a992e9f85e81315ad2a2186` (собран до ppe-кода).
- **Конфиг**: `/opt/etc/b4/b4.json` = **fake-quic**, md5 `76d9353692f5fa80f29233875c6e22b9`. Локальная копия: `D:\b4x\b4.fake-quic.json`.
  - Живые YouTube-сеты: `combo-timestamp` (`211bf07f`, API) и `youtube-video` (`9b31cb9b`) — `udp.mode: "fake"` (не reject). Также включён `youtube-ui`.
  - Нет: `offload_policy`, `logging.directory`, `desync`, `reassembly`, strategy-catalog.
  - `faking: {sni_type: 3}`.
- **Лог baseline**: `/tmp/b4.log` (tmpfs). S99b4/rc.func шлёт stdout в `/dev/null` — без ручного nohup лог пропадает.
- **Маркеры в логе**: `Sending fake UDP packet 6/6`; `Using fake SNI payload of 1573 bytes` + `Sending fake SNI packet 1/1`; `Sending TCP packet with fragmentation strategy: combo`; `Loaded targets: 37 domains, 12 IPs across 12 sets`.
- **Дестрой фейка на baseline**: AutoTTL (`dynamicTTL` = realTTL−1). badsum в коде есть, в этом конфиге **выключен**.
- **PPE на baseline**: не активен и для rc9 это норма. `iptables -t mangle -L B4_PPE_PRE -n -v` пусто. Хук `/opt/etc/ndm/netfilter.d/94-b4-ppe-reconcile.sh` висит, rc9 USR1 игнорирует.
- **Что baseline НЕ закрывает**: зависание ванили при seek / TCP-медиа googlevideo (ECH). ReVanced/QUIC-путь живой.

`$F` = `/tmp/mnt/37fdc502-d92b-dd01-3075-c402d92bdd01`

### Сломанные компоненты — не возвращать

| Что | Отпечаток | Почему нельзя |
|---|---|---|
| GUI-бинар с выбором папки логов | sha/md5 префикс `43b5042b`, `30d4208b` | FD-утечка, 4095/4096, `accept4: too many open files` |
| Конфиг с `offload_policy: "exclude"` | `b4.json.gui-exclude` и аналоги | b4 перестаёт маскировать 443; PPE ютуб не маскирует |
| reject-конфиги youtube-video | `b4.json.v3ppe`, `b4.json.reject-backup` (md5 ≠ `76d93536`) | `udp.mode=reject` убивает QUIC-путь |
| `sni_mutation` / substitute | T8, rc13 | TLS 1.3 transcript mismatch, `SEC_E_DECRYPT_FAILURE` у ванили |
| Левые/автономные утилиты тестирования | `warpscan`, `warpfieldprobe`, `nc` и др. для полевых вердиктов | СТРОЖАЙШЕ ЗАПРЕЩЕНО. Шлют голые пакеты/упрощённый код без полного боевого стека маскировки b4 (uTLS, QUIC I1, AWG, NFQ). Все полевые тесты туннелей — ИСКЛЮЧИТЕЛЬНО через боевой бинарник b4 (`b4.exp-*`) с тестовым конфигом! |

Подозрение «FD-утечка сидит в HEAD» — **не доказано**. Доказана только утечка у GUI-бинарей выше.

---

## 3. Почему ходили по кругу

Сессия `quiet-garden` (`b4x_field_validation_agent_pack.json`): ~3710 сообщений, модель deepseek-v4-flash-free, ~20M input tokens. Старт — кампания L0–L8 из `B4X_HARDWARE_FIELD_VALIDATION_AGENT_INSTRUCTION.md`. Дальше — живой YouTube. Итог: одни и те же симптомы каждый день, стек не зафиксирован.

Повторяющийся цикл:

1. Включить сразу T1+T2+T3 на живом бинаре.
2. Ютуб тупит / seek виснет / интерфейс не грузится.
3. В логе: «SNI не маскируется», «reassembly off», «PPE непонятно».
4. Подкрутить конфиг. Короткий проблеск.
5. Не зафиксировать sha/md5/маркеры.
6. Следующий деплой затирает живое. Появляется FD / `/tmp` ENOSPC / `exclude`.
7. Откат на rc9. Агент «заново открывает» то же самое.

Корневые причины (не «агент глупый»):

1. **Цель и baseline свалены в одну фразу.** «Включи Fake SNI + PPE» читается как настройка, а не как пять задач.
2. **Брошюра принимается за факт.** Дизайн говорит badsum+PPE. Поле говорит AutoTTL без PPE + QUIC. Агент пытается подогнать поле под брошюру и ломает YouTube.
3. **Нет изоляции эксперимента.** Живые `/opt/etc/b4/b4.json` и `$F/bin/b4` перезаписываются.
4. **Ложные маркеры.** Цепочка `B4_PPE_PRE` ≠ PPE помогает YouTube. Строка `Sending fake SNI` ≠ SNI разрезан в pcap. «Ютуб открылся» ≠ seek. curl с ПК ≠ Android Cronet.
5. **Несколько багов как один.** ECH, split ClientHello, ENOSPC лога, FD-утечка, `exclude`, запрет mutation — разные тикеты.
6. **Документы противоречат друг другу.** `PROJECT_DIRECTIVES`, `.ag/findings.md`, `.ag/state_packet.md`, пустой `PPE.md`, кампания L0–L8. Агент читает любой и стартует из чужого мира.
7. **Кампания валидации всего продукта** (WARP, detector, FaultLab) смешана с отладкой YouTube на `.152`.

Запрещено в YouTube-сессии: запускать L0–L8 из `B4X_HARDWARE_FIELD_VALIDATION_AGENT_INSTRUCTION.md`. Этот pack — стенд и доступ, не текущий план.

### SEEK STALL — поле 18.08.2026 (не открывать заново)

Полная лестница слоёв и тактики A/B/C: `YOUTUBE_DATAPLANE.md`. Ниже — исходный разбор handoff, его не переоткрывать.

Симптом: интерфейс и начало ролика быстрые; прыжок на середину **длинного** ролика — зависание. Стек в момент замера: rc9 + fake-quic, PPE выкл., лог на флешке.

Доказательство в `$F/b4/log/b4.log` ~20:16 UTC, клиент `.152` / `22:30:F3:33:62:27`:

- QUIC на `rr1---sn-4g5edndd.googlevideo.com` → `172.217.133.166:443`: `sni-set=youtube-video`, `Sending fake UDP packet 6/6`.
- Через секунды TCP на **тот же IP** (`:44154`, `:49352`, `:44054`): нет hostname, `No domain yet for TLS connection … ignoring`, в INFO нет `sni-set`. Fake SNI не уходит.
- То же для `172.217.133.198` и `142.251.39.129`.
- Строк scoped/learned hint нет. В `b4.fake-quic.json` нет `system.classifier.flags`.

Вывод: старт идёт по QUIC (маскируется). Seek открывает TCP/ECH на уже известный googlevideo-IP; классификатор не переносит QUIC-SNI на TCP.

Что **не** делать (уже проверено этой ночью):

- `targets.ip` на `172.217.0.0/16` + `syn_fake` + `offload_policy=exclude` (`b4.json.v2c`) — ютуб стал хуже, Gmail/News под ударом.
- Чинить `clean SYN` через SSYN. На rc9 после clean SYN ClientHello **приходит** (`TCP payload len=480` + `Sending fake SNI packet 1/1` на youtubei).
- `No domain yet` — это `capture.Manager`, не выбор стратегии. Признак «имени нет», не причина.

Что делать: флаг HEAD `system.classifier.flags.quic_tcp_handoff_enabled` (`src/nfq/quic_handoff.go`, TTL 90 с, тот же client+IP, proto 6). Не google-диапазоны.

Гейт: после seek на TCP к тем же IP есть `sni-set=youtube-video` или fake SNI; владелец: середина длинного ролика не виснет; Gmail жив.

**Поле 18.08 ~20:33 UTC (exp-handoff LIVE, владелец):** PARTIAL.

- Ваниль = ReVanced. Gmail и приложение Google **живы** (изоляции google `/16` не делали — правильно).
- Часть роликов seek OK, часть зависает.
- В логе handoff **работает**: `strategy=scoped-hint` + `quic_sni` + TCP googlevideo с `sni-set=youtube-video` + `Sending fake SNI`. Все TCP-IP googlevideo из этого окна уже встречались на QUIC того же клиента.
- Остаток: `ECH fallback remains non-final` (53 раза); `No domain yet` на IP, которые **потом** получают сет (гонка: первые пакеты до hint); TCP youtubei `172.217.113.4` сначала без set. Видео, где seek сразу бьёт в **новый** CDN-IP по TCP/ECH до любого QUIC/DNS hint — handoff не поможет.
- **Поле 18.08 ~20:43–20:46 UTC (exp-dnshint):** UX как у handoff: в целом быстро, часть seek всё ещё виснет. В логе **ноль** `dns_answer` / `DNS query` / `DNS redirect` после старта. Телефон не отдаёт YouTube-резолв в UDP/53 (кэш / Cronet DoH / имя приходит из youtubei). Hint из DNS **не участвовал**. Все `scoped-hint` снова только `quic_sni`. Флаг не вредный, но seek не закрыл. Не путать с «dns hint проверили и он слабоват» — его просто нечем было кормить.

### Очередь проверок (не «оставим как есть»)

Продукт не готов, пока не пройдены **по одному**:

| Порядок | Что | Зачем | Не смешивать с |
|---|---|---|---|
| 1 | `quic_tcp_handoff` | TCP на IP, который клиент уже видел по QUIC | — уже LIVE, PARTIAL |
| 2 | `scoped_dns_hints` | TCP/ECH на **новый** IP из **видимого b4 DNS** | прогнан 18.08: флаг ON, **0 DNS-ответов** с телефона — инертно. Не считать seek-фиксом |
| 3 | `syn_fake` | явная SYN-техника (не «оставить CH в очереди») | только после 2; не google `/16`; не exclude |
| 4 | PPE window (`detect`, не exclude) | второй сегмент CH в NFQUEUE | только после L2-бинаря и 1–2; никогда exclude |

«Оставим как есть» значило: не откатывать удачный handoff. Не значило «PPE и syn_fake выкинуть».

---

## 4. LADDER — один слой, один деплой, один вердикт

Живой стек = baseline, пока слой не прошёл гейт. Эксперимент = **копия** бинаря `$F/bin/b4.exp-<слой>` + копия конфига `/opt/etc/b4/b4.json.exp-<слой>`. sha/md5 записать сюда **до** старта.

### L0 — здоровье (каждая сессия, 2 минуты, без правок)

1. `pidof b4` и `ls /proc/$(pidof b4)/fd | wc -l` → fd < 200. 4095+ = утечка, стоп, откат на rc9.
2. `md5sum /opt/etc/b4/b4.json` → `76d9353692f5fa80f29233875c6e22b9` (или новый референс, если слой принят).
3. `sha256sum $F/bin/b4` → `2820b208…` (или новый референс).
4. `df -h /tmp` — не 100%. Иначе лог врёт.
5. При трафике YouTube растёт `Sending fake UDP` (или эквивалент на новом лог-пути).
6. `iptables -t mangle -L B4_PPE_PRE -n -v | wc -l` → 0 на baseline. Если >0, это уже не rc9 — свериться со слоем, не «чинить наугад».

Если L0 красный — чинить здоровье, не YouTube.

### L1 — только логи на флешку

- Менять: `system.logging.directory` = `$F/b4/log` на **копии** fake-quic. Бинарь: либо rc9 (если пишет directory), либо отдельный `b4.exp-logdir` = HEAD log-фича **без** PPE apply и **без** `offload_policy`.
- Не менять: сеты, faking, udp.mode, PPE.
- Гейт: fd стабилен < 200 десять минут; лог растёт на флешке; fake UDP/TCP маркеры как у baseline; YouTube не хуже baseline (ваниль+ReVanced, 1 ролик + seek).
- Провал: откат конфига, бинарь в «сломанные».

### L2 — новый бинарь на том же конфиге, PPE выключен

- Цель: HEAD (или выбранный коммит) ведёт себя не хуже rc9.
- Конфиг: тот же fake-quic. Никакого apply PPE, никакого exclude.
- Гейт: fd < 200; те же маркеры маскировки; curl youtubei 405/200; поле `.152` не хуже rc9.
- Провал: стоп. Не включать PPE «чтобы починить регресс».

### L3 — классификатор (настоящий YouTube-баг)

Чинить по одному, с pcap на флешку (`tcpdump -i eth3 -w $F/cap.pcap`, не в `/tmp`):

1. Split ClientHello (~1396+хвост) → SNI из первого сегмента / observe-reassembly. Код: `f98b3c6f` (lenient SNI) — проверить **на поле**, не считать закрытым по unit-тесту.
2. Seek-stall (поле 18.08): TCP на IP, который секунду назад был QUIC googlevideo, без SNI. Эксперимент: `quic_tcp_handoff_enabled`. DNS HTTPS type 65 — отдельный шаг, если handoff не закроет ванильный ECH на **новом** IP.
3. DNS → first-flow этого клиента, не глобальный learned-IP.

Гейт L3: в pcap/логе первый flow `.152` к API / UI / googlevideo получает **свой** сет до backoff Cronet. Не «ютуб потом открылся».

Запрещено на L3: `sni_mutation`, подбор pastseq/timestamp руками (это не лечит выбор сета).

### L4 — доказательство Fake SNI Desync

Отдельно AutoTTL (уже на baseline) и отдельно badsum. Не оба в одном деплое.

Доказательство только тройкой:

- лог: fake + combo на первый CH;
- pcap WAN: в одном TCP-сегменте нет целого `youtube`/`youtubei`; fake не собирается сервером (TTL или csum);
- клиент: нет `bad_record_mac` / decrypt failure.

«Sending fake SNI packet 1/1» само по себе — не PASS.

### L5 — PPE как окно рукопожатия, не как «ускоритель YouTube»

Смысл (addendum + z2k): железо не должно уводить поток до второго сегмента CH / ретрансмита / ServerHello. После окна — bulk можно в PPE.

- Штатная реализация b4 (`src/capture/ppe`) — lifecycle, selftest, reconciler, NDM-хук. Scope: ipset `b4_managed_devices`, порты из конфига.
- Эталон z2k: та же форма правил (`-m connskip --connskip 30 -j PPE`), шире порты и все клиенты.
- **Не включать оба.** Наш apply требует каноничности (наши jump первые). z2k на роутере установлен, сейчас не должен крутить свой deoffload.
- **Никогда `offload_policy=exclude`**, пока L4 не PASS. Exclude = «PPE замаскирует» — PPE не маскирует.

Гейт L5: счётчики `B4_PPE_PRE` растут; в NFQUEUE виден **второй** сегмент CH (этого не было бы без окна); маскировка L4 не деградировала; YouTube не хуже L2.

### L6 — изоляция

Gmail / Google News / прочие Google-приложения на `.152` живы при включённых YouTube-сетах. Регресс = FAIL слоя, даже если YouTube идеален.

---

## 5. Контракт сессии

1. Начать с L0. Состояние роутера из прошлого чата — протухло, перепроверить.
2. Открыт ровно один слой лестницы. Записать его в «Открытый эксперимент» ниже **до** деплоя.
3. Не перезаписывать живые `$F/bin/b4` и `/opt/etc/b4/b4.json`. Только `.exp-<слой>`.
4. Вердикт слоя: PASS / FAIL / BLOCKED + sha бинаря + md5 конфига + 3 маркера + наблюдение пользователя (ваниль / ReVanced / seek / Gmail).
5. FAIL → откат на baseline за минуту, отпечаток в «сломанные». Не чинить поверх.
6. PASS → обновить раздел 2, закрыть слой. Следующий слой — только в новой сессии или после явной команды.
7. Пользователь на `.152` — источник UX. Агент не объявляет «YouTube работает» по curl с `.40`.
8. Не коммитить и не пушить без прямой просьбы.
9. Игнорировать противоречащие `.ag/state_packet.md`, `.ag/summaries/session_summary.md`, `.ag/findings.md`, если они старше этого файла. Этот файл главнее.

### Что считать доказательством

| Утверждение | Мало | Нужно |
|---|---|---|
| PPE работает | цепочка есть / selftest PASS | окно: второй CH-сегмент в NFQUEUE + счётчики + YouTube не хуже |
| Fake SNI работает | строка в логе | pcap: имя разрезано, сервер не принял fake, клиент без bad_record_mac |
| Сет применился | домен есть в json | первый flow `.152` классифицирован до backoff |
| Логи на флешке | ключ в конфиге | fd лог-файла на `$F/b4/log/b4.log`, рост при трафике, `/tmp` не забит этим логом |
| Seek живой | «один раз не зависло» | ваниль + ReVanced, середина ролика, повторно |

---

## 6. Команды / доступ

- SSH: `192.168.1.1:222` (`python "$env:TEMP\opencode\rrun.py" 'cmd'`; rssh.py удалён — rrun.py). PowerShell не раскрывает `%TEMP%` — только `$env:TEMP`. Для кириллицы в выводе: `$env:PYTHONIOENCODING='utf-8'`. UTC+5.
- Деплой: `python %TEMP%\opencode\ssh_cat.py <local> <remote>` (dropbear без sftp). Скачать: `python %TEMP%\opencode\fetch.py <remote> <local>`.
- `/tmp` = tmpfs ~243MB. pcap и бинари — только на флешку `$F`. Чистка: `rm -f /tmp/b4.*.log /tmp/*.pcap`.
- Сборка arm64 только docker (`-v` ломается, нужен `--mount`):

```text
docker run --rm --dns 8.8.8.8
  --mount type=bind,source=D:\b4x,target=/src
  --mount type=bind,source=C:\Users\AlexZander\go\pkg\mod,target=/go/pkg/mod
  -w /src/src golang:1.25.3-alpine
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFLAGS=-mod=mod
  go build -trimpath -ldflags "-s -w -X main.Version=1.0.0 -X main.Commit=local -X main.Date=20260817"
  -o ../out/linux-arm64/b4 .
```

- Тесты в том же контейнере: `go test ./config/ ./sni/`.
- Проба с ПК: `curl --resolve youtubei.googleapis.com:443:<IP> https://youtubei.googleapis.com` → 405/200 = обход жив; 000 = блок или флоу не дошёл до b4.
- Устройства: `.152` `22:30:F3:33:62:27`, `.40` `BC:FC:E7:B5:F5:8E`. WAN `eth3`, SNAT `192.168.0.50`.
- API (когда бинарь его слушает): `http://127.0.0.1:7000` / `http://192.168.1.1:7000`. PPE rollback: `POST /api/v1/capture/offload/rollback` + Idempotency-Key + expected_generation.
- Эталон PPE: `D:\netcreaze\z2k` (читать, не включать рядом). Полевые заметки: `B4X_FIELD_VALIDATION_AGENT_PACK/PPE.md`.

---

## 7. Pitfalls — симптом → причина → что делать

1. **Видео/seek виснет, fake UDP идут** → TCP googlevideo без стратегии (ECH / split CH). Не «включай PPE». Это L3.
2. **Mapped падает, fake UDP умирает, PUT висит** → FD-утечка GUI-бинаря. Откат на rc9. Чеклист п.1.
3. **000 после «включили PPE»** → почти всегда `offload_policy=exclude`, не форма правил. Снять exclude. Форма правил = z2k, это уже проверяли.
4. **b4 жив, лог молчит** → `/tmp` ENOSPC, флашер глотает ошибки. `df -h /tmp`, чистить. Не диагностировать маскировку по мёртвому логу.
5. **fake UDP нет при `udp.mode=fake`** → подменили конфиг на reject или бинарь не тот.
6. **«reassembly всегда off»** → дефолт `ReassemblyOff`. Ключ в json без полевого pcap не закрывает тикет. Слой L3.1, не «добавь во все конфиги и идём дальше».
7. **Ваниль decrypt failure после substitute** → T8, не повторять mutation.
8. **Агент снова гоняет L0–L8 / FaultLab / WARP** → не эта работа. Вернуться к открытому слою лестницы.
9. **После деплоя RST/steer-класса тормозит даже старт видео** → активная помеха doomed-флоу сама портит UX: RST = шторм ретраев новыми tuple (22.08 v1), молчаливый SYN-drop = kernel-backoff тех же tuple, limbo дольше базы (22.08 v2). Steer-семейство закрыто, `YOUTUBE_DATAPLANE` §7. Лечится только откатом на holdch3/nosplit.
10. **«Откат на holdch3» скопировал `$F/bin/b4` и получил rexmit `b08a8c87`** → на флешке `$F/bin/b4` = rexmit, НЕ holdch3! Live восстанавливать только из `$F/bin/b4.exp-holdch3` (`666eb175…`), sha сверять ДО старта S99b4. Полная инвентаризация архивов: sha256sum $F/bin/b4*.
11. **AWG data-path «висит» на TLS через туннель** → Go 1.24+ по умолчанию шлёт post-quantum `X25519MLKEM768`, что раздувает TLS-рукопожатие (~1.2 КБ) за **бюджет внешнего UDP-потока WARP (~3–4 КБ)**. Это НЕ «блэкхол ISP» и НЕ gVisor. Фикс: пин классических кривых (`X25519`,`P-256`) + профиль **`vanilla-off`** (junk/I1 съедает бюджет). Улики/рецепты: `.ag/summaries/awg-session-2026-09-18.md`, `bd b4x-nxx` (закрыт).
12. **`ssh_cat.py` портит бинарь** (`data.replace(b"\r\n", b"\n")`) → деплой бинаря ТОЛЬКО через base64: локально base64 → `ssh_cat.py <file.b64> <remote.b64>` → на роутере `base64 -d … > bin && chmod +x`, сверить sha256.
13. **На роутере нет `timeout`** → `nohup timeout N tcpdump …` молча не стартует (pcap не создаётся). Запускать `nohup tcpdump … &` и убивать вручную. Также rrun теряет хвост при фоновом `nohup … &` — `S99b4 start` всегда отдельным SSH-вызовом.
14. **Голый WG/WARP-поток душится средой — нужен QUIC-Initial (I1).** Доказано A/B референсом `wireproxy-awg` с ключами b4 на `.40`: vanilla → trace пусто, bulk 10 МБ = 0; с полевым QUIC-I1 (1250 Б, маркер `44d0`) → **10 МБ/0.82 с = 12.2 МБ/с**. Прежний вывод «`vanilla-off` — рабочий профиль, junk съедает бюджет» **опровергнут**: он был артефактом малого trace. Не выбирать `vanilla-off` для реального трафика.
15. **`quici1.Build` (runtime-I1 профиль `cf-quic-cover`) даёт НЕрабочий Initial** (на проводе `c1 00000001 80 …`, маркер `44d1`), с ним b4-trace всегда падает. Рабочий — точный полевой blob из `D:\b4x\wireguard\Nova\awg\WARPv1_14.conf` (I1, 44d0). Добавлен seed-профиль **`cf-field-i1`** (`src/transport/wg/profiles.go`); пиновать его `system.warp.awg.profile`.
16. **`ip rule pref 2: from all lookup main` перекрывает tproxy-марки** (`3: fwmark 0x… lookup 252`) → TPROXY-пакет уходит по main вместо локальной доставки, клиентский поток блэкхолится. Снимать `ip rule del pref 2` перед прогоном (найти источник — `b4x-36d`). Ещё не закрыто: accepted TPROXY-client-сокет не отдаёт данные приложению (ClientHello ретрансмитится, нет ACK; `tunnel dial OK`, но `pipe client→upstream` пуст; `-m socket --transparent … ACCEPT` матчится). Диагноз/план — `bd b4x-36d`.
17. **Kernel-mode AWG (`mode=kernel`) на этом роутере не поднять как есть:** BusyBox `ip` без `not fwmark`, таблицы ≤255, FORWARD DROP, нужен SNAT/LAN-bypass; и bootstrap kernel-режима шлёт пробник не в ту сторону. Часть починена (см. дерево), bootstrap — `bd b4x-e5c`.
18. **TPROXY на порт 443 блэкхолится Keenetic NDM:** NDM ставит в **mangle INPUT** `-A INPUT -p tcp --dport 443 -j _NDM_HTTP_INPUT_TLS_` → `_NDM_HTTP_INPUT_TLS_PASS_` c финальным `-j DROP` (TLS-SNI allowlist). Mangle INPUT идёт **до** filter INPUT, поэтому помеченный TPROXY-пакет (ClientHello 443) падает там раньше b4'шного mark-accept (`iptables -I INPUT` = filter). Симптом: `.40` шлёт CH и ретрансмитит, роутер не ACK-ает; rx_queue=0; conntrack = только SYN+ACK (packets=2); пакетов в OUTPUT от сокета нет. **Диагностическое отличие:** port sweep к той же цели — 443 FAIL, а 8443/9999/2053 PASS (NDM трогает только dport 443). Лечение (в дереве, `bd b4x-36d`): ставить per-mark ACCEPT и в **mangle INPUT** (`src/tables/routing_proxy.go: addProxyInputAccept`). Не путать с PPE offload — тот исключён полем (флаш B4_PPE_* не помогал).
19. **`web.telegram.org` не работает через telegram-сет (`mode=mtproto-ws`), и это НЕ регресс.** `web.telegram.org` резолвится в **IP дата-центра** Telegram (`149.154.167.99`), его ловит telegram-сет на 443 и отдаёт в MTProto-мост; обычный HTTPS/WSS мост не несёт. Generic-туннель (`FailOpenViaWorker`, `/apiws?dst=&port=`) умеет **только свой** CF Worker (`system.mtproto.cf_worker_domain`), которого в live пуст. Публичный cfproxy-пул (`Flowseal/tg-ws-proxy`, `kws<N>.<domain>`) релеит **только MTProto по `kws<N>`-префиксу** (A-записи на IP DC) и generic-путь отвергает (`414`/`503`) — проверено полем (`bd b4x-0z7`, коммит `143c85ef` дормантный). A/B: без mangle-фикса — timeout 14 с, с фиксом — reset 10 с; сломано в обоих.
20. **Tunnel-режим «по домену».** `netstack v1` (warp/MASQUE) резолвит имена **in-tunnel DoH** (`NetstackCarrier.WithDoHResolver`/`resolveV4`/`DialStreamHost`, `MasqueCarrier.DialStreamHost`; дефолт `https://1.1.1.1/dns-query`, коммит `a7565e47`, `bd b4x-4cl`); резолвер tproxy использует `hostDialer`-шов. **AWG-карьер** (`routing.tunnel=warp`, канарейка) пока диалает только литеральные IPv4 — `bd b4x-1ev` (его gVisor-netstack уже с `DNS=1.1.1.1`). **`b4x-1ev` ЗАКРЫТ 19.09:** AWG-карьер реализует `DialStreamHost` (in-tunnel DNS нетстека, первый IPv4) — tunnel-сеты могут целиться в домен.
21. **Канарейка/тест-конфиг без правки живого `b4.json`:** `S99b4` запускает `/opt/sbin/b4 --config=/opt/etc/b4/b4.json --log-dir=<USB>/b4/log --verbose=trace`. Для тест-конфига: `S99b4 stop` → вручную `nohup /opt/sbin/b4 --config=<копия> --log-dir=<USB>/b4/log --verbose=trace >/dev/null 2>&1 &` → вернуть `S99b4 start`. Живой конфиг не трогается.
22. **`tproxy: tunnel carrier "<kind>" is not registered for set X` на старте — НЕ регресс:** карьер регистрируется на ~1–2 с позже tproxy `SyncConfig`; сет остаётся fail-closed и затем открывается (`listening on … for set X`).
23. **Промоут/правка живого `b4.json`:** пишется Go `encoding/json` (2 пробела; порядок полей структур, НЕ глобальная сортировка). Правка — python-скриптом с сохранением порядка + проверка `git diff --no-index` (ждём чисто аддитивный дифф); restore point (бинарь+конфиг) на флешку ДО замены; репетиция `promote→restore→promote`. `bd close` отказывает при искусственном блокере — `--force`.
24. **CF API drift: `client_id` — base64, не hex.** `/v0a4471` теперь отдаёт `client_id` как 4-символьный base64 (3 байта reserved); старый WG-мост `bridgeClientID` ждал длинный hex и падал `not decodable hex` (фикс `7dadf6dc`: 4-char → base64, иначе hex). **Enrollment из домашней сети:** `api.cloudflareclient.com` SNI-фильтруется, а enroll-клиент proxy-env-free (`HTTP_PROXY` не помогает) — но регистрацию можно прогнать **через свой живой `warp-tunnel`**: добавить A-записи API (`104.16.192.82`, `104.16.24.84`) в `targets.ip` сета и запустить инструмент с `.40` (`--add-host api.cloudflareclient.com:104.16.192.82`); улика — `sni-set=warp-tunnel [tunnel:warp]` + `tunnel dial OK`. Инструменты: `cmd/warpenroll` (MASQUE), `cmd/awgenroll` (AWG). Слоты nested-пар по умолчанию: `/opt/etc/b4/warp/chain-<kind>-{outer,inner}.json`.
25. **Nested-пары (FIELD3, `.ag/research/field3-report.md`).** ~~РАЗНЫЕ assigned-адреса~~ **ОТМЕНЕНО (`b4x-w96`):** слои в РАЗНЫХ netstack, поэтому общий CF-адрес `172.16.0.2` — не коллизия (подтверждено `warpscout/nest.go`); правило `nested.go:143` удалено, хак `wg_assigned_v4` больше не нужен. Chain-слоям **ЗАПРЕЩЕНО** переиспользовать одиночные слоты — нужны выделенные `chain-<kind>-{outer,inner}.json`. **События цепочек логируются только если в `main.go` передан OnEvent** (`ddbee0c3`). `W+M`: identity-блок снят `DeferRevalidation` (`4863f5a4`), остался nested-MASQUE data-path (`b4x-e74`). **Стабильность nested-outer:** пассивный rx-idle (`session.go:81`, дефолт `max(30s, 3×keepalive)`) ложно режет тихий outer каждые ~30 с; blanket-`RXIdle` ЛОМАЕТ детектор смерти WAN (`TestE2EWgMasqueKillWAN`) → нужен **активный inner-probe** (путь `zapret-gui/warp_in_warp_watchdog.py`), отдельный слой. `НЕ-РФ` — все verified-`RegionalPools` = RU-выходы (`b4x-rnn`).
26. **Nested-outer data-path: junk vs data (`b4x-mrl`, коммит `48cac81e`).** W+W-outer **обязан** иметь активный junk-профиль (`ErrOuterObfRequired`), а его дефолт `DefaultJunkActiveCfWarp()` = `quic-a` (Jc=4 со своей fake-QUIC приманкой) — и **junk душит WARP data-path** в этой среде (прямо сказано в `config/awgwarp.go:303`), т.е. outer встаёт, но TCP/данные не идут (пробы `dial_fail`, `outer_rx_delta=0`). ФИКС: профиль **`cf-field-i1-j4`** = проверенный `cf-field-i1` (44d0, 1250 Б) INIT + минимальный Jc=4 junk (эталон `wireproxy`: Jc=4+I1 = 8.1 МБ/с); дефолт W+W предпочитает его. Плюс inner-liveness-проба (`transport/wg/liveness.go`, TLS через INNER каждые 10 с) кормит rx-анкер outer (~3.6 КБ/пробу) → ложных `rx-idle` нет. Поле: `hs_ok=true`, `parent_lost=0` (было каждые ~33 с). Пассивный watchdog не менялся (`TestE2EWgMasqueKillWAN` жив). **Дефолт chain-AWG-слоя** теперь `cf-field-i1` (для `awg+awg` — `cf-field-i1-j4`) вместо ladder-head (`vanilla-off`/`quic-a`), коммит `f6760dcc` (`b4x-e74`): с ним W+M inner-MASQUE подключается (`warp_masque_connected h2`), иначе — вечный `connect-ip-timeout`. Остаток W+M закрыт: feeder-probe перенесён в `WgMasqueRuntime` (`b4x-sce`, коммит `095847b3`) → W+M `warp_masque_connected h2`, `parent_lost=0`. **4-я пара M+M (`masque+masque`) — FAIL/BLOCKED_EXPERIMENTAL** (`b4x-ive`): наш M+M = **запрещённая H2-в-H2** (chain-outer без `Dialer` → legacy H2, inner TCP-only `nsDialThrough`). Референс `zapret-gui/warp_in_warp.py` **прямо запрещает H2-в-H2** и требует **H3-in-H3** (performance/auto), inner принудительно H3. Вариант «outer→H3» проверен (`b4.exp-nm14`) — **не помог** (inner `tls-timeout`/`connect-ip-timeout`). Корень: наш nested-carrier **IPv4/TCP-only** (`SupportsUDP=false`), inner не может уйти в H3 (QUIC/UDP). ФИКС = UDP-поверхность nested-carrier (netstack v2) + H3 у inner. До этого M+M — `BLOCKED_EXPERIMENTAL`; `b4x-4sk` снова открыт. НЕ-РФ (`b4x-rnn`) — по-прежнему открыта.
   **b4x-ive поле 19.09-7 — M+M = PASS (H3-in-H3).** Два корня, оба конфигурационные: (1) **фрагментация inner-QUIC** — quic-go `InitialPacketSize=1280` → inner-IP 1308 B > outer-MTU 1280; фикс **`H3InitialPacketSize=1200`** (`SessionConfig`→`H3SessionConfig`→`quic.Config.InitialPacketSize`); улика: до фикса `egress udp len=1276(+52)`, после — 61× `egress udp len=1228`, фрагментов нет. (2) **chain-outer слал КАНОНИЧЕСКИЙ MASQUE-SNI** → эдж блэкхолит data-phase (b4x-5oy) → outer-H3 `data-plane-validation-timeout` (handshake 200 DME, данных нет) и inner молчал; фикс — outer-template `SNI = system.warp.masquerade.EffectiveSNI()` (+Fingerprint), тот же cover, что у standalone MASQUE-карьера. Поле: outer+inner `warp_h3_negotiated 200` + `warp_masque_connected transport=h3`, `warp_nested_child_revalidated gen=1 outer_netstack=attached ctrl=h3-udp-through-outer`, стабильно >3.5 мин, `parent_lost=0`, egress=45/inbound=51 (было 8/99). Кандидат `$F/bin/b4.exp-ive3` (`fff570bc`). Диагностика env-gated `B4_NETSTACK_UDP_DBG`/`B4_H3_DBG` (stdout). Отчёт `field3-report.md` §7. ВЫВОД: «среда WARP/бюджет 3–4 КБ» был НЕ корнем. ОСТАТОК: перепроверить M+W/W+M/W+W после cover-SNI (правка общая для outer-ветки, но только улучшающая); не-RU (`b4x-rnn`) — BLOCKED.
27. **b4x-s2x / b4x-d69 (19.09-6).** Прод-линия — **HEAD-based** (решение `s2x`, doc `.ag/research/promote-binary-policy-2026-09-19.md`): rebase на anchor `9ab2c733` срезал бы `cd153f04` (gvisor bump — пререквизит AWG data-path) и весь AWG/WARP-стек; dormant `143c85ef` (0z7) already-live/guarded. **MASQUE-карьер рабочий как routing-consumer** (`d69` PASS): scoped `.40` → `sni-set=<set> [tunnel:masque]` + `tproxy: tunnel dial OK`. **Грабли:** (1) docker-сборка arm64 без `-e GOOS=linux -e GOARCH=arm64` даёт amd64-бинарь → на роутере `ENOEXEC` («syntax error» от shell) — всегда задавать env сборки; (2) `killall/pidof b4` матчат по ИМЕНИ: тест-бинарь `b4.exp-*` не убивается `killall b4`, запускать как `/opt/sbin/b4` или убивать по точному имени; (3) router-OUTPUT `curl` к target-IP сета загрязнён NFQUEUE-классификатором (`clean TCP SYN ... accepted`) — canary проверять только на трафике scoped-девайса; (4) `$F`/`$(...)` нельзя раскрывать при вложенном квотинге PowerShell↔docker↔ssh (использовать launcher-скрипты).
28. **b4x-rnn — не-RU WARP через SOCKS5-egress (19.09-8).** **WARP egress country — CONNECTION-level, не account-level и не endpoint-level** (уточнение формулировки в `transport/wg/endpoints.go`): регистрация через не-RU SOCKS5 + прямое подключение → `loc=RU`; но **проведение MASQUE-H2 (TCP) через не-RU SOCKS5** → CF видит IP прокси → `loc=GB colo=LHR warp=on`. **РЕАЛИЗОВАНО (`b4x-w4c`):** конфиг-поле **`system.warp.socks5`** (`host:port` | `socks5://[user:pass@]host:port`; валидатор `ValidateSocks5`), применяется в `warpservice` (H3-ладдер байпасится — SOCKS5=TCP); env `B4_WARP_SOCKS5` остаётся полевым сеамом. Поле-гейт через КОНФИГ (без env): `warp_masque_connected transport=h2 colo=LHR` + trace `loc=GB warp=on`. Routing: scoped-сет `"tunnel":"masque"` (карьер `kind=masque`, proven `b4x-d69`) → выбранный трафик идёт через не-RU WARP. Ограничение: SOCKS5=TCP (UDP/QUIC не идёт; для `.40` `warp-tunnel` и так `upstream.udp=false`); прокси = узкое место. Doс `.ag/research/nonru-warp-socks5-2026-09-19.md`. Остаток: owner-гейт `loc≠RU` на живом `.40`-трафике; UDP-не-RU — reserve (Opera/Proton).

29. **E-FXVPN: эдж Fastly-masque `23.235.42.0/24` заблокирован по ПРЕФИКСУ — SNI/hello-маскировка бессильна.** Поле (`b4x-auj`, 20.09): server-list и Guardian из РФ **доступны**, но голый TCP (`nc`, без TLS) к `23.235.42.1/.11/.39` на `:80`/`:443`/`:2499` → `No route to host` (ICMP host-unreachable), тогда как другие Fastly (`146.75.117.x`, `151.101.x`) и `8.8.8.8:443` живы; DNS чистый (локальный резолвер и `8.8.8.8` отдают одно). TLS с SNI `p.m1.fastly-masque.net` к **доступным** Fastly-IP проходит (`421 Misdirected`), но `:2499` там не слушается. ⇒ это **L3-блок адреса**, а не сигнатура: `sni_mutation`/fake-SNI/Initial-padding пакет не доставляют. **Диагностика: `nc IP PORT` без TLS; «No route to host» ≠ «DPI режет по SNI».** Лечится только сменой пути — **вложением (carrier nesting, дизайн §7.5)** или сменой вендора. Поле: `fxvpnctl --base awg` (отдельный CF-device `chain-awg+awg-outer.json`, `8.39.204.9:7103`, `cf-field-i1`) → `nested=true carrier=h2`, выход `loc=DE`/`loc=BR`, 12/12 HTTP 200, fd 10–11.

30. **`fxvpservice.Runtime.loop` (и демонская проводка `main.go:953`) не вызывали `pool.Bootstrap` — fxvpn-пул навсегда `provisioning`/`blocked`.** `NewPool` заводит аккаунты в `StateProvisioning`, а `RotateIfDue` такие места намеренно пропускает: переводит в `active` только `pool.Bootstrap()`. Поле дало `pool_blocked=true` при полностью здоровом аккаунте (refresh+Guardian ок, quota 50 ГиБ). Фикс: в `loop` вызвать `r.pool.Bootstrap(ctx)` перед первым `tick` (проверить и демонскую проводку).

31. **Тест-инстанс b4 с ЖИВЫМ конфигом на Keenetic → watchdog software reset (ребут роутера).** Поле 22.09 (AFS Gate A): `S99b4 stop` → `nohup <тест-бинарь под именем b4> --config=<копия live>` → опрос API. `killall b4` (SIGTERM) НЕ завершил b4 за 3 с (graceful shutdown завис на разборе packet-path), `S99b4 start` увидел живой `pidof b4` и **пропустил** запуск → тест-инстанс продолжал работать; через ~20 мин `mt_wdt ... SoC power status: software reset` перезагрузил роутер (uptime сброшен), live поднялся автостартом на буте (`--config=/opt/etc/b4/b4.json`). Урок: **не запускать тест-инстанс b4 с живым конфигом** (он поднимает тот же NFQUEUE/PPE/routing, а shutdown может зависнуть); для полевой проверки API — либо минимальный изолированный конфиг без packet-path, либо не трогать живой. Если запускали: убивать `killall -9 b4`, дождаться пустого `pidof b4` ДО `S99b4 start`, `S99b4 start` отдельным вызовом, сверить sha `5627c147`/md5 `e629da1e` + `S99b4 selfcheck`.

32. **НЕ РФ в UI: галка `nonru` = МАСТЕР-ВЫКЛЮЧАТЕЛЬ не-РФ.** Галка **ON** + SOCKS5-прокси → базовый MASQUE идёт через прокси (**не-РФ**); галка **OFF** → прокси **инертен**, базовый MASQUE прямой (**RU**), даже если прокси введён. Реализация (`3a0e47a2`): `warpservice` применяет `system.warp.socks5` только при `system.warp.nonru.enabled`. Вложенный `nonru`-движок (nested M+M над base-plane) больше **НЕ запускается** — он контендил base-warp и ронял его data-path (`tls: read tcp 172.16.0.2:…: connection reset by peer`; мои прежние ложные «0 байт/RST» — из-за него). Валидатор: `nonru.enabled` **требует** `system.warp.socks5` (галка без прокси = 400). Routing `tunnel=nonru` алиасится в `masque`. Проверено на живом: OFF → `ip=104.28.213.233 colo=DME loc=RU`; ON → `ip=104.28.192.58 colo=LHR loc=GB`. Прокси владельца (WARP, 10 МБ): **GB `31.59.20.176:6754` — 3.80 МБ/с (лучший)**, PT `84.247.60.125:6095` — 3.14, DE `31.58.9.4:6077` — **0 (данные не идут)**. Смена галки/прокси применяется после рестарта b4 (движки конфиг-первичны).

---

## 8. Инварианты

- На сервер должны уйти оригинальные байты ClientHello. Fake уничтожается AutoTTL или badsum, не подменой SNI в том же transcript.
- fake QUIC: обязателен multisplit (обратный порядок фрагментов).
- fake TCP baseline: fake SNI + combo (дефолт при пустом `fragmentation`).
- ТСПУ: тихий дроп TCP по SNI `youtube*`, без RST. QUIC/UDP 443 часто проходит.
- PPE не маскирует SNI. PPE только оставляет рукопожатие на CPU.
- Discovery не подбирает стратегии руками в этой кампании. Сначала классификатор должен увидеть flow.
- **НЕ РФ: галка `nonru` (UI) = мастер-выключатель.** ON + `system.warp.socks5` → базовый MASQUE идёт через прокси (не-РФ); OFF → прокси инертен (базовый MASQUE RU), даже если прокси введён. Вложенный nonru-движок не используется; `routing.tunnel=nonru` алиасится в `masque`.

---

## 9. Открытый эксперимент

**Поле 18.08 07:26:18–54 UTC (ваниль hang, ReVanced OK, стек exp-rexmit, перечитано 12:37 +05):**  
`rr1---sn-5go7ynlk.googlevideo.com` → `173.194.6.6`. Сначала QUIC `fake UDP 6/6`, через 0.46 с шесть TCP: 41422/41436/41438/41440/41444/41446. ECH CH режется `1396` (`16030106f0`/`0710`/`06d0`) + хвост 385/417/353. Сет `youtube-video`. На каждый 0x16: fake SNI 1573 + **fake-only accept**, combo **ни разу** на этот IP. RST нет, ServerHello нет ~36 с. Combo в том же окне только на короткий youtubei 189 B (`16030100b8`). ReVanced 07:27: UDP googlevideo + `returnyoutubedislikeapi.com`, без TCP-медиа.  
Вывод: классификатор и rexmit живы; **ванильный TCP+ECH на этом GGC fake SNI не пробивает, потому что combo не режет неполный record**. Не google `/16`. Дальше: hold полного CH → один combo **или** снять ECH (type 65 / DoH).

**Слой:** nosplit LIVE `b4b2d2fc…` (21:00 +05). Телефон откат. Карта C: `YOUTUBE_DATAPLANE.md` §7. Открыто: YouTube Windows `.40` (`BC:FC:E7:B5:F5:8E`).

**ИТОГ НОЧИ 21→22.08 (важнейшее):** тактика C закрыта НАВСЕГДА — ТСПУ режет TCP к Google по факту ECH-ext в записи (доказательства и Firefox-эксперимент: `YOUTUBE_DATAPLANE.md` §2). Телефонный Chromium шлёт ECH GREASE всегда — на Android не отключается. ПК `.40`: YouTube через Firefox работает; Chrome 151 с политикой `EncryptedClientHelloEnabled=0`. Владелец ОДОБРИЛ следующий слой **L-steer** (`b4x-p0.8`): RST TCP к сет-IP `youtube-video`, чтобы Cronet мгновенно оставался на masked-QUIC. Гварды: только youtube-video, конфиг не трогать, PPE off.

**ИТОГ СЕССИИ 22.08 (L-steer v1 FAIL → v2 FAIL, steer закрыт): откат holdch3 17:24 UTC.**
v1 `69b18178`: RST по ECH-детекту — механика точна, UX хуже базы (шторм новых tuple каждые 3–13 c). v2 `fc8b08ed`: клиент-scoped дроп SYNs (MAC+dstIP) 10 c после первого steer + автогейт `cmd/echprobe` с ПК (A-steer RST 50 мс / B-suppress fresh-tuple SYN тихо умер / C-clean не тронут; лог: 110 армингов, 723 dropped SYN, гвардии без промахов). UX владельца: ваниль виснет при перемотке, ReVanced часть роликов с большой задержкой. **Корневое:** молчаливый SYN-drop = kernel-backoff тех же tuple — TCP-limbo дольше базы; любая активная помеха doomed-TCP (RST или SYN-drop) хуже естественного fallback Кронета на masked-QUIC. Steer-семейство закрыто навсегда: карта путей и криптозакрытия в `YOUTUBE_DATAPLANE.md` §7.

**Предыдущий слой:** exp-rexmit `b08a8c87…` остаётся на `$F/bin/b4`.

**Ночь:** b4 умер; USB `noexec` после ребута. S99b4 теперь remount exec + `/opt/sbin/b4`.

**1/10 ещё:** 23:43 `74.125.173.134` CH 517 B полный (`1603010200`), fake+combo один раз, дальше 5 ретраев того же 0x16 ушли **без** маски (`already applied`). ТСПУ видел голый SNI.

**rexmit:** каждый 0x16 инжектится; хвост не-0x16 — accept. holdpath для неполного ECH остаётся.

Правила агента: `AGENTS.md`. Карта YouTube: `YOUTUBE_DATAPLANE.md`. Стартовый промпт: `.ag/prompts/SESSION_START.md`. Как говорить с агентом: `B4X_FIELD_VALIDATION_AGENT_PACK/AGENT_CONTRACT.md`.
