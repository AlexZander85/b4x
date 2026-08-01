# B4X Test Execution Index

Дата: 31.07.2026. Все прогоны выполнены в disposable clone `C:\Users\AlexZander\AppData\Local\Temp\opencode\b4x-audit\repo` (autocrlf=false), src = рабочее дерево `D:\b4x` (нормализованный blob совпадает). Логи: `logs\`.

| # | Команда | Окружение | Результат | Лог |
|---|---|---|---|---|
| 1 | `go build ./...` (без UI) | Windows, go 1.25.3 | FAIL: `http\server.go:24:12: pattern ui/dist/*: no matching files found` | — |
| 2 | `go run tools/gendefaults.go` | Windows | FAIL: `log` пакет (syslog.New, unix.Dup2 — Unix-only) | — |
| 3 | `go run tools/gendefaults.go` | Docker golang:1.25-alpine, linux/amd64, CGO=0, GOPROXY=off | OK → `src/http/ui/src/models/defaults.json` (3495 B) | — |
| 4 | `pnpm install --frozen-lockfile` | Windows, pnpm 9.15.9, Node 22.11.0 | OK (1m12s; warning: vite требует Node ≥22.12) | — |
| 5 | `pnpm build` (vite 7.3.3) | Windows | OK (12605 модулей; после gen-defaults) → `dist/` | — |
| 6 | `go build ./...` | Docker golang:1.25-alpine, linux/amd64, CGO=0 | **OK** (BUILD_OK) | logs/go-build.log (пуст) |
| 7 | `go vet ./...` | Docker golang:1.25-alpine | **FAIL**: fieldtest/session.go:59 (2× повтор json-тега config_gen); capture/ppe/product_bundle_test.go:100 (cannot use cfg as *config.Config) | logs/go-vet.log |
| 8 | `go test -count=1 ./...` | Docker golang:1.25-alpine | **FAIL**: 41/42 OK; `capture/ppe [build failed]` (строки 100-101) | logs/go-test.log |
| 9 | `go test -race -count=1 ./...` | Docker golang:1.25-bookworm, CGO=1 | **FAIL**: тот же `capture/ppe [build failed]`; остальные 41 пакет OK по race | — |
| 10 | `go list -deps ./` | Docker golang:1.25-alpine | OK: достижимы capture/ppe, crossservice, detector, monitor, observability, runtimecontrol; НЕ достижимы warp, serviceprofile, fieldtest, silentpath | — |
| 11 | warp-пакет: `go test ./...` | Docker golang:1.25 (по warp_audit.md) | OK 19/19 PASS, `go vet` чист (только модели) | warp_audit.md |

Примечания:
- Linux/amd64 = целевая платформа (Keenetic). Windows-сборка невозможна (log/syslog).
- Docker Desktop 29.6.1 (linux/amd64); модули из GOMODCACHE `C:\Users\AlexZander\go\pkg\mod` (для #3 — GOPROXY=off; для #6/7/8/9 — сеть, дозагрузка mdlayher/socket).
- gendefaults (#3) выполнен в контейнере, т.к. Windows не компилирует log-пакет; остальные команды — тоже в контейнере ради Linux-цели.
