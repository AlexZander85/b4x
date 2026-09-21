# VLESS in-process XTLS Vision — real-Xray interop evidence

This artifact answers the review finding "real Xray interop is not in CI": the
interop test is opt-in (`B4_XRAY_BIN`), so the committed `interop-run.log` is
the evidence, reproducible with the exact commands below.

## What it proves

`TestVisionInteropXray` (src/transport/vless/vision_interop_test.go) starts a
**real Xray-core server** with a VLESS inbound and runs the b4x *in-process*
VLESS client against it, end-to-end over TLS-in-TLS:

- subtest `plain`     — `flow=""`           (control: plain VLESS over TLS)
- subtest `vision`    — `flow=xtls-rprx-vision` (XTLS Vision framing)

Both fetch a local HTTPS target through the tunnel and assert the body, so the
test only passes if the VLESS framing, the outer TLS, the Vision padding
(encoder + decoder) and the lazy response-header read all work against a real
server.

## Environment used

- Xray-core built from the local reference `D:\netcreaze\Xray-core` (MPL-2.0).
- Version reported by the binary: `Xray 26.9.9 ... Custom (go1.27.0 linux/amd64)`.
- Binary: `xray`, size `49760942` bytes,
  sha256 `7fb882c6817396236e177944a00c3c2e2065a3edca1be9adfbf44958b188f506`.
- Tested at commit that added `vision.go` (see git history).

## Reproduce

```powershell
# 1) build xray from the reference into D:\tmp\opencode\xray
docker run --rm --dns 8.8.8.8 `
  --mount type=bind,source=D:\netcreaze\Xray-core,target=/xray `
  --mount type=bind,source=C:\Users\AlexZander\go\pkg\mod,target=/go/pkg/mod `
  --mount type=bind,source=D:\tmp\opencode,target=/out `
  golang:1.25.3-alpine sh -c "cd /xray && GOTOOLCHAIN=auto GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/xray ./main"

# 2) run the interop test
docker run --rm --dns 8.8.8.8 `
  --mount type=bind,source=D:\b4x,target=/src `
  --mount type=bind,source=C:\Users\AlexZander\go\pkg\mod,target=/go/pkg/mod `
  --mount type=bind,source=D:\tmp\opencode,target=/xbin,readonly `
  -w /src/src -e GOFLAGS=-mod=vendor -e B4_XRAY_BIN=/xbin/xray golang:1.25.3-alpine `
  sh -c "go test -timeout 240s -run TestVisionInteropXray -v ./transport/vless/"
```

Expected: `--- PASS: TestVisionInteropXray/plain` and
`--- PASS: TestVisionInteropXray/vision` (see `interop-run.log`).

## How to read the server log in interop-run.log

For the `vision` subtest the Xray server prints the full Vision exchange:

- `Xtls Unpadding new block, content 0 padding ... command 0` — our preamble
  (long padding that hides the VLESS header).
- `Xtls Unpadding new block, content 1479 padding ... command 0` +
  `XtlsFilterTls found tls client hello!` — our padded inner ClientHello.
- `XtlsFilterTls found tls 1.3! 2472 TLS_AES_128_GCM_SHA256` — TLS-in-TLS.
- `XtlsPadding 2472 ... 0` — the server's own downlink padding, which our
  decoder strips.
- `command 0` then `command 1` (End) — our uplink padding terminator.

Note: the test config sets `freedom` `finalRules:[{action:"allow"}]` because
Xray blackholes loopback/private destinations by default (the local target).
