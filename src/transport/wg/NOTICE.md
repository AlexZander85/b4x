# NOTICE — third-party component: amneziawg-go

This package (`src/transport/wg`) embeds the following third-party Go module:

- Module path: `github.com/amnezia-vpn/amneziawg-go/v3`
- Pinned version (go.mod): `v3.1.20260814`
- Pinned commit: `1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1` (tag `v3.1.20260814`)
- License: MIT (SPDX verified via GitHub API at design time, 2026-08-24)

## Modifications

- `device/timers.go` (`NewTimer`): move the `timer.duration = 0` reset under
  `modifyingLock` inside the timer callback — fixes a data race between the
  callback (reset after unlock) and `Timer.Del` (reset under lock). Upstream
  report: pending — draft in `docs/upstream/amneziawg-timers-race-issue.md`.

- `device/device.go` + `device/send.go` (E-PROTON review P3, stage PT-obf1):
  add the optional `Device.InitPacketSpecFunc func(index int) string` seam.
  When set, `SendHandshakeInitiation` consults it for every I-slot (0-based
  I1..I5) and materializes the returned obf-chain spec FRESH for each
  initiation; `""` or a malformed spec keeps the static IpcSet chain (a
  parse failure never drops the slot to no-obfuscation). Purpose: per-hand
  shake I1 regeneration — the proton QUIC family re-renders its QUIC Initial
  (new DCID + randomness) on every handshake instead of re-sending one
  byte-identical 1250-byte datagram (the static-DCID replay signature the
  on-path DPI table flags). The field is nil in every other target — the
  default behavior is bit-for-bit unchanged.

## Rule

Any future change that modifies upstream files (vendored copy, patch, fork)
MUST update the "Modifications" section above in the same commit and MUST
re-pin/re-hash this NOTICE. The mechanical guard is `TestLicenseNoticeHash`
(license_test.go): it fails whenever this file changes without the pinned
hash literal being updated.

## Upstream license text (verbatim from LICENSE at the pinned commit)

Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
