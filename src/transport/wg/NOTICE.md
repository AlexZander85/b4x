# NOTICE — third-party component: amneziawg-go

This package (`src/transport/wg`) embeds the following third-party Go module:

- Module path: `github.com/amnezia-vpn/amneziawg-go/v3`
- Pinned version (go.mod): `v3.1.20260814`
- Pinned commit: `1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1` (tag `v3.1.20260814`)
- License: MIT (SPDX verified via GitHub API at design time, 2026-08-24)
- Modifications to upstream files: **none**

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
