<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
Copyright (C) 2026 Nero Duality, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# pcsc-fido @TAG@

**Linux only** — daemon-side bridge: virtual FIDO HID (UHID) → PC/SC → NFC FIDO card / NFC security key via `pcscd` and a USB CCID reader.

## Changelog

<!-- Optional per-release notes below. CI publishes this template as-is when no release-specific notes are added. -->

Git history contains detailed changes. Includes general improvements and capability updates.

**Notice:** AI-assisted, human-reviewed, and hardware-tested. Source-only development firmware.

<!-- Per-release changes (optional):

- ...
-->

## Documentation

Packages ship **`INSTALLATION.md`** and **`NOTICE`** under `/usr/share/doc/pcsc-fido/`.

- [INSTALLATION.md](https://github.com/neroduality/pcsc-fido/blob/@TAG@/INSTALLATION.md) — install, upgrade, and uninstall
- [README.md](https://github.com/neroduality/pcsc-fido/blob/@TAG@/README.md) — overview and contributing
- [docs/](https://github.com/neroduality/pcsc-fido/tree/@TAG@/docs/) — debugging, security posture, checklist, and more (repo only)

Verify downloads: `sha256sum -c SHA256SUMS` (see Assets).

## Assets

- **DEB (6):** amd64, arm64, armhf, ppc64el, riscv64, s390x
- **RPM (6):** x86_64, aarch64, armv7hl, ppc64le, riscv64, s390x
- **Source:** `pcsc-fido-@VERSION@.tar.gz` (git archive at tag)
- **Integrity:** `SHA256SUMS` (GNU `sha256sum` format)
- **Tests:** amd64 release lint gate runs `ctest`; native package builds run `ctest` with `BUILD_TESTING=ON`; cross-compiled ports skip unit tests (`SKIP_CTEST=1`)

## Notes

| Item | Detail |
| ------ | -------- |
| Package name | `pcsc-fido` |
| Binary / service | `pcsc-fido`, `pcsc-fido.service` |
| Debug logging | Release packages omit `PCSC_FIDO_DEBUG`; build Debug from source if needed |
| Hardware testing | Manual smoke matrix in [CHECKLIST.md — Hardware/browser smoke matrix](https://github.com/neroduality/pcsc-fido/blob/@TAG@/docs/CHECKLIST.md#hardwarebrowser-smoke-matrix) (not certification) |
| Security reports | [SECURITY.md](https://github.com/neroduality/.github/blob/main/SECURITY.md) |
| License | Apache-2.0 |
