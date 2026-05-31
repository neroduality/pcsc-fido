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

# pcsc-fido checklist

Living checklist for the independent **pcsc-fido** project.

This checklist and `make lint` (spec coverage step) are engineering traceability gates. They confirm that
documented requirements still map to code, tests, packaging, or docs; they are not a FIDO,
CTAP, ISO 7816, PC/SC, Debian, or Fedora certification claim.

## How to use and maintain

1. After a behavioral change, update the relevant row(s) and spec coverage.
2. Re-run the verification commands below before marking rows green.
3. Keep **manual** rows ⚠ until platform smoke is recorded (issue, release note, or log reference).
4. Do not treat out-of-scope specs as product gaps unless scope explicitly expands.

### Verification commands

| Repo | Command | Purpose |
| ---- | ------- | ------- |
| pcsc-fido | `make lint` | License headers, formatting, spec coverage, unsafe-API guard, systemd/polkit integration checks, shellcheck, codespell, build, CTest, Release ELF hardening, cppcheck |
| pcsc-fido | `make test` | Host unit tests (plain build) |
| pcsc-fido | `make verify` | Plain, ASan, UBSan, TSan, Valgrind |
| pcsc-fido | `make fuzz` | Optional local libFuzzer on `cbor_util`, `request_assembly`, and `apdu` (Clang; 180s/target, `-max_len` 8192/16384; not CI) |
| pcsc-fido | `make security-lint` | SPDX, secret scans, supply-chain checks |

## Status legend

| Symbol | Meaning |
| ------ | ------- |
| ✅ | Implemented and covered by automated checks and/or documented manual proof |
| ⚠ | Partially done or requires periodic manual platform verification |
| ❌ | Known gap against current product goals |
| N/A | Out of product scope |

## Authoritative specifications

Use these public sources when reviewing compliance. Order follows the product stack (browser → virtual CTAPHID → PC/SC client → host reader driver), then Linux packaging.

| Specification | Version / scope | Authoritative source | Product relevance |
| ------------- | ----------------- | -------------------- | ----------------- |
| W3C WebAuthn / FIDO CTAP 2.x | Current web specs | [WebAuthn](https://www.w3.org/TR/webauthn/) · [CTAP 2.1](https://fidoalliance.org/specs/fido-v2/fido-client-to-authenticator-protocol-v2.1-ps-20201208.html) | Browser ceremony and authenticator protocol reference |
| FIDO CTAP HID | CTAP 2.x §11.2 (USB HID) | [CTAP HID transport](https://fidoalliance.org/specs/fido-v2/fido-client-to-authenticator-protocol-v2.1-ps-20201208.html#usb-hid-protocol) | Virtual FIDO HID device over Linux **UHID** |
| FIDO CTAP over NFC (APDU) | CTAP 2.x §11.3 + ISO 7816 mapping | [CTAP NFC](https://fidoalliance.org/specs/fido-v2/fido-client-to-authenticator-protocol-v2.1-ps-20201208.html#nfc) · [ISO/IEC 7816-4 overview](https://www.iso.org/standard/54550.html) | CTAP2/U2F APDUs relayed through **`pcscd`** |
| PC/SC Part 1 | Revision 2.01.01 (September 2005) | [PC/SC Part 1 PDF](https://pcscworkgroup.com/Download/Specifications/pcsc1_v2.01.01.pdf) | **`libpcsclite`** client API and reader session model |
| USB CCID (host reader) | Revision 1.1 (April 2005) | [USB CCID 1.1 PDF](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf) | Host-side USB CCID readers via **`libccid`** / **`pcscd`** (not implemented in this repo) |
| systemd service sandbox | distro unit files | [systemd.exec](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) | `pcsc-fido.service` hardening |
| udev | Linux device permissions | [udev(7)](https://www.freedesktop.org/software/systemd/man/udev.html) | `70-pcsc-fido.rules` — static **`/dev/uhid`** (`static_node=uhid`) and active-seat **`uaccess`** for virtual bridge **hidraw**; `pcsc-fido-uhid.conf` loads **`uhid`** at boot |

### Spec coverage automation

Manifest: **`docs/spec-coverage.yaml`**. Top-level keys group **`requirements`** with **`label`**, **`pattern`** (extended regex), and **`paths`**. The gate runs in **`make lint`** (`.github/linters/ci-lint.sh` via `helper-spec-coverage-check.py`) and as a dedicated **Spec coverage** job in Main CI. Requires **PyYAML** (`python3-yaml`).

Spec coverage is source-tree traceability, not binary inspection. It greps configured source, test, documentation, packaging, and script paths for requirement-specific strings. It does not inspect compiled objects, exported symbols, debug sections, or installed packages, so Release symbol stripping does not affect spec coverage results.

| Specification (`spec_id`) | Manifest scope |
| ------------------------- | -------------- |
| `fido-ctap-hid` | UHID daemon, CTAPHID framing, keepalive, cancel, unchanged CTAP payload relay, reader selection, tap-arm, rate limiting |
| `fido-apdu` | FIDO AID, CTAP CBOR APDU pack/parse, `61xx` chaining, PC/SC exchange |
| `packaging` | udev, systemd sandbox, RPM/DEB, install docs, runtime deps, sanitizers |
| `ci-release` | CI build/test/lint, package artifacts, GitHub release upload |

When adding or renaming protocol entry points, update **`docs/spec-coverage.yaml`** in the same change as **`docs/CHECKLIST.md`**.

## Architecture and packaging

| Status | Requirement | Evidence |
| ------ | ----------- | -------- |
| ✅ | Pure C / ISO C23 | CMake (`CMAKE_C_STANDARD 23`); `cmake/HostHardening.cmake` |
| ✅ | UHID browser bridge | Virtual FIDO HID over `/dev/uhid`; README explains Linux browser PC/SC gap |
| ✅ | PC/SC NFC relay | `pcsc_bridge.c` (+ `pcsc_session.c`, `pcsc_reader_ops.c`) → CTAP2/U2F APDUs via libpcsclite (no in-repo IFD driver) |
| ✅ | Host compile/link hardening | OpenSSF guide TL;DR via `HostHardening.cmake` (PIE, fortify, stack/CET, pthread `-fexceptions`, linker hygiene, probe-gated GCC/Clang extras); see C-STYLE-CODEFLOW.md for intentional gaps |
| ✅ | systemd + udev + polkit | `packaging/`; `ensure-pcsc-fido-user.sh` at install (mode `0700`); **`modules-load.d`** + **postinst** bootstrap `uhid`/udev (no root **ExecStartPre**); lint via `verify-systemd-unit.sh` and `verify-pcsc-integration.sh` |
| ✅ | Unit tests | 23 CTest targets: CTAPHID, APDU/chain, reader selection/ops, PC/SC bridge/session, daemon config/UHID loop, tap-arm/browser daemon, card monitor, rate limiting, thread-safety (TSan via `make verify`) |
| ✅ | Source install | `sudo make install` builds/stages a Release daemon only, strips Release installs, stops a running bridge before replacement, creates/updates the `pcsc-fido` identity, loads `uhid`, reloads udev/systemd (including `daemon-reload`), and does not enable/start `pcscd.socket` or `pcsc-fido.service`. |
| ✅ | Source uninstall | `sudo make uninstall` is source-install only: stops/disables the bridge, removes manifest/known/stale files, drop-ins, rules, docs, source-created identity, reloads system state, and fails if known leftovers remain. |
| ✅ | Production packages | RPM/DEB/CPack; runtime deps include `pcscd`, CCID driver, systemd, udev, polkit; package scripts create/update the service identity and reload host metadata; package removal uses `dnf`/`apt`, not `make uninstall`. |
| ✅ | User docs | Packaged docs: [INSTALLATION.md](../INSTALLATION.md), `NOTICE`; repo-only: [README](../README.md), [RELEASE.md](../RELEASE.md), [CHECKLIST.md](CHECKLIST.md), [DEBUGGING.md](DEBUGGING.md), [ECOSYSTEM.md](ECOSYSTEM.md), [REMEDIATIONS.md](REMEDIATIONS.md), [C-STYLE-CODEFLOW.md](C-STYLE-CODEFLOW.md), [spec-coverage.yaml](spec-coverage.yaml), [.github/WORKFLOWS.md](../.github/WORKFLOWS.md) |

## Protocol scope

| Status | Surface | Notes |
| ------ | ------- | ----- |
| ✅ | CTAPHID INIT / PING / CBOR / MSG | INIT assigns channel; PING echoed; CBOR/U2F forwarded through PC/SC; `61xx` completed with GET RESPONSE |
| ✅ | CTAPHID keepalive / LOCK / CANCEL | Keepalive during PC/SC work; LOCK acknowledges, standalone CANCEL resets without a direct response, in-flight CANCEL completes the original CBOR request with `CTAP2_ERR_KEEPALIVE_CANCEL`, and UHID close resets state without poisoning the channel |
| ✅ | CTAPHID timing edges | Tests cover INIT timeout, repeated keepalive, bad continuation, wrong channel, oversized response |
| ✅ | FIDO AID select | Shared `pcsc_fido_pack_select_fido_apdu()` (`00 A4 04 00 08 A0 00 00 06 47 2F 00 01`; `Le=00` and no-`Le` fallback) on the session path and in **`reader_probe_fido_card`** |
| ✅ | PC/SC reader selection | Auto-discovery; unambiguous single-reader selection; single contactless non-SAM slot auto-selected from a SAM/PICC pair; card-presence tiebreaker; **`reader_probe_fido_card`** when several slots show cards; `confirm_card_present` before connect; reader names capped at `PCSC_FIDO_READER_NAME_MAX` (256) |
| ✅ | CTAP payload forwarding | CBOR/MSG payload bytes are preserved at the CTAP layer and encapsulated as CTAP-over-NFC APDUs; no synthesized responses or compatibility cache |
| ✅ | Tap-arm virtual key | Default hidden key until card-present edge; timed arm window (`PCSC_FIDO_ARM_SEC`); stale wake drains prevent same-presence re-arm after timeout; `always` mode for diagnostics |
| ✅ | CTAPHID / PC/SC rate limiting | Rolling-window frame and exchange budgets; exchange limit enforced in **`pcsc_fido_bridge_exchange`**; `CHANNEL_BUSY` when throttled; disable via `PCSC_FIDO_RATE_LIMIT=0` for diagnosis |
| ✅ | Reader/startup seams | Reader-enumeration retry window; terminal-operation PC/SC cleanup |
| ✅ | Session concurrency | Generation-invalidated TX snapshots; active-transmit handle lifetime tracking; `SCardCancel` can interrupt blocking transmit; `verify_ready` (`SCardStatus`); `confirm_card_present`; cancel checks in APDU chain; `pcsc_err.c`; see [REMEDIATIONS.md](REMEDIATIONS.md#safeguards-for-pcsc-fido-nfc-specific) |
| ✅ | Thread-safe PC/SC cancellation | Session snapshots under mutex; TSan-tested concurrent cancel/reset vs exchange |
| ✅ | Debug protocol logging | Debug builds only: `PCSC_FIDO_DEBUG=1`; Release ignores the env var |

## Out-of-scope specifications

| Status | Area | Notes |
| ------ | ---- | ----- |
| N/A | FIDO authenticator certification | Transport bridge only — see [CTAP](https://fidoalliance.org/specs/fido-v2/fido-client-to-authenticator-protocol-v2.1-ps-20201208.html) on the token |
| N/A | USB CCID device / IFD handler | Host **`libccid`** or USB CCID reader firmware behavior — see [USB CCID 1.1](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf) |
| N/A | ICAO 9303 / eMRTD | Not a product target |
| N/A | Credential Exchange Format | Passkey import/export — not bridge scope |

## Hardware/browser smoke matrix

Manual interoperability only — not certification. Keep evidence concise and current. Pick one option from each row; also test both readers attached when changing reader selection. Release packaging covers additional Linux architectures in [RELEASE.md](../RELEASE.md).

| Status | Dimension | Manual smoke options |
| ------ | ----------- | -------------------- |
| ⚠ | Reader | [HID Global OMNIKEY 5022](https://www.hidglobal.com/products/omnikey-5022-reader) or [ACS ACR1252U PICC slot](https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader/) |
| ⚠ | Token | [Cryptnox NFC FIDO card](https://cryptnox.com/fido2-security-key-nfc-compatible-passwordless-key/) or [YubiKey NFC security key](https://www.yubico.com/us/product/yubikey-5-series/yubikey-5c-nfc/) |
| ⚠ | Browser | Firefox, Chrome, or Brave |
| ⚠ | Linux arch | amd64/x86_64, arm64/aarch64, or riscv64 where hardware is available |
| ⚠ | Scenario | `webauthn.io` registration and sign-in; PIN if configured; YubiKey touch when prompted |
| ⚠ | Cold boot | Reboot the machine; confirm `pcscd.socket` and `pcsc-fido.service` are enabled, start cleanly, and WebAuthn smoke still passes |
| ⚠ | Service restart | `sudo systemctl restart pcsc-fido.service`; re-run registration/sign-in smoke without reboot |

Last Updated: 2026-05-30
