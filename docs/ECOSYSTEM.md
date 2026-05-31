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

# Ecosystem

Where `pcsc-fido` fits among related Linux OSS.

## Why Linux needs a bridge (for now) - May 2026

On Linux, browsers such as Firefox, Chrome, or Brave use **CTAPHID** over **`/dev/hidraw*`**, not PC/SC, for WebAuthn. **`fido2-token`**, OpenSSH **`sk-*`**, and other **libfido2** clients can use PC/SC NFC directly; **unmodified browser tabs do not**. Windows and macOS integrate NFC FIDO into their platform WebAuthn stacks; mainstream Linux does not yet — the [Credentials for Linux](https://github.com/linux-credentials) stack is the emerging path (its `libwebauthn` already speaks NFC over PC/SC; browser/portal adoption is the remaining gap).

## Related projects

Links are pointers, not endorsements.

### Same problem — browser WebAuthn over PC/SC NFC

All rely on [Below the bridge](#below-the-bridge-host-pcsc-stack).

| Project | Transport to browser | Priv | Notes |
| ------- | -------------------- | ---- | ----- |
| [fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge) | **`/dev/uhid`** | **root** | Python — UHID relay; manual install; no udev (typical **`sudo`**); stock **`uhid`** |
| [cryptnox-fido2-bridge](https://github.com/cryptnox/cryptnox-fido2-bridge) | **`/dev/uhid`** | **root** | Python — UHID relay; based on fido2-hid-bridge by Bryan Jacobs (adapted/extended by Cryptnox); manual install; no shipped udev (typical **`sudo`**; optional DIY udev); stock **`uhid`** |
| [CTAP-bridge](https://github.com/StarGate01/CTAP-bridge) | USB gadget (`configfs`) | **root** | Python — USB gadget relay (not UHID); configfs/gadget modules; udev for emulated device; optional composite CCID (`-c`) depends on out-of-tree [`f_ccid`](https://gist.github.com/caj380/2de5b9a41797663fdac72e0bdebd9d6c) — not in stock Fedora/Debian kernels ([libfido2 #626](https://github.com/Yubico/libfido2/discussions/626)) |
| **pcsc-fido** (this repo) | **`/dev/uhid`** | **lower** | C — UHID relay; packaged `.rpm`/`.deb`, systemd, udev; **`pcsc-fido`** user + polkit; stock **`uhid`** |

### Adjacent — different consumer

| Project | Notes |
| ------- | ----- |
| [libfido2](https://github.com/Yubico/libfido2) / **`fido2-token`** | C — FIDO2/U2F library and CLI; optional, experimental PC/SC NFC transport (compile-time `USE_PCSC`, off by default) for apps, not unmodified browser WebAuthn |
| [libwebauthn](https://github.com/linux-credentials/libwebauthn) / [credentialsd](https://github.com/linux-credentials/credentialsd) | Rust — platform credential stack / portal direction. `libwebauthn` implements NFC over PC/SC (via the `nfc-backend-pcsc` Cargo feature) for FIDO2 and U2F; `credentialsd` is a D-Bus credential service. Today a browser extension (`navigator.credentials` override) wires Firefox 140+ and Chromium/Edge 111+ to `credentialsd`; an experimental patched Firefox build talks to it natively. No browser has upstreamed native portal support yet. Reduces the need for a browser relay as adoption lands. |
| [FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet) | Java (JavaCard) — token firmware; PC/SC-only; browsers on Linux still need a CTAPHID bridge |
| [VirtualWebAuthn](https://github.com/UoS-SCCS/VirtualWebAuthn) | Python — software virtual authenticator (research); not a PC/SC relay |
| [fidorium](https://github.com/edg-l/fidorium) | Rust — software virtual authenticator (TPM-backed); not a PC/SC relay |

### Below the bridge (host PC/SC stack)

Runtime requirements for the relays above (and for libfido2 PC/SC clients). They rely on **`pcscd`** plus a CCID IFD driver — **`libccid`** on most Fedora/Debian setups; a vendor IFD can substitute for some readers.

| Component | Notes |
| --------- | ----- |
| [pcsc-lite](https://sources.debian.org/src/pcsc-lite/) (Debian **`pcsc-lite`** / Fedora **`pcsc-lite`**) | C — **`pcscd`**, **`libpcsclite`** (required) |
| [ccid](https://sources.debian.org/src/ccid/) (Debian **`libccid`** / Fedora **`pcsc-lite-ccid`**) | C — USB CCID IFD driver for common readers (required on typical hardware) |

Corrections and additions welcome via issue or PR — the landscape changes.

Last Updated: 2026-05-30
