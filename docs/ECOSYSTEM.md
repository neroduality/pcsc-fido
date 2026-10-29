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

## Why a bridge (October 2026)

Linux browsers (Firefox, Chrome, Brave) do WebAuthn only as CTAPHID over `/dev/hidraw*`. They never use PC/SC, so NFC security keys (NFC FIDO cards and NFC-enabled security keys) are invisible to them. libfido2 clients (`fido2-token`, OpenSSH `sk-*`) can use NFC over PC/SC directly.

Windows supports NFC FIDO natively. macOS does not. On Linux the [Credentials for Linux](https://github.com/linux-credentials) stack is the likely fix; its `libwebauthn` already does NFC over PC/SC, and browser/portal adoption is what remains.

## Related projects

Listed for reference, not endorsement.

### Browser WebAuthn over PC/SC NFC

| Project | Lang | Browser transport | Runs as | Notes |
| ------- | ---- | ----------------- | ------- | ----- |
| [fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge) | Python | `/dev/uhid` | root | Manual install, no udev rules. |
| [cryptnox-fido2-bridge](https://github.com/cryptnox/cryptnox-fido2-bridge) | Python | `/dev/uhid` | root | Fork of fido2-hid-bridge. Manual install, no shipped udev rules. |
| [CTAP-bridge](https://github.com/StarGate01/CTAP-bridge) | Python | USB gadget (`configfs`) | root | Optional CCID composite (`-c`) needs out-of-tree [`f_ccid`](https://gist.github.com/caj380/2de5b9a41797663fdac72e0bdebd9d6c), absent from stock Fedora/Debian kernels ([libfido2 #626](https://github.com/Yubico/libfido2/discussions/626)). |
| **pcsc-fido** | C | `/dev/uhid` | `pcsc-fido` user | `.rpm`/`.deb`, systemd, udev, polkit. |

### Other consumers

| Project | Notes |
| ------- | ----- |
| [libfido2](https://github.com/Yubico/libfido2) / `fido2-token` | C library and CLI. PC/SC NFC (`USE_PCSC`) is on by default in v1.18, still labelled experimental. For apps, not browsers. |
| [libwebauthn](https://github.com/linux-credentials/libwebauthn) / [credentialsd](https://github.com/linux-credentials/credentialsd) | Rust platform credential stack. `libwebauthn` does FIDO2/U2F over PC/SC NFC (`nfc-backend-pcsc` feature). `credentialsd` is a D-Bus service; today it needs a patched `xdg-desktop-portal` and reaches browsers via an extension (Firefox 140+, Chromium/Edge 111+; documented for test origins such as `webauthn.io`) or an experimental patched Firefox Flatpak. No browser supports it upstream yet. |
| [FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet) | JavaCard FIDO2 applet. PC/SC only; Linux browsers still need a bridge. |
| [VirtualWebAuthn](https://github.com/UoS-SCCS/VirtualWebAuthn) | Python software authenticator (research). Not a PC/SC relay. |
| [fidorium](https://github.com/edg-l/fidorium) | Rust software authenticator (TPM-backed). Not a PC/SC relay. |

### Host PC/SC stack

Required by every PC/SC relay above and by libfido2 PC/SC clients.

| Component | Packages | Role |
| --------- | -------- | ---- |
| [pcsc-lite](https://sources.debian.org/src/pcsc-lite/) | Debian `pcscd`, `libpcsclite1`; Fedora `pcsc-lite` | `pcscd` daemon and `libpcsclite` |
| [ccid](https://sources.debian.org/src/ccid/) | Debian `libccid`; Fedora `pcsc-lite-ccid` | USB CCID reader driver (some readers use a vendor driver) |

Corrections welcome via issue or PR.
