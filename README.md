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

<!-- Upstream: https://github.com/neroduality/pcsc-fido -->

# pcsc-fido

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Main CI](https://github.com/neroduality/pcsc-fido/actions/workflows/main-ci.yml/badge.svg?branch=main)](https://github.com/neroduality/pcsc-fido/actions/workflows/main-ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/neroduality/pcsc-fido/badge)](https://securityscorecards.dev/viewer/?uri=github.com/neroduality/pcsc-fido)
[![Release](https://img.shields.io/github/v/release/neroduality/pcsc-fido)](https://github.com/neroduality/pcsc-fido/releases)
[![Documentation](https://img.shields.io/badge/docs-read-blue.svg)](docs/)
![Linux only](https://img.shields.io/badge/platform-Linux%20only-blue)

Daemon-side stopgap middleware for Linux: Exposes a virtual FIDO HID device via UHID to relay browser CTAP/U2F requests to NFC security keys over the PC/SC stack.

**Linux only** — this bridge targets Linux browser flows that do not already expose NFC FIDO cards through the platform WebAuthn stack.

## Quick start

You need: an NFC reader / Smart Card reader (examples below), an **NFC FIDO card / NFC enabled security key**, and Firefox, Chrome, or Brave.

1. **Set up PC/SC for your USB CCID reader (NFC reader / Smart Card reader)**

   Install the USB CCID reader driver, PC/SC daemon, and **`pcsc-tools`** (provides **`pcsc_scan`** for reader checks), then enable PC/SC at boot:

   Fedora/RHEL:

   ```sh
   sudo dnf install -y pcsc-lite-ccid pcsc-lite pcsc-tools
   sudo systemctl enable --now pcscd.socket
   ```

   Debian/Ubuntu:

   ```sh
   sudo apt-get install -y libccid pcscd pcsc-tools
   sudo systemctl enable --now pcscd.socket
   ```

   Enable **`pcscd.socket`** so the PC/SC listener is ready at boot; **`pcscd`** starts on the first client connection (socket activation). Use the socket unit, not **`pcscd.service`**.

2. **Install the bridge from a [GitHub release](https://github.com/neroduality/pcsc-fido/releases)**

   Download the `.rpm` or `.deb`, then install (packages declare core PC/SC runtime deps: **`pcscd`** and the USB CCID driver). Enable the **pcsc-fido** daemon when done:

   Fedora/RHEL:

   ```sh
   sudo dnf install ./pcsc-fido-*.rpm
   sudo systemctl enable --now pcsc-fido.service
   ```

   Debian/Ubuntu (local `.deb` from Downloads — use `dpkg`, not `apt install ./…`, if you see `_apt` permission denied):

   ```sh
   sudo dpkg -i ./pcsc-fido_*.deb
   sudo apt-get install -f
   sudo systemctl enable --now pcsc-fido.service
   ```

3. **Plug in your reader** — for example the [HID Global OMNIKEY 5022](https://www.hidglobal.com/products/omnikey-5022-reader) or [ACS ACR1252U](https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader/). Run **`pcsc_scan`** (from **`pcsc-tools`**) and confirm the reader appears. Without **`pcsc-tools`**, use **`pcsc-fido --list-readers`** instead.

4. **Try WebAuthn** — for repeated tests, use a resettable burner NFC token; registrations can consume limited credential slots.

   Open [webauthn.io](https://webauthn.io) and start registration or sign-in. The virtual browser key stays hidden until a fresh NFC FIDO card / NFC enabled security key presentation; place and hold the token on the reader to arm the bridge for 60 seconds, then complete the browser prompt. Small relay delays are normal.

   - [Cryptnox NFC FIDO cards](https://cryptnox.com/fido2-security-key-nfc-compatible-passwordless-key/): the tap/hold is presence; there is no separate touch button. If the card has or was set up with a PIN and the browser/RP asks for PIN/UV, a PIN prompt appears; otherwise it will not.
   - [YubiKey NFC security keys](https://www.yubico.com/us/product/yubikey-5-series/yubikey-5c-nfc/): keep the key on the reader and touch it when prompted. If the YubiKey has or was set up with a PIN and the browser/RP asks for PIN/UV, a PIN prompt appears; otherwise it will not.

## Documentation

Release packages install [INSTALLATION](INSTALLATION.md) and NOTICE under `/usr/share/doc/pcsc-fido/`. Additional docs live in [docs/](docs/):

The docs and source are also written for readers who want to understand how the bridge works—not only how to install it.

## Contributing

Contributions are welcome — see the org-wide [CONTRIBUTING](https://github.com/neroduality/.github/blob/main/CONTRIBUTING.md) guide. We deliberately leverage AI and automation, backed by human review and hardware testing, though the project remains in early development and is not yet production battle-tested.

## Security

`pcsc-fido` serves as a stopgap until the Linux credential stack matures to make this project—and the bridge it provides—entirely obsolete. See [REMEDIATIONS](docs/REMEDIATIONS.md) for the security posture and limits.

Report vulnerabilities via the org [SECURITY](https://github.com/neroduality/.github/blob/main/SECURITY.md) policy.

`pcsc-fido` has been open-sourced by [Nero Duality](https://neroduality.com/), which supports open tools that make WebAuthn with NFC FIDO cards and NFC-enabled security keys practical on Linux.

## License

See [LICENSE](LICENSE).

Last Updated: 2026-05-30
