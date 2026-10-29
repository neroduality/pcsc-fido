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

# Debugging

```bash
journalctl -u pcsc-fido -u pcscd -n 0 -f --no-pager   # live logs
systemctl status pcsc-fido --no-pager
ls -l /dev/uhid                                       # expect crw-rw---- root pcsc-fido
pcsc-fido --version
pcsc-fido --print-config                              # virtual-key mode, arm window
pcsc-fido --list-readers
pcsc_scan                                             # optional, from pcsc-tools
```

After install or upgrade, restart the service. `daemon-reload` alone keeps the old binary running:

```bash
sudo systemctl restart pcsc-fido.service
```

## Debug build

Release builds compile out protocol logging, so `PCSC_FIDO_DEBUG=1` does nothing there. For APDU/CTAP detail:

```bash
make debug
sudo make install-debug INSTALL_PREFIX=/usr
```

> **Warning:** Debug logs hex-dump up to 220 bytes of each `getAssertion` request and response and of failed responses from the NFC security key: `rpId`, `clientDataHash`, credential IDs, signatures, `pinUvAuthParam`. These are not private keys or PINs, but they identify your credentials and stay in the journal on disk. Use a test NFC security key or throwaway credentials (for example on `webauthn.io`). Reinstall Release when done ([INSTALLATION](../INSTALLATION.md#debug-install)).

## Log lines

| Build | Substring | Meaning |
| ----- | --------- | ------- |
| All | `place the NFC key on the reader to arm` | Dormant; tap the NFC security key to create the virtual key. |
| All | `virtual FIDO key armed` | Virtual key visible to the browser. Keep the NFC security key on the reader. |
| All | `virtual FIDO key arm window expired` | Virtual key removed. Lift and re-tap, or raise `PCSC_FIDO_ARM_SEC`. |
| All | `PC/SC bridge failed` | Relay error. The rest of the line (often `SCardTransmit: PC/SC 0x...`) and `pcscd` logs say why. |
| All | `failed to deliver CTAP response` | The NFC security key answered but the HID reply was too large or the UHID write failed. Session reset. |
| All | `... during PC/SC exchange; resetting PC/SC session` | Client closed (`UHID client closed`) or re-sent INIT (`CTAPHID channel resynchronized`) mid-exchange. Session reset. |
| All | `FIDO NFC card left the reader before connect` | NFC security key left the field before `SCardConnect`. Hold it on the reader and retry. |
| All | `cancelled while waiting` | CANCEL arrived during reader enumeration or while waiting for the NFC security key. |
| Debug | `completed WebAuthn operation` | `makeCredential`, `getAssertion`, or last `getNextAssertion` delivered; session reset. |
| Debug | `SCardTransmit failed; reconnecting PC/SC session once` | Stale handle or the NFC security key moved; one retry. |
| Debug | `using PC/SC reader`, `waiting for FIDO NFC card` | Reader chosen; waiting for the NFC security key. |
| Debug | `SCardConnect ok`, `FIDO SELECT`, `SCardTransmit` | Session setup and APDU relay (`hid=0x10` CBOR, `hid=0x03` U2F). |

## Common issues

| Symptom | Fix |
| ------- | --- |
| Browser sees no security key | Tap the NFC security key and wait for `virtual FIDO key armed`. Check `/dev/uhid` permissions and that the service is active. For diagnosis only: `PCSC_FIDO_VIRTUAL_KEY=always`. |
| Virtual key appeared, then vanished | Arm window ended. Removing the NFC security key does not hide the virtual key; it fails the next exchange instead. Re-tap. |
| Virtual key visible with no NFC security key on the reader | `PCSC_FIDO_VIRTUAL_KEY=always` is set. Otherwise restart the service and reload the tab. |
| Prompt stalls (`CHANNEL_BUSY`) | Sent to the browser, not logged. Rate limit hit, exchange in progress, or another channel's INIT mid-request. `PCSC_FIDO_RATE_LIMIT=0` disables only the rate limit; not for production. |
| Wrong reader | Set `PCSC_FIDO_READER` to a substring from `pcsc-fido --list-readers`. |
| Won't start: `open /dev/uhid: Permission denied`, `status=217/USER`, or no `/dev/uhid` | Check `70-pcsc-fido.rules` and `pcsc-fido-uhid.conf`, re-run the package install (`modprobe uhid`, udev reload, `ensure-pcsc-fido-user.sh`), then restart. |
| `Start request repeated too quickly` | Fix the logged error, then `systemctl reset-failed pcsc-fido.service` and restart. |
| `SCardEstablishContext ... 0x8010006a` | polkit denied `pcsc-fido`. Confirm `50-pcsc-fido.rules` is installed, then restart the service. |
| `SCardListReaders ... 0x8010001d` | `SCARD_E_NO_SERVICE`: `pcscd` unreachable. Start `pcscd.socket`, then restart the service. |
| `no PC/SC readers available` | Enable `pcscd.socket`, install `libccid` / `pcsc-lite-ccid`, replug the reader, check `pcsc_scan`. |
| `CmdPowerOn Card absent`, power-up errors | The NFC security key left the field. Hold it on the reader for the whole prompt. |
| Fails right after arming | Same: keep the NFC security key in place until the browser prompt finishes. |
| `PC/SC reader name too long` | Reader name exceeds 256 bytes including NUL. (An overlong `PCSC_FIDO_READER` gives `no matching PC/SC reader` instead.) |
| `LIBUSB_ERROR_*` in `pcscd` logs | Reader or USB problem. Replug, try another port or reader. |
| Registration starts failing after many tests | The NFC security key's credential storage is full. Reset it with its vendor tool. |
| APDUs succeed, browser still fails | Browser or site state. Try a fresh tab or profile, clear site data, or reset test credentials. |
