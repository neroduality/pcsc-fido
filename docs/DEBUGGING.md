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

# Debugging pcsc-fido

Reproduce with live logs:

```bash
journalctl -u pcsc-fido -u pcscd -n 0 -f --no-pager
```

Quick checks:

```bash
systemctl status pcsc-fido --no-pager
ls -l /dev/uhid             # expect crw-rw---- root pcsc-fido
pcsc-fido --version
pcsc-fido --print-config    # resolved tap-arm / always mode and arm timing
pcsc-fido --list-readers
pcsc_scan                   # optional (pcsc-tools)
```

After install or upgrade, **`daemon-reload` does not replace a running daemon** — restart the bridge:

```bash
sudo systemctl restart pcsc-fido.service
```

Token presence, PIN, tap-vs-touch UX, and session concurrency: [REMEDIATIONS.md](REMEDIATIONS.md#bridge-vs-usb-hid) · [Safeguards](REMEDIATIONS.md#safeguards-for-pcsc-fido-nfc-specific).

## Debug build (APDU / CTAP detail)

Release binaries compile out protocol debug (`NDEBUG`); setting **`PCSC_FIDO_DEBUG=1` on Release has no effect**. Use a Debug source install:

```bash
make debug
sudo make install-debug INSTALL_PREFIX=/usr
journalctl -u pcsc-fido -u pcscd -n 0 -f --no-pager
```

Hex logs may include credential IDs and challenges — disable Debug logging when finished ([INSTALLATION.md](../INSTALLATION.md#2-source-install)).

## Log lines worth watching

| Build | Substring | Meaning |
| ----- | --------- | ------- |
| Always | `place the NFC key on the reader to arm` | Tap-arm dormant; present token to expose the virtual key. |
| Always | `virtual FIDO key armed` | Browser should see the key; keep the token on the reader. |
| Always | `virtual FIDO key arm window expired` | Lift and present the token again to re-arm (or raise **`PCSC_FIDO_ARM_SEC`**). |
| Always | `PC/SC bridge failed` | Relay error at INFO; message often includes `SCardTransmit: PC/SC 0x…`. Read the rest of the line and **`pcscd`** logs. |
| Always | `FIDO NFC card left the reader before connect` | Token lifted between presence detection and connect — hold on the reader and retry. |
| Always | `PC/SC session card no longer present` | Cached session invalidated by **`SCardStatus`** — bridge rebuilds on the next exchange. |
| Always | `cancelled while waiting` | Bridge cancel during PC/SC reader enumeration or NFC card wait. |
| Debug only | `completed WebAuthn operation` | Terminal **`makeCredential`** or signed **`getAssertion`**; PC/SC session reset (empty-hash preflight probes do not log this). |
| Debug only | `SCardTransmit failed; reconnecting PC/SC session once` | Stale handle or card movement; one reconnect retry (generation-checked snapshots). |
| Debug only | `using PC/SC reader` / `waiting for FIDO NFC card` | Reader selection and wait for token. |
| Debug only | `SCardConnect ok` / `FIDO SELECT` / `SCardTransmit` | PC/SC session and APDU relay (`hid=0x10` CBOR, `hid=0x03` U2F MSG). |

## Common issues

| Symptom | What to try |
| ------- | ----------- |
| No security key in the browser | Default is tap-arm: place the token on the reader until logs show `virtual FIDO key armed`, then use the browser prompt. Confirm `/dev/uhid` permissions and that `pcsc-fido.service` is active. Diagnostics only: `PCSC_FIDO_VIRTUAL_KEY=always`. |
| Key appeared, then disappeared | Arm window expired or token left the field — keep the token on the reader through the ceremony; lift and present again after `arm window expired`. |
| Key visible with no token | `PCSC_FIDO_VIRTUAL_KEY=always`, or stale browser UI — restart the service and refresh the tab. |
| Prompt stalls / CHANNEL_BUSY | CTAPHID or PC/SC rate limit — wait and retry. Local diagnosis only: `PCSC_FIDO_RATE_LIMIT=0` in a systemd drop-in (not for production). |
| Wrong reader | Set `PCSC_FIDO_READER` to a stable substring; run `pcsc-fido --list-readers` to see PC/SC names. Use `pcsc-fido --print-config` only for tap-arm mode and **`PCSC_FIDO_ARM_SEC`** (not reader selection). |
| Service will not start (`open /dev/uhid: Permission denied`, `status=217/USER`, or `/dev/uhid` missing) | `70-pcsc-fido.rules`, `pcsc-fido-uhid.conf` (boot), reinstall/postinst (`modprobe` + udev), `ensure-pcsc-fido-user.sh`, then `systemctl restart pcsc-fido.service`. |
| Start request repeated too quickly | Fix the underlying journal error, then `systemctl reset-failed pcsc-fido.service` and restart. |
| `SCardEstablishContext ... 0x8010006a` | PC/SC security violation — usually `pcscd` denied the `pcsc-fido` user; confirm `50-pcsc-fido.rules` is installed (`polkitd` reloads rules automatically). Restart the bridge after fixing. |
| `no PC/SC readers available` | Enable `pcscd.socket`, install `libccid` / `pcsc-lite-ccid`, plug/replug the reader, run `pcsc_scan`. |
| `CmdPowerOn Card absent` / power-up errors | Token not in the NFC field — hold it on the reader for the whole prompt. |
| `PC/SC reader name too long` | PC/SC reader string exceeds 256 bytes — rename the reader slot or set a shorter `PCSC_FIDO_READER` needle. |
| Ceremony fails right after arming | Normal NFC timing: keep the token on the reader through the whole browser prompt; see [safeguards](REMEDIATIONS.md#safeguards-for-pcsc-fido-nfc-specific). |
| `SCardListReaders ... 0x8010001d` | `pcscd` restarted while the bridge held a context — restart `pcsc-fido.service`. |
| `LIBUSB_ERROR_*` in `pcscd` logs | USB CCID reader/driver issue — replug, try another port, compare with known-good hardware. |
| Registration suddenly fails after repeated testing | NFC FIDO cards have limited credential storage; repeated `makeCredential` runs can fill the card. Reset or clear the NFC token (vendor reset/PIN management tool or card-specific factory reset), then retry. |
| APDU success in logs, browser still fails | Often browser/RP state or a full token — fresh tab/profile, clear site data, reset test credentials on burner tokens before changing bridge settings. |

Last Updated: 2026-05-30
