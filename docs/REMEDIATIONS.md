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

# Remediations and limits

**pcsc-fido** is a stopgap for Linux browsers that speak WebAuthn only over **CTAPHID/hidraw**, while an NFC FIDO token is a **physical card** on a CCID reader, reached through **PC/SC** (`pcscd`). It exposes a **virtual** hidraw device; the bridge is the **hidraw peer** and forwards CTAPHID to the card over PC/SC.

## Bridge vs USB HID

| | USB HID key | pcsc-fido + NFC |
| - | ----------- | --------------- |
| Path | USB HID → **hidraw** (CTAPHID to token firmware) | Browser → **hidraw** (virtual key) → kernel UHID → **/dev/uhid** (bridge) → **pcscd** → reader → NFC token |
| Browser visibility | While plugged in | Default **tap-arm**: hidden until a card is present, armed for a timed window (`PCSC_FIDO_ARM_SEC`), and re-armed only after an absent → present transition |
| Presence | Touch button (many models) | Tap/hold on reader; touchless cards treat tap as presence; NFC tokens with a separate touch sensor may require an additional touch when prompted |
| PIN / UV | Browser ↔ token | Same rules; bridge preserves CTAP CBOR fields (`clientPIN`, `pinUvAuthParam`, `options.uv`, etc.) and does not bypass browser PIN prompts |
| Trust (CTAPHID) | **hidraw** peer = token firmware (USB device). Handles CTAPHID; keys on USB key. **TCB (trusted computing base):** USB FIDO gadget; host USB/hid stack; USB token firmware | **hidraw** peer = **bridge** (forwards CTAPHID over PC/SC; not NFC card firmware). Handles CTAPHID; keys on NFC card. **TCB (trusted computing base):** bridge ([shortcomings](#shortcomings)); host UHID/hid stack; pcscd; CCID reader + driver; NFC card firmware |

## Safeguards for `pcsc-fido` (NFC-specific)

| Area | Remediation |
| ---- | ----------- |
| Tap-arm | Stops the card-present wake monitor while armed and drains stale wake signals on arm/expiry, so a token left on the reader cannot immediately re-arm after timeout. |
| UHID open | Filesystem TOCTOU on `/dev/uhid` is avoided by opening the device directly (no prior `access()`). For log strings and operator steps, see [DEBUGGING.md](DEBUGGING.md). |
| CTAP forwarding | Preserves CTAP CBOR/MSG payloads at the CTAP layer, encapsulates them as CTAP-over-NFC APDUs for PC/SC, does not synthesize CTAP responses, and keeps no compatibility cache. |
| DoS containment | Rate-limits CTAPHID frames and PC/SC exchanges (rolling window); serializes in-flight PC/SC work; returns CTAPHID `CHANNEL_BUSY` when throttled or busy. |
| Session cleanup | Resets CTAPHID reassembly and the PC/SC session on UHID close/stop, CTAPHID CANCEL, successful terminal WebAuthn ops (`makeCredential` and signed `getAssertion`, but not empty-hash preflight probes), arm expiry/disarm, and PC/SC transmit failures. Standalone CTAPHID CANCEL has no direct HID response; in-flight cancellation completes the original CBOR request with `CTAP2_ERR_KEEPALIVE_CANCEL`. |
| Session concurrency | Monotonic **generation** on each `session_reset`; transmit snapshots carry `{card, pci, generation}` and are rejected after reset/cancel/close races; active transmits are tracked so `session_reset` waits to release handles, while `session_cancel` can still reach `SCardCancel` during a blocking `SCardTransmit`; `session_verify_ready` uses `SCardStatus` before reusing a cached session; reader presence is re-checked immediately before `SCardConnect`. |
| Service hardening | Dedicated `pcsc-fido` user, polkit access to `pcscd`, active-seat `uaccess` for the virtual hidraw node, strict systemd sandbox, no root runtime. |
| Compatibility | Reader auto-selection only when unambiguous (single reader, or a single contactless non-SAM slot from a SAM/PICC pair), card-presence tiebreaker, **FIDO probe when several readers show cards**; PC/SC reader-enumeration retry window. |

## Shortcomings

**pcsc-fido** is a **bridge**, not a native Linux WebAuthn path (see [Trust](#bridge-vs-usb-hid)). The browser’s **hidraw** peer is this daemon, not NFC card firmware; CTAPHID is forwarded over PC/SC while the card holds the signing keys. That enlarges the **trusted computing base** beyond USB’s (USB FIDO gadget, host USB/hid stack, USB token firmware) to include the **bridge**, host UHID/hid stack, **pcscd**, CCID reader + driver, and NFC card firmware. The same hidraw observe/alter risk applies: a **rogue USB FIDO gadget** is a malicious peer on USB, and a **compromised bridge** is the parallel risk here.

A compromised **bridge** still cannot extract private keys from the card or sign without card cooperation (tap/PIN/UV as required); honest RPs still verify challenge, origin, and `rpId`. The **bridge** also cannot fix compromised hosts, replaced packages, malicious browsers, card firmware bugs, browser/RP state, or broken **pcscd**/reader stacks. It adds timing-sensitive NFC UX and reader-selection/startup seams. It is tested on real hardware but is not a formal certification boundary.

## Preferred long-term outcome

The best remediation is for Linux to make this bridge obsolete: browsers and desktop credential services should reach NFC FIDO cards on CCID readers through PC/SC without a UHID shim. The likely direction is the Linux Credentials stack — for example [libwebauthn](https://github.com/linux-credentials/libwebauthn), [credentialsd](https://github.com/linux-credentials/credentialsd), and portal integration — so WebAuthn and `pcscd` share one platform path. Until that path is broadly shipped and used by browsers, unmodified Linux browser tabs still speak CTAPHID over hidraw, and **pcsc-fido** aims to keep this stopgap narrow, observable, packaged, and hardened.

Last Updated: 2026-05-30
