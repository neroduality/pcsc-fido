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

# Security model and limits

Linux browsers speak WebAuthn only as CTAPHID over hidraw. An *NFC security key* (an NFC FIDO card, or an NFC-enabled security key such as a YubiKey 5 NFC) is reached through PC/SC (`pcscd`) instead. `pcsc-fido` is a stopgap between the two: it creates a *virtual key* (a virtual hidraw FIDO device) and relays CTAPHID to the NFC security key.

## Bridge vs USB security key

| | USB security key | pcsc-fido + NFC security key |
| - | ---------------- | ---------------------------- |
| hidraw peer | Security key firmware | This daemon |
| Visible to browser | While plugged in | For `PCSC_FIDO_ARM_SEC` after a tap (default 60 s) |
| Presence | Touch | Tap/hold on reader; NFC security keys with a touch sensor may also ask for a touch |
| PIN / UV | Browser <-> security key | Same; `clientPIN`, `pinUvAuthParam`, `options.uv` are passed through unchanged |
| Trusted computing base | Security key firmware, host USB/HID stack | Daemon, host UHID/HID stack, `pcscd`, reader + CCID driver, NFC security key firmware |

## Safeguards

| Area | Rule |
| ---- | ---- |
| Tap-arm | Monitor off while armed. Stale wakes drained on arm and expiry. Re-arm only after absent -> present. |
| UHID | Plain `open("/dev/uhid")`, no `access()` check first (no TOCTOU). |
| CTAP bytes | Wrapped as NFC APDUs. No synthesized or cached responses. |
| Memory | Relayed data is wiped after use; core dumps off: [Memory hygiene](C-STYLE-CODEFLOW.md#memory-hygiene). |
| Rate limits | Token buckets, refilled over `PCSC_FIDO_RATE_WINDOW_SEC` (90 s): `PCSC_FIDO_RATE_CTAPHID` INIT frames (60), `PCSC_FIDO_RATE_EXCHANGE` PC/SC exchanges (24). CANCEL is free. A failed monotonic clock denies. |
| Busy | One exchange at a time. `CHANNEL_BUSY` when throttled, busy, or another channel sends INIT during reassembly. |
| Concurrency | `session_reset` bumps a generation counter; stale `{card, pci, generation}` snapshots are rejected. Reset waits for in-flight transmits before releasing handles. |
| Presence checks | NFC security key confirmed in the field before `SCardConnect`. Session reused only if `SCardStatus` is `SCARD_POWERED` and not `SCARD_ABSENT`. |
| Service | User `pcsc-fido`, polkit for `pcscd`, hidraw via `uaccess`, systemd sandbox, never root. |
| Readers | Auto-select only when unambiguous, else FIDO SELECT probe (contactless first). Enumeration retries for 10 s. |

### PC/SC session reset triggers

- **Client:** UHID close/stop (drops that client's channels), `POLLERR`/`POLLHUP`/`POLLNVAL`, short read mid-exchange, owner CANCEL, owner channel evicted, INIT on the busy channel (resync keeps the channel ID).
- **PC/SC:** any failure after reaching the NFC security key, cancelled exchange, transmit failure, failed HID delivery.
- **CTAP:** delivered `makeCredential` or non-probe `getAssertion` (any status; kept if `numberOfCredentials` > 1), last `getNextAssertion`, empty or failed `getNextAssertion` mid-sequence, CBOR/MSG from another channel, owner sends anything but `getNextAssertion` mid-sequence.
- **Lifecycle:** daemon stop, arm expiry, 30 s idle.

**No reset:** exchange thread failed to start; empty-hash `getAssertion` probe with no open sequence; `getNextAssertion` with none left; rate-limited exchange; `ERR_MSG_TIMEOUT` (wipes only the partial request).

**CANCEL replies:** standalone: none. In-flight CBOR: `CTAP2_ERR_KEEPALIVE_CANCEL`. In-flight MSG: none.

## How a login is verified

The bridge is not part of this check; it only carries the bytes.

1. The relying party (RP, the website) sends a random, single-use challenge.
2. The browser checks that the site's origin may use the requested `rpId`, builds client data (`type`, `challenge`, `origin`), and sends its SHA-256 (`clientDataHash`) with the `rpId` to the NFC security key.
3. The NFC security key checks user presence (and PIN/UV if required), then signs `authenticatorData` (which contains SHA-256 of the `rpId`) together with `clientDataHash`, using the credential's private key.
4. The RP verifies the signature with the public key it stored at registration, and checks that the challenge is the one it issued, the origin is its own, and the `rpId` hash matches.

So a copied signature cannot be reused for another login or another site, and nothing that crosses the bridge lets anyone sign without the NFC security key.

## Limits

- A compromised daemon sits after the browser's origin check. It could replace a request with one for a different RP, so the NFC security key signs that instead when you tap. The same is true of any process allowed to reach `pcscd`. The NFC security key's presence and PIN/UV checks still apply; for NFC cards without a touch sensor, presence just means being on the reader.
- It cannot extract private keys or produce signatures without the NFC security key.
- It does not protect against a compromised host, a replaced package, a malicious browser, NFC security key firmware bugs, or a broken `pcscd`/reader stack.
- It adds NFC timing and reader-selection failure modes.
- Hardware-tested, not certified.

## Retirement

Long-term path: browsers reach NFC security keys through [credentialsd](https://github.com/linux-credentials/credentialsd) (0.3.x, pre-1.0) on [libwebauthn](https://github.com/linux-credentials/libwebauthn), which already does NFC over PC/SC.

State in October 2026: a browser extension for Firefox 140+ and Chromium/Edge 111+, an experimental portal-aware Firefox Flatpak, and `credentialsd` needs a patched `xdg-desktop-portal`. No browser ships portal support upstream.

This bridge can be retired once all of these ship:

1. Stable `credentialsd` / `libwebauthn` with NFC.
2. The portal upstream in `xdg-desktop-portal`.
3. Distros enable it.
4. Browsers, Chromium included, use the portal instead of hidraw.
