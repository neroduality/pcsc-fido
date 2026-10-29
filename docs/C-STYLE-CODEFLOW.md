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

# Code flow and C style

This follows one login from the moment you tap your NFC security key until the website gets its signature. Source files are named at each step.

**Terms used here.** *NFC security key*: the physical authenticator, either an NFC FIDO card or an NFC-enabled security key such as a YubiKey 5 NFC. *Virtual key*: the USB-style FIDO device that `pcsc-fido` creates for the browser. PC/SC itself calls whatever sits on the reader a "card"; that word appears below only in PC/SC API names.

```text
browser -> virtual key (/dev/hidraw*) -> kernel UHID -> /dev/uhid -> pcsc-fido -> pcscd -> reader -> NFC security key
```

The browser believes it is talking to a USB security key. It is talking to the virtual key, and `pcsc-fido` carries each message, unchanged, to the NFC security key. The NFC security key holds the private keys and performs every check that matters: user presence, PIN, and signing.

## A login, step by step

### 1. Startup

`browser_daemon.c` turns off core dumps, reads the environment (`daemon_config.c`), and enters the tap-arm loop (`tap_arm.c`). No virtual key exists yet.

### 2. You tap the NFC security key

`card_monitor.c` watches the readers with `SCardGetStatusChange`, without connecting to anything. When the NFC security key enters a reader's field, it wakes `tap_arm.c`, which stops the monitor and creates the virtual key (`UHID_CREATE2` in `uhid_transport.c`). The virtual key exists for `PCSC_FIDO_ARM_SEC` seconds (default 60).

### 3. The browser finds the virtual key

The website calls `navigator.credentials.get()` with a random challenge. The browser sees a new FIDO HID device and sends `CTAPHID_INIT` on the broadcast channel. `daemon_request_handler.c` answers it locally and `daemon_channels.c` assigns the browser its own channel ID (up to 8 at once). `PING` and `WINK` are also answered locally; they never reach the NFC security key.

### 4. The browser sends the request

The browser builds client data (challenge, origin, type), hashes it into `clientDataHash`, and sends `authenticatorGetAssertion` (CTAP command `0x02`) with the `rpId`, `clientDataHash`, the allowed credential IDs, and options. The message arrives as 64-byte HID reports, which `request_assembly.c` joins back into one request. If the next report doesn't arrive within 3 s, the request is dropped with `ERR_MSG_TIMEOUT`.

If the site requires a PIN, the browser first runs `authenticatorClientPIN` (`0x06`) through this same path to get a PIN token from the NFC security key, then includes `pinUvAuthParam` in the request.

### 5. The daemon hands it to a worker

`daemon_request_handler.c` checks the rate limit and that no other exchange is running (otherwise `CHANNEL_BUSY`). `exchange_orchestrator.c` starts a worker thread for the PC/SC exchange and keeps the browser waiting with a `KEEPALIVE` every 100 ms.

### 6. The worker reaches the NFC security key

`pcsc_bridge.c` drives this, using `pcsc_session.c` and `pcsc_reader_ops.c`:

1. If the PC/SC session from the previous command is still open and `SCardStatus` reports `SCARD_POWERED` (not `SCARD_ABSENT`), reuse it.
2. Otherwise pick the reader (`PCSC_FIDO_READER`, or the only usable one, or the one whose NFC security key answers FIDO SELECT), wait for the NFC security key, confirm it is still in the field, `SCardConnect`, and SELECT the FIDO applet (AID `A0000006472F0001`).
3. Wrap the CTAP message in an APDU: `80 10 00 00 Lc <request> 00`, or the extended-length form above 255 bytes (`apdu.c`).
4. Send it (`apdu_chain.c`). If the reply is `61xx` ("more data"), fetch the rest with GET RESPONSE.
5. If the transmit fails, reconnect once and retry.

### 7. The NFC security key authenticates you

This is the only step that proves who you are, and it happens entirely on the NFC security key:

1. It looks up a credential for the `rpId`.
2. It checks user presence. On NFC cards the tap itself is presence; NFC security keys with a touch sensor ask for a touch.
3. If a PIN was used, it checks `pinUvAuthParam` against the PIN token it issued.
4. It signs `authenticatorData` (which includes SHA-256 of the `rpId` and a signature counter) together with `clientDataHash`, using the credential's private key.

It returns a CTAP status byte, the CBOR response (credential ID, `authenticatorData`, signature, and `numberOfCredentials` if several credentials matched), and the ISO status word `90 00`.

### 8. The answer goes back

`pcsc_bridge.c` treats any status word other than `90 00` as a failure, strips it, and returns the CTAP response. `uhid_transport.c` splits it into HID reports on the browser's channel. The browser passes the assertion to the website, which verifies the signature and checks the challenge, origin, and `rpId` ([details](REMEDIATIONS.md#how-a-login-is-verified)).

### 9. Cleanup

`daemon_request_handler.c` closes the PC/SC session once a `getAssertion` result is delivered. The exception is `numberOfCredentials` = n > 1: the session stays open for up to min(n-1, 32) `authenticatorGetNextAssertion` calls. All buffers that held the request and response are wiped. When the arm window ends, `tap_arm.c` removes the virtual key and closes any session; the NFC security key must leave the reader and return to arm again.

### Variations

- **Registration** follows the same path with `authenticatorMakeCredential` (`0x01`). The NFC security key creates a key pair and returns the new credential ID, public key, and attestation. The session closes after delivery.
- **Silent probe:** browsers may first send `getAssertion` with `clientDataHash` set to SHA-256 of the empty string, just to see which allowed credential exists. That does not close the session.
- **U2F** (`CTAPHID_MSG`): the browser already sends a complete APDU. It is forwarded as is, and the reply keeps its status word.
- **Cancel:** `CTAPHID_CANCEL` from the same channel calls `SCardCancel`. A transmit already in progress can't be interrupted; when it returns, a CBOR request gets `CTAP2_ERR_KEEPALIVE_CANCEL`.
- **Idle:** a session left open (probe, PIN, or `getNextAssertion`) closes after 30 s without a command.
- **`PCSC_FIDO_VIRTUAL_KEY=always`** skips tap-arm (`daemon_uhid_loop.c`): the virtual key is always visible and has no arm window.

Every reason the PC/SC session gets reset: [Safeguards](REMEDIATIONS.md#safeguards).

## What passes through the daemon

Private keys never leave the NFC security key; CTAP has no command to export them. The daemon only relays these messages:

| Data | What it is | Use to an attacker who copies it |
| ---- | ---------- | -------------------------------- |
| `clientDataHash` | SHA-256 of the browser's client data (challenge, origin, type) | None; it commits to a single-use challenge |
| Signature, `authenticatorData` | The NFC security key's signature over `authenticatorData` and `clientDataHash` | None; valid for that one challenge and site only |
| Credential ID, public key, attestation | Names a credential at one site. A credential ID may wrap a private key encrypted under a key that never leaves the NFC security key | Linking you to an account (privacy), not signing in |
| PIN protocol messages | PIN hash encrypted under an ECDH key shared only by the browser and the NFC security key; `pinUvAuthParam` is an HMAC tied to one request | The daemon never sees the PIN in plaintext |

## Memory hygiene

The data above is not key material, but it is wiped promptly so it does not linger:

- Buffers holding UHID events, HID packets, APDUs, or responses are wiped at scope exit via `__attribute__((cleanup))` (`PCSC_FIDO_SCRUB_ON_EXIT`). The reassembly buffer is wiped when its request finishes or is dropped.
- Wipe primitive: `memset_explicit`, else `explicit_bzero`, else a volatile byte loop.
- `make test` runs a scrub-mutant sweep: each wipe in `src/` is removed in turn and its test must fail.
- At startup the daemon sets `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` and exits if either fails; the unit also sets `LimitCORE=0`. `abort`, `_exit`, and fatal signals skip the wipes.
- Not covered: no `mlockall` (pages can swap). Copies in the browser, kernel UHID/hidraw buffers, libpcsclite, and `pcscd` are out of reach.

## Service permissions

Runs as user `pcsc-fido`, never root. polkit grants it `pcscd` access. `/dev/uhid` is `0660 root:pcsc-fido`. The virtual hidraw node is `0600` with `uaccess`, so only the logged-in seat user's browser can open it.

## C conventions

- ISO C23, GNU extensions off. Configure requires GCC >= 13 or Clang >= 16 and `__attribute__((cleanup))`.
- Fallible functions return `bool` and write the error into a caller-supplied buffer. `PCSC_FIDO_NODISCARD` is `[[nodiscard]]` only when `__STDC_VERSION__ >= 202311L` (GCC 13 reports less).
- Length arithmetic is overflow-checked; copies that would overrun fail.
- No heap. `make lint` bans `malloc`/`free`, `strcpy`, `sprintf`, the `scanf` family, and `system`.

## Build hardening

### Where the flags come from

`cmake/Hardening.cmake` and `cmake/CompilerHardeningProbes.cmake` are generated files. Do not edit them by hand.

- **Source:** the org lint kit ([neroduality/.github](https://github.com/neroduality/.github), `lint-c-cpp/`) generates both from its `config/openssf-hardening-manifest.yaml`, which encodes the [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) plus a few extra flags.
- **Probes:** `CompilerHardeningProbes.cmake` tests each flag against the compiler and linker at configure time (`HAVE_*` cache variables). A flag the toolchain lacks is skipped, not fatal.
- **Wiring:** `CMakeLists.txt` includes `Hardening.cmake` and calls `define_hardening(TARGET hardening C_STANDARD 23)`. `pcsc_fido_core`, and through it the daemon and tests, links that `hardening` interface library.
- **Repo-specific changes** live only in `policy.overrides.openssf-hardening` in `.github/lint-c-cpp.yaml`. pcsc-fido uses its `cross` list to keep PIE, `-z relro`, `-z now`, `-z noexecstack`, `-z text`, `-z pack-relative-relocs`, `--error-execstack`, `--error-rwx-segments`, and `-fexceptions` on cross builds. The kit baseline applies those to native builds only.
- **Regeneration:** `make lint` regenerates both files and fails if they differ from what is committed. To change a flag, edit the override, run `make lint`, and commit the regenerated files.

### Resulting flags

| Flag | When |
| ---- | ---- |
| `-Werror` | Default. Distro source builds (`debian/rules`, RPM spec) pass `-DHARDENING_WERROR=OFF`. |
| `-fstack-protector-strong`, PIE, `-z relro -z now -z noexecstack` | Always. |
| `-fhardened`, else `-D_FORTIFY_SOURCE=3` (native only) | Release, RelWithDebInfo, MinSizeRel; not with sanitizers. |
| `-O2` | Native Release and RelWithDebInfo. Cross builds keep CMake's default (`-O3` for Release). |
| LTO | Release, RelWithDebInfo, MinSizeRel, if supported and no sanitizers or coverage. |
| Strip | Release, MinSizeRel. |
