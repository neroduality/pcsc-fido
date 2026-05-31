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

# Code Flow and C23 Style

Concise companion to the source: first **how a request flows** between the
browser and the card, then **how the C is written**; it makes no
"always/all" guarantee the code does not enforce.

## Modules

| File | Role |
| --- | --- |
| `browser_daemon.c` | Entry point, CLI (`--help`, `--version`, `--print-config`, `--list-readers`), mode dispatch. |
| `daemon_config.c` | Env-based virtual-key mode and tap-arm timing configuration. |
| `daemon_signals.c` | `sigaction` handlers and atomic stop flag; poll loops observe shutdown via bounded timeouts (no signal wake pipe). |
| `daemon_uhid_loop.c` | UHID event dispatch, shared poll/read loop, always-mode runner. |
| `tap_arm.c` | Card-gated tap-to-arm state machine (wake pipe, monitor, arm/disarm deadlines, stale-wake drain). |
| `card_monitor.c` | PC/SC polling thread for fresh absent-to-present card edges (**presence-only** wake; no connect/SELECT). |
| `request_assembly.c` | CTAPHID INIT/continuation reassembly into a bounded pending buffer. |
| `daemon_request_handler.c` | CTAPHID dispatch; local commands vs CBOR/MSG forwarding. |
| `daemon_rate_limit.c` | Rolling-window DoS guard. |
| `exchange_orchestrator.c` | Single-flight PC/SC worker thread with KEEPALIVE and CANCEL draining. |
| `uhid_transport.c` | UHID CREATE2/DESTROY and CTAPHID response/error/keepalive framing. |
| `daemon_hid.c` | CTAPHID packet helpers (CID, INIT decode, CANCEL, payload normalize). |
| `daemon_policy.c` | Classifies CTAP requests (getAssertion, terminal vs. probe via empty-clientDataHash marker) for session-reset and logging. |
| `pcsc_bridge.c` | Public PC/SC bridge API: CTAPHID→APDU exchange; reset/cancel delegates. |
| `pcsc_session.c` | Single-daemon PC/SC session: context/card handles, **generation** counter, mutex, `verify_ready`, snapshot TX, connect, FIDO SELECT, transmit/chain, ensure/reset/cancel. |
| `pcsc_reader_ops.c` | Reader enumeration, env-based selection, card-present wait, **`confirm_card_present`** before connect, multi-reader poll. |
| `pcsc_err.c` | Centralized `set_err` / `format_err` (explicit truncation marker when the buffer is too small). |
| `pcsc_log.c` | Leveled `pcsc_fido_log()` to stderr (`DEBUG` gated by `PCSC_FIDO_DEBUG`). |
| `pcsc_bridge_debug.c` | Debug-only CBOR/hex logging (`PCSC_FIDO_DEBUG`; stripped in Release). |
| `reader_select.c` | Reader-name matching, SAM filtering, contactless-slot detection. |
| `apdu.c` | FIDO NFC APDU parse/pack: shared **`pcsc_fido_pack_select_fido_apdu()`**, CTAP2 CBOR pack. |
| `apdu_chain.c` | ISO 7816 `61xx` GET RESPONSE chaining. |
| `cbor_util.c` | Bounded CBOR type/length/skip/read helpers. |
| `ctaphid.c` | CTAPHID frame encode/decode and standalone exchange helper. |

`include/pcsc_fido/version.h` is generated at configure time from `version.h.in` and
`project(VERSION …)` in `CMakeLists.txt` (single release version source). It defines
`PCSC_FIDO_VERSION_MAJOR` / `_MINOR` / `_PATCH` and `PCSC_FIDO_VERSION`.

Local libFuzzer harnesses (optional, Clang): `tests/fuzz/fuzz_cbor_util.c`,
`tests/fuzz/fuzz_request_assembly.c`, `tests/fuzz/fuzz_apdu.c` — run via `make fuzz` or
`.github/scripts/run-local-fuzz.sh` (host-only build tree `.fuzz/`; default 180s/target,
`-max_len` 8192 / 16384, ASan+UBSan when supported).

## Request flow

The same path carries every ceremony; only the CTAP command byte differs
(see [Registration vs authentication](#registration-vs-authentication)).

### Outbound — browser request reaches the card

1. **Read + reassemble.** `daemon_uhid_loop.c` polls `/dev/uhid`, dispatches
   `UHID_OUTPUT` through the CTAPHID frame rate limit, and feeds the 64-byte packet
   to `request_assembly.c`, which splits INIT (high
   bit on byte 4) from continuation frames, rejects lengths above
   `PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD` (7609 = 57 + 128×59, the framing
   ceiling), copies the 57/59-byte fragments via `pcsc_fido_copy_bytes`, and
   accumulates the length with the overflow-checked `PCSC_FIDO_TRY_ADD`.
2. **Dispatch.** `daemon_request_handler.c` answers local commands (`INIT`,
   `PING`, `WINK`, `LOCK`, `CANCEL`); standalone `CANCEL` resets without a direct
   HID response, and only `CBOR` and `MSG` are forwarded, after
   the PC/SC exchange rate limit.
3. **Single-flight worker.** `exchange_orchestrator.c` runs one
   `pcsc_fido_bridge_exchange()` on a worker thread while the main loop sends
   KEEPALIVE (~750 ms), drains CANCEL/close into `SCardCancel()`, and answers
   unrelated traffic with `CHANNEL_BUSY`.
4. **Session + APDU.** `pcsc_fido_session_ensure()` reuses a cached session only when
   `pcsc_fido_session_verify_ready()` (`SCardStatus`) succeeds; otherwise it resets,
   enumerates/selects a reader, waits for presence, **`pcsc_fido_reader_confirm_card_present()`**
   immediately before `SCardConnect`, runs shared **`pcsc_fido_pack_select_fido_apdu()`**
   for FIDO AID `A0000006472F0001`, then `pcsc_fido_pack_ctap2_cbor_apdu()` wraps CTAP
   as `80 10 00 00 …` (short form when ≤255 bytes, else extended). `pcsc_fido_session_snapshot_tx()`
   captures `{card, pci, generation}`; `pcsc_fido_session_tx_is_current()` rejects stale
   snapshots after concurrent `session_reset` (UHID close, CANCEL, arm expiry).
5. **Transmit + chain.** `apdu_chain.c` sends via `SCardTransmit` and completes
   `61xx` with GET RESPONSE (`00 C0 00 00`), accumulating until `9000`.

### Inbound — card response reaches the browser

1. **Validate + strip.** For CBOR the bridge requires `SW=9000` and a CTAP
   response of at least 3 bytes (status + SW), then strips the 2-byte status
   word (`rapdu_len -= 2`). Anything else resets the session and surfaces the
   CTAP status byte.
2. **Reframe.** `uhid_transport.c` re-fragments the CTAP bytes into one INIT plus
   continuation frames (sequence `0..0x7F`, refusing to encode beyond the framing
   ceiling) and writes `UHID_INPUT2` events, retrying partial writes and `EINTR`.
   The browser reassembles the response and returns the WebAuthn result.

### Registration vs authentication

Both ceremonies traverse the identical transport above with byte-identical CBOR
handling; the only meaningful difference is the CTAP command byte —
`makeCredential` (`0x01`) mints a new credential keypair and returns an
attestation object, while `getAssertion` (`0x02`) returns an assertion signature
over the relying party's challenge. Both preserve the CTAP CBOR payload bytes
before NFC APDU encapsulation. `daemon_policy.c` treats `makeCredential` and signed
`getAssertion` (non-empty `clientDataHash`) as terminal operations, so after
success the session is reset: PC/SC is disconnected and the session state is
cleared. Empty-hash preflight `getAssertion` probes are forwarded like any other
request but do not trigger that reset. Keys never leave the card in either
ceremony.

## C23 style and safety

**Baseline:** ISO C23, extensions off (`CMAKE_C_STANDARD 23`). `cmake/VerifyCompiler.cmake` requires GCC ≥ 13 / Clang ≥ 16 and probes `nullptr`, `<stdckdint.h>`, and `memset_explicit`. Code uses `nullptr`/`bool`, atomics for cross-thread state, and fallible `bool` APIs with `[[nodiscard]]` plus caller `char *err` / `size_t err_cap`.

**Host hardening:** Release builds apply the [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) TL;DR compile/link set via `cmake/HostHardening.cmake` — PIE, `_FORTIFY_SOURCE=3`, stack/CET or AArch64 branch protection (native), `-fexceptions`, GCC `-Wtrampolines` / `-Wbidi-chars=any` / `-fzero-init-padding-bits=all` when probed, Clang `-Wimplicit-fallthrough` when probed, selective `-Werror=*` for format/obsolete-C conversions, and RELRO/NOW/noexecstack/nodlopen/`--as-needed` linker hygiene. Intentional non-parity: pure C (no `_GLIBCXX_ASSERTIONS`), no blanket `-Werror`, Release `-O3` not `-O2`, cross builds may omit arch-specific CET/branch flags. Release LTO when sanitizers and coverage are off.

**Attributes (`attrs.h`):** Centralized, feature-probed macros (no-op on older toolchains). `[[unsequenced]]` / `[[reproducible]]` sit after the parameter list and only on side-effect-free readers.

| Macro | C23 form | Use |
| --- | --- | --- |
| `PCSC_FIDO_NODISCARD` | `[[nodiscard]]` | Fallible public `bool` APIs |
| `PCSC_FIDO_MAYBE_UNUSED` | `[[maybe_unused]]` | Signal-handler parameters |
| `PCSC_FIDO_UNREACHABLE()` | `unreachable()` | CBOR switch defaults |
| `PCSC_FIDO_STATIC_ASSERT` | `static_assert` | Wire-format size invariants |
| `PCSC_FIDO_UNSEQUENCED` | `[[unsequenced]]` | Stateless predicates (`pcsc_fido_span_ok`) |
| `PCSC_FIDO_REPRODUCIBLE` | `[[reproducible]]` | Pure readers (`pcsc_fido_parse_apdu`, …) |

**Wire invariants:** `static_assert` keeps buffers aligned with the protocol — CTAPHID framed max 7609 (`ctaphid.h`), 64-byte HID report (`uhid_transport.c`), 8-byte FIDO AID (`apdu.h`), pending buffer = CTAPHID cap (`request_assembly.h`), chain cap ≥ payload cap (`apdu_chain.h`).

**`mem_util.h`:** Checked arithmetic (`pcsc_fido_try_add_*`, `PCSC_FIDO_TRY_ADD`), span checks (`pcsc_fido_span_ok`), bounded copy/move/strlen, and `pcsc_fido_secure_clear` (`memset_explicit` or volatile fallback). Initialize accumulators explicitly (`size_t end = 0u`). `make lint` rejects unbounded C APIs (`strcpy`, `sprintf`, `system`, `*scanf`, …).

**Parsers and session:** CTAPHID reassembly, APDU shape, `61xx` chaining (with **cancel checks** in the chain loop), and CBOR length/depth (max 32) are validated before copy — reject mismatches, never repair. CTAP CBOR/MSG payload bytes are preserved at the CTAP layer and encapsulated as CTAP-over-NFC APDUs; no synthesized responses or compat cache. `pcsc_session.c` owns the single-daemon PC/SC session (context, card handle, transmit PCI, monotonic **generation**, cancel flag) behind one mutex; committed **`session_transmit_chained`** validates the generation before transmitting, tracks active transmits while the mutex is released around `SCardTransmit`, and lets reset/cancel reach `SCardCancel` without releasing handles until active work exits. `pcsc_bridge.c` snapshots TX handles, checks generation around transmit, and delegates reset/cancel. Reader names use `pcsc_fido_copy_cstr` / `PCSC_FIDO_READER_NAME_MAX` (256); stack error buffers use `PCSC_FIDO_ERR_MSG_MAX`; errors go through `pcsc_err.c`.

**Errors:** Fallible APIs take `char *err` / `size_t err_cap`. Use `pcsc_fido_set_err`, `pcsc_fido_set_pcsc_err`, or `pcsc_fido_format_err` — not raw `snprintf` on bridge paths. When the buffer is too small, `format_err` still NUL-terminates and appends `(truncated)`.

When adding C code: length-aware external input, span-checked writes, checked size math, explicit parser failures with tests.

Last Updated: 2026-05-30
