// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "pcsc_fido/attrs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pcsclite.h>

void mock_pcsc_reset(void);

void mock_pcsc_set_readers(const char* readers);
void mock_pcsc_set_reader_pair(const char* reader_a, const char* reader_b);
void mock_pcsc_set_list_probe_needed(DWORD needed);
void mock_pcsc_set_list_probe_no_readers_retries(unsigned retries);
void mock_pcsc_set_list_probe_always_no_readers(bool enabled);
void mock_pcsc_set_establish_fail_system_scope(bool enabled);
void mock_pcsc_set_establish_fail(LONG rv);
void mock_pcsc_set_list_probe_fail(LONG rv);
void mock_pcsc_set_list_fill_fail(LONG rv);
void mock_pcsc_set_get_status_fail(LONG rv);
void mock_pcsc_set_connect_fail(LONG rv);
void mock_pcsc_set_connect_proto_mismatch_once(bool enabled);
void mock_pcsc_set_connect_active_protocol(DWORD protocol);
void mock_pcsc_set_card_present_immediately(bool enabled);
void mock_pcsc_set_status_specific(bool enabled);
/* Forces the SCardStatus card-state dword (present, swallowed, powered) for
 * every later call until mock_pcsc_reset(). */
void mock_pcsc_set_status_state(DWORD state);
void mock_pcsc_set_status_present_sequence(const bool* present, size_t len);
void mock_pcsc_set_get_status_timeouts_before_present(unsigned count);
void mock_pcsc_set_multi_present_readers(bool enabled);
void mock_pcsc_set_transmit_fail(bool enabled);
void mock_pcsc_set_transmit_fail_once(bool enabled);
void mock_pcsc_set_transmit_wait_for_cancel(bool enabled);
/* Non-SELECT transmits block for `stall_ms`, ignoring SCardCancel; 0 = off. */
void mock_pcsc_set_transmit_stall_ms(unsigned stall_ms);
void mock_pcsc_set_transmit_response(const uint8_t* data, size_t len);
void mock_pcsc_set_select_first_fail(bool enabled);

unsigned mock_pcsc_transmit_call_count(void);
unsigned mock_pcsc_get_status_call_count(void);
PCSC_FIDO_NODISCARD bool mock_pcsc_cancel_during_transmit(void);
PCSC_FIDO_NODISCARD bool mock_pcsc_wait_for_transmit_waiting(
    unsigned timeout_ms);

// The mock's pcsclite entry points, bound to the real SCard* symbol names so
// the code under test links against them instead of libpcsclite.
LONG scard_establish_context(
    DWORD scope, LPCVOID reserved1, LPCVOID reserved2,
    LPSCARDCONTEXT context_out) __asm__("SCardEstablishContext");
LONG scard_release_context(SCARDCONTEXT context) __asm__("SCardReleaseContext");
LONG scard_list_readers(SCARDCONTEXT context, LPCSTR groups, LPSTR readers,
                        LPDWORD readers_len) __asm__("SCardListReaders");
LONG scard_get_status_change(
    SCARDCONTEXT context, DWORD timeout_ms, LPSCARD_READERSTATE reader_states,
    DWORD readers_count) __asm__("SCardGetStatusChange");
LONG scard_connect(SCARDCONTEXT context, LPCSTR reader, DWORD share_mode,
                   DWORD preferred_protocols, LPSCARDHANDLE card_out,
                   LPDWORD active_protocol_out) __asm__("SCardConnect");
LONG scard_disconnect(SCARDHANDLE card,
                      DWORD disposition) __asm__("SCardDisconnect");
LONG scard_status(SCARDHANDLE card, LPSTR reader_name_out,
                  LPDWORD reader_name_len_out, LPDWORD state_out,
                  LPDWORD protocol_out, LPBYTE atr_out,
                  LPDWORD atr_len_out) __asm__("SCardStatus");
LONG scard_transmit(SCARDHANDLE card, const SCARD_IO_REQUEST* send_pci,
                    LPCBYTE send_buffer, DWORD send_length,
                    LPSCARD_IO_REQUEST recv_pci, LPBYTE recv_buffer,
                    LPDWORD recv_length) __asm__("SCardTransmit");
LONG scard_cancel(SCARDCONTEXT context) __asm__("SCardCancel");
