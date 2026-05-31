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

#define _POSIX_C_SOURCE 200809L

#include "pcsc_fido/apdu.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_reader_ops.h"
#include "pcsc_fido/pcsc_session.h"
#include "pcsc_fido/pcsc_util.h"
#include "pcsc_fido/reader_select.h"

#include <winscard.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static bool pcsc_no_readers(LONG rv) {
#if defined(SCARD_E_NO_READERS_AVAILABLE)
  return rv == SCARD_E_NO_READERS_AVAILABLE;
#else
  return (unsigned long)rv == 0x8010002eUL;
#endif
}

bool pcsc_fido_reader_establish_context(SCARDCONTEXT *ctx, pcsc_fido_reader_ctx_scope_t scope,
                                        char *err, size_t err_cap) {
  LONG rv;
  if (ctx == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid PC/SC context arguments");
    return false;
  }
  if (scope == PCSC_FIDO_READER_CTX_DAEMON) {
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, ctx);
    if (rv != SCARD_S_SUCCESS) {
      rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, ctx);
    }
  } else {
    rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, ctx);
  }
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardEstablishContext", rv);
    return false;
  }
  return true;
}

const SCARD_IO_REQUEST *pcsc_fido_reader_pci_for_protocol(DWORD active_protocol) {
  if ((active_protocol & SCARD_PROTOCOL_T1) != 0u) {
    return SCARD_PCI_T1;
  }
  if ((active_protocol & SCARD_PROTOCOL_T0) != 0u) {
    return SCARD_PCI_T0;
  }
  if ((active_protocol & SCARD_PROTOCOL_RAW) != 0u) {
    return SCARD_PCI_RAW;
  }
  return nullptr;
}

static bool reader_list_fill_once(SCARDCONTEXT ctx, char *buf, DWORD *buf_len, char *err,
                                  size_t err_cap) {
  LONG rv;
  DWORD needed = 0u;
  if (buf == nullptr || buf_len == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid reader list arguments");
    return false;
  }
  rv = SCardListReaders(ctx, nullptr, nullptr, &needed);
  if (rv != SCARD_S_SUCCESS || needed == 0u) {
    if (rv == SCARD_S_SUCCESS || pcsc_no_readers(rv)) {
      pcsc_fido_set_err(err, err_cap, "no PC/SC readers available");
    } else {
      pcsc_fido_set_pcsc_err(err, err_cap, "SCardListReaders(probe)", rv);
    }
    return false;
  }
  if (needed > *buf_len) {
    pcsc_fido_set_err(err, err_cap, "too many PC/SC readers");
    return false;
  }
  rv = SCardListReaders(ctx, nullptr, buf, &needed);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardListReaders(fill)", rv);
    return false;
  }
  if (!pcsc_fido_reader_list_is_valid(buf, needed)) {
    pcsc_fido_set_err(err, err_cap, "invalid reader listing output");
    return false;
  }
  *buf_len = needed;
  return true;
}

bool pcsc_fido_reader_list_snapshot(SCARDCONTEXT ctx, char *buf, DWORD *buf_len, char *err,
                                    size_t err_cap) {
  return reader_list_fill_once(ctx, buf, buf_len, err, err_cap);
}

size_t pcsc_fido_reader_fill_status_states(const char *readers, size_t readers_len,
                                           SCARD_READERSTATE *states, size_t states_cap) {
  size_t count = 0u;
  size_t off = 0u;
  if (readers == nullptr || states == nullptr || states_cap == 0u) {
    return 0u;
  }
  while (off < readers_len) {
    pcsc_fido_reader_list_entry_result_t entry_result;
    const char *entry;
    size_t entry_len;
    if (readers[off] == '\0') {
      break;
    }
    entry_result = pcsc_fido_reader_list_next(readers, readers_len, &off, &entry, &entry_len);
    if (entry_result != PCSC_FIDO_READER_LIST_ENTRY_OK) {
      break;
    }
    if (count >= states_cap) {
      pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                    "PC/SC reader status list truncated at %u readers; additional readers ignored",
                    (unsigned)states_cap);
      break;
    }
    states[count].szReader = entry;
    states[count].dwCurrentState = SCARD_STATE_UNAWARE;
    states[count].dwEventState = 0;
    count++;
  }
  return count;
}

bool pcsc_fido_reader_list(SCARDCONTEXT ctx, char *buf, DWORD *buf_len, char *err, size_t err_cap) {
  LONG rv;
  time_t deadline =
    pcsc_fido_add_seconds_saturating(time(nullptr), PCSC_FIDO_BRIDGE_READER_ENUM_TIMEOUT_SEC);
  if (buf == nullptr || buf_len == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid reader list arguments");
    return false;
  }
  do {
    DWORD needed = 0u;
    rv = SCardListReaders(ctx, nullptr, nullptr, &needed);
    if (rv == SCARD_S_SUCCESS && needed > 0u) {
      if (needed > *buf_len) {
        pcsc_fido_set_err(err, err_cap, "too many PC/SC readers");
        return false;
      }
      rv = SCardListReaders(ctx, nullptr, buf, &needed);
      if (rv == SCARD_S_SUCCESS) {
        if (!pcsc_fido_reader_list_is_valid(buf, needed)) {
          pcsc_fido_set_err(err, err_cap, "invalid reader listing output");
          return false;
        }
        *buf_len = needed;
        return true;
      }
      if (!pcsc_no_readers(rv)) {
        pcsc_fido_set_pcsc_err(err, err_cap, "SCardListReaders(fill)", rv);
        return false;
      }
    } else if (rv != SCARD_S_SUCCESS && !pcsc_no_readers(rv)) {
      pcsc_fido_set_pcsc_err(err, err_cap, "SCardListReaders(probe)", rv);
      return false;
    }
    if (pcsc_fido_session_cancel_requested()) {
      pcsc_fido_set_err(err, err_cap, "cancelled while waiting for PC/SC reader enumeration");
      return false;
    }
    pcsc_fido_sleep_ms((long)PCSC_FIDO_READER_LIST_RETRY_MS);
  } while (time(nullptr) < deadline);
  if (rv == SCARD_S_SUCCESS || pcsc_no_readers(rv)) {
    pcsc_fido_set_err(err, err_cap, "no PC/SC readers available");
  } else {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardListReaders(probe)", rv);
  }
  return false;
}

static size_t collect_reader_candidates(const char *readers, size_t readers_len,
                                        const char *candidates[PCSC_FIDO_BRIDGE_MAX_READERS]) {
  size_t count = 0u;
  if (readers == nullptr || candidates == nullptr) {
    return 0u;
  }
  for (size_t off = 0u;;) {
    const char *p;
    size_t p_len;
    pcsc_fido_reader_list_entry_result_t entry_result =
      pcsc_fido_reader_list_next(readers, readers_len, &off, &p, &p_len);
    if (entry_result == PCSC_FIDO_READER_LIST_ENTRY_END) {
      break;
    }
    if (entry_result != PCSC_FIDO_READER_LIST_ENTRY_OK) {
      break;
    }
    if (pcsc_fido_reader_name_is_sam_slot_len(p, p_len)) {
      continue;
    }
    if (count >= PCSC_FIDO_BRIDGE_MAX_READERS) {
      pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                    "PC/SC reader candidate list truncated at %u readers; additional readers "
                    "ignored",
                    (unsigned)PCSC_FIDO_BRIDGE_MAX_READERS);
      break;
    }
    candidates[count++] = p;
  }
  return count;
}

static bool probe_select_transmit(SCARDHANDLE card, const SCARD_IO_REQUEST *pci,
                                  const uint8_t *apdu, DWORD apdu_len) {
  uint8_t response[258];
  DWORD response_len = sizeof(response);
  LONG rv = SCardTransmit(card, pci, apdu, apdu_len, nullptr, response, &response_len);
  return rv == SCARD_S_SUCCESS && response_len >= 2u && response[response_len - 2u] == 0x90u &&
         response[response_len - 1u] == 0x00u;
}

bool pcsc_fido_reader_probe_fido_card(SCARDCONTEXT ctx, const char *reader) {
  SCARDHANDLE card = 0;
  DWORD active_protocol = 0;
  const SCARD_IO_REQUEST *pci;
  size_t select_len = 0u;
  bool selected = false;
  LONG rv;
  if (reader == nullptr) {
    return false;
  }
  rv = SCardConnect(ctx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
                    &active_protocol);
  if (rv == SCARD_E_PROTO_MISMATCH) {
    rv = SCardConnect(ctx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_RAW, &card, &active_protocol);
  }
  if (rv != SCARD_S_SUCCESS) {
    return false;
  }
  pci = pcsc_fido_reader_pci_for_protocol(active_protocol);
  if (pci != nullptr) {
    uint8_t select_apdu[PCSC_FIDO_SELECT_APDU_MAX];
    if (pcsc_fido_pack_select_fido_apdu(select_apdu, sizeof(select_apdu), &select_len, true)) {
      selected = probe_select_transmit(card, pci, select_apdu, (DWORD)select_len);
    }
    if (!selected &&
        pcsc_fido_pack_select_fido_apdu(select_apdu, sizeof(select_apdu), &select_len, false)) {
      selected = probe_select_transmit(card, pci, select_apdu, (DWORD)select_len);
    }
  }
  (void)SCardDisconnect(card, SCARD_LEAVE_CARD);
  return selected;
}

static bool pick_best_present_reader(SCARDCONTEXT ctx,
                                     const char *present[PCSC_FIDO_BRIDGE_MAX_READERS],
                                     size_t present_count, char *reader, size_t reader_cap) {
  const char *probe_order[PCSC_FIDO_BRIDGE_MAX_READERS];
  size_t probe_count = 0u;
  size_t contactless_count = 0u;
  const char *only_contactless = nullptr;
  if (present_count == 0u || reader == nullptr || reader_cap == 0u) {
    return false;
  }
  if (present_count == 1u) {
    return pcsc_fido_copy_cstr(reader, reader_cap, present[0]);
  }
  for (size_t i = 0u; i < present_count; i++) {
    size_t name_len = 0u;
    if (!pcsc_fido_bounded_strlen(present[i], PCSC_FIDO_READER_NAME_MAX, &name_len)) {
      continue;
    }
    if (pcsc_fido_reader_name_is_contactless_slot_len(present[i], name_len)) {
      contactless_count++;
      only_contactless = present[i];
      probe_order[probe_count++] = present[i];
    }
  }
  if (contactless_count == 1u) {
    return pcsc_fido_copy_cstr(reader, reader_cap, only_contactless);
  }
  for (size_t i = 0u; i < present_count; i++) {
    size_t name_len = 0u;
    if (!pcsc_fido_bounded_strlen(present[i], PCSC_FIDO_READER_NAME_MAX, &name_len)) {
      continue;
    }
    if (!pcsc_fido_reader_name_is_contactless_slot_len(present[i], name_len)) {
      probe_order[probe_count++] = present[i];
    }
  }
  for (size_t i = 0u; i < probe_count; i++) {
    if (pcsc_fido_session_cancel_requested()) {
      return false;
    }
    if (pcsc_fido_reader_probe_fido_card(ctx, probe_order[i])) {
      return pcsc_fido_copy_cstr(reader, reader_cap, probe_order[i]);
    }
  }
  return pcsc_fido_copy_cstr(reader, reader_cap, present[0]);
}

static bool wait_for_present_reader(SCARDCONTEXT ctx, const char *readers, size_t readers_len,
                                    char *reader, size_t reader_cap, char *err, size_t err_cap) {
  const char *candidates[PCSC_FIDO_BRIDGE_MAX_READERS];
  SCARD_READERSTATE states[PCSC_FIDO_BRIDGE_MAX_READERS];
  size_t candidate_count = collect_reader_candidates(readers, readers_len, candidates);
  time_t deadline = pcsc_fido_add_seconds_saturating(time(nullptr), PCSC_FIDO_WAIT_SEC_DEFAULT);
  if (reader == nullptr || reader_cap == 0u) {
    pcsc_fido_set_err(err, err_cap, "invalid reader wait arguments");
    return false;
  }
  if (candidate_count == 0u) {
    pcsc_fido_set_err(err, err_cap, "no selectable PC/SC readers found");
    return false;
  }
  memset(states, 0, sizeof(states));
  for (size_t i = 0u; i < candidate_count; i++) {
    states[i].szReader = candidates[i];
    states[i].dwCurrentState = SCARD_STATE_UNAWARE;
  }
  pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "waiting for FIDO NFC card on %zu possible readers",
                candidate_count);
  while (time(nullptr) < deadline) {
    const char *present[PCSC_FIDO_BRIDGE_MAX_READERS];
    size_t present_count = 0u;
    LONG rv =
      SCardGetStatusChange(ctx, PCSC_FIDO_READER_STATUS_POLL_MS, states, (DWORD)candidate_count);
    if (rv != SCARD_E_TIMEOUT && rv != SCARD_S_SUCCESS) {
      pcsc_fido_set_pcsc_err(err, err_cap, "SCardGetStatusChange", rv);
      return false;
    }
    for (size_t i = 0u; i < candidate_count; i++) {
      if (pcsc_fido_reader_state_has_card((const pcsc_fido_reader_state_t *)&states[i]) &&
          present_count < PCSC_FIDO_BRIDGE_MAX_READERS) {
        present[present_count++] = states[i].szReader;
      }
      states[i].dwCurrentState = states[i].dwEventState;
    }
    if (present_count >= 1u) {
      if (!pick_best_present_reader(ctx, present, present_count, reader, reader_cap)) {
        if (pcsc_fido_session_cancel_requested()) {
          pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT);
        } else {
          pcsc_fido_set_err(err, err_cap, "PC/SC reader name too long");
        }
        return false;
      }
      if (present_count == 1u) {
        pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "using PC/SC reader \"%s\" (selected by card presence)",
                      reader);
      } else {
        pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                      "%zu readers have cards present; using \"%s\" for this browser operation",
                      present_count, reader);
      }
      return true;
    }
    if (pcsc_fido_session_cancel_requested()) {
      pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT);
      return false;
    }
  }
  if (pcsc_fido_session_cancel_requested()) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT);
  } else {
    pcsc_fido_set_err(err, err_cap, "timed out waiting for FIDO NFC card on any reader");
  }
  return false;
}

bool pcsc_fido_reader_confirm_card_present(SCARDCONTEXT ctx, const char *reader, char *err,
                                           size_t err_cap) {
  SCARD_READERSTATE state;
  LONG rv;
  if (reader == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid reader name for presence check");
    return false;
  }
  memset(&state, 0, sizeof(state));
  state.szReader = reader;
  state.dwCurrentState = SCARD_STATE_UNAWARE;
  rv = SCardGetStatusChange(ctx, 0, &state, 1);
  if (rv == SCARD_E_TIMEOUT) {
    pcsc_fido_set_err(err, err_cap, "FIDO NFC card left the reader before connect");
    return false;
  }
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardGetStatusChange", rv);
    return false;
  }
  if (!pcsc_fido_reader_state_has_card((const pcsc_fido_reader_state_t *)&state)) {
    pcsc_fido_set_err(err, err_cap, "FIDO NFC card left the reader before connect");
    return false;
  }
  return true;
}

static bool wait_for_card(SCARDCONTEXT ctx, const char *reader, char *err, size_t err_cap) {
  SCARD_READERSTATE state;
  time_t deadline = pcsc_fido_add_seconds_saturating(time(nullptr), PCSC_FIDO_WAIT_SEC_DEFAULT);
  if (reader == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid reader name for card wait");
    return false;
  }
  memset(&state, 0, sizeof(state));
  state.szReader = reader;
  state.dwCurrentState = SCARD_STATE_UNAWARE;
  pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "waiting for FIDO NFC card");
  while (time(nullptr) < deadline) {
    LONG rv;
    if (pcsc_fido_session_cancel_requested()) {
      pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT);
      return false;
    }
    rv = SCardGetStatusChange(ctx, PCSC_FIDO_READER_STATUS_POLL_MS, &state, 1);
    if (rv == SCARD_E_TIMEOUT) {
      continue;
    }
    if (rv != SCARD_S_SUCCESS) {
      pcsc_fido_set_pcsc_err(err, err_cap, "SCardGetStatusChange", rv);
      return false;
    }
    if (pcsc_fido_reader_state_has_card((const pcsc_fido_reader_state_t *)&state)) {
      return true;
    }
    state.dwCurrentState = state.dwEventState;
  }
  if (pcsc_fido_session_cancel_requested()) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT);
  } else {
    pcsc_fido_set_err(err, err_cap, "timed out waiting for FIDO NFC card");
  }
  return false;
}

bool pcsc_fido_reader_select_and_wait(SCARDCONTEXT ctx, const char *reader_needle, char *reader,
                                      size_t reader_cap, char *err, size_t err_cap) {
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  DWORD readers_len = sizeof(readers);
  const char *needle = pcsc_fido_reader_env_needle(reader_needle);
  bool auto_select = needle == nullptr || needle[0] == '\0';
  bool auto_selected_contactless = false;
  pcsc_fido_reader_pick_result_t pick_result;
  if (!pcsc_fido_reader_list(ctx, readers, &readers_len, err, err_cap)) {
    return false;
  }
  pick_result = pcsc_fido_pick_reader_from_list(readers, (size_t)readers_len, needle, auto_select,
                                                reader, reader_cap, &auto_selected_contactless);
  if (pick_result == PCSC_FIDO_READER_PICK_OK) {
    if (auto_selected_contactless) {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                    "using PC/SC reader \"%s\" (auto-selected contactless slot)", reader);
    } else {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "using PC/SC reader \"%s\"", reader);
    }
    return wait_for_card(ctx, reader, err, err_cap);
  }
  if (pick_result == PCSC_FIDO_READER_PICK_NAME_TOO_LONG) {
    pcsc_fido_set_err(err, err_cap, "PC/SC reader name too long");
  } else if (pick_result == PCSC_FIDO_READER_PICK_NO_MATCH) {
    pcsc_fido_set_err(err, err_cap, "no matching PC/SC reader; set PCSC_FIDO_READER");
  } else if (auto_select) {
    return wait_for_present_reader(ctx, readers, readers_len, reader, reader_cap, err, err_cap);
  } else {
    pcsc_fido_set_err(err, err_cap,
                      "PCSC_FIDO_READER matches multiple readers; use a more specific value");
  }
  return false;
}

bool pcsc_fido_reader_print_list(FILE *out, char *err, size_t err_cap) {
  SCARDCONTEXT ctx = 0;
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  DWORD readers_len = sizeof(readers);
  if (out == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid reader listing output");
    return false;
  }
  if (!pcsc_fido_reader_establish_context(&ctx, PCSC_FIDO_READER_CTX_USER, err, err_cap)) {
    return false;
  }
  if (!pcsc_fido_reader_list(ctx, readers, &readers_len, err, err_cap)) {
    (void)SCardReleaseContext(ctx);
    return false;
  }
  for (size_t off = 0u;;) {
    const char *p;
    size_t p_len;
    pcsc_fido_reader_list_entry_result_t entry_result =
      pcsc_fido_reader_list_next(readers, readers_len, &off, &p, &p_len);
    if (entry_result != PCSC_FIDO_READER_LIST_ENTRY_OK) {
      break;
    }
    fprintf(out, "%s%s\n", p,
            pcsc_fido_reader_name_is_contactless_slot_len(p, p_len) ? " [contactless]" : "");
  }
  (void)SCardReleaseContext(ctx);
  return true;
}
