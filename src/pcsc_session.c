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
#include "pcsc_fido/apdu_chain.h"
#include "pcsc_fido/attrs.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_reader_ops.h"
#include "pcsc_fido/reader_select.h"
#include "pcsc_fido/pcsc_session.h"

#include <winscard.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

typedef struct {
  SCARDCONTEXT ctx;
  SCARDHANDLE card;
  const SCARD_IO_REQUEST *send_pci;
  char reader[PCSC_FIDO_READER_NAME_MAX];
  uint64_t generation;
  SCARDCONTEXT pending_ctx;
  unsigned active_transmits;
  atomic_bool cancel_requested;
  pthread_mutex_t lock;
  pthread_cond_t idle;
} pcsc_fido_session_state_t;

static pcsc_fido_session_state_t g_session = {
  .lock = PTHREAD_MUTEX_INITIALIZER,
  .idle = PTHREAD_COND_INITIALIZER,
};

static void release_pcsc_handles(SCARDCONTEXT ctx, SCARDHANDLE card) {
  if (card != 0) {
    (void)SCardDisconnect(card, SCARD_LEAVE_CARD);
  }
  if (ctx != 0) {
    (void)SCardReleaseContext(ctx);
  }
}

static bool commit_session(SCARDCONTEXT ctx, SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
                           const char *reader) {
  bool ok = true;
  pthread_mutex_lock(&g_session.lock);
  g_session.ctx = ctx;
  g_session.card = card;
  g_session.send_pci = send_pci;
  if (reader != nullptr) {
    ok = pcsc_fido_copy_cstr(g_session.reader, sizeof(g_session.reader), reader);
    if (!ok) {
      g_session.reader[0] = '\0';
    }
  } else {
    g_session.reader[0] = '\0';
  }
  pthread_mutex_unlock(&g_session.lock);
  return ok;
}

bool pcsc_fido_session_is_ready(void) {
  bool ready;
  pthread_mutex_lock(&g_session.lock);
  ready = g_session.card != 0 && g_session.send_pci != nullptr;
  pthread_mutex_unlock(&g_session.lock);
  return ready;
}

static bool card_state_is_usable(DWORD state) {
  return pcsc_fido_reader_status_has_card((uint32_t)state);
}

bool pcsc_fido_session_verify_ready(char *err, size_t err_cap) {
  SCARDHANDLE card = 0;
  DWORD state = 0u;
  DWORD protocol = 0u;
  LONG rv;
  pthread_mutex_lock(&g_session.lock);
  if (g_session.card == 0 || g_session.send_pci == nullptr) {
    pthread_mutex_unlock(&g_session.lock);
    return false;
  }
  card = g_session.card;
  pthread_mutex_unlock(&g_session.lock);
  rv = SCardStatus(card, nullptr, nullptr, &state, &protocol, nullptr, nullptr);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardStatus", rv);
    return false;
  }
  if (!card_state_is_usable(state)) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session card no longer present");
    return false;
  }
  return true;
}

bool pcsc_fido_session_snapshot_tx(pcsc_fido_session_tx_t *tx, char *err, size_t err_cap) {
  bool ok;
  if (tx == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid PC/SC session snapshot arguments");
    return false;
  }
  pthread_mutex_lock(&g_session.lock);
  ok = g_session.card != 0 && g_session.send_pci != nullptr;
  if (ok) {
    tx->card = g_session.card;
    tx->send_pci = g_session.send_pci;
    tx->generation = g_session.generation;
  }
  pthread_mutex_unlock(&g_session.lock);
  if (!ok) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session is not connected");
  }
  return ok;
}

bool pcsc_fido_session_tx_is_current(const pcsc_fido_session_tx_t *tx) {
  bool ok;
  if (tx == nullptr || tx->card == 0) {
    return false;
  }
  pthread_mutex_lock(&g_session.lock);
  ok = g_session.card == tx->card && g_session.send_pci == tx->send_pci &&
       g_session.generation == tx->generation;
  pthread_mutex_unlock(&g_session.lock);
  return ok;
}

SCARDCONTEXT pcsc_fido_session_snapshot_context(void) {
  SCARDCONTEXT ctx;
  pthread_mutex_lock(&g_session.lock);
  ctx = g_session.ctx;
  pthread_mutex_unlock(&g_session.lock);
  return ctx;
}

void pcsc_fido_session_reset(void) {
  SCARDCONTEXT ctx;
  SCARDHANDLE card;
  SCARDCONTEXT pending;
  bool active;
  pthread_mutex_lock(&g_session.lock);
  ctx = g_session.ctx;
  card = g_session.card;
  pending = g_session.pending_ctx;
  active = g_session.active_transmits != 0u;
  g_session.generation++;
  g_session.ctx = 0;
  g_session.card = 0;
  g_session.send_pci = nullptr;
  g_session.pending_ctx = 0;
  g_session.reader[0] = '\0';
  if (active) {
    atomic_store(&g_session.cancel_requested, true);
  }
  pthread_mutex_unlock(&g_session.lock);
  if (active) {
    if (ctx != 0) {
      (void)SCardCancel(ctx);
    }
    if (pending != 0 && pending != ctx) {
      (void)SCardCancel(pending);
    }
    pthread_mutex_lock(&g_session.lock);
    while (g_session.active_transmits != 0u) {
      (void)pthread_cond_wait(&g_session.idle, &g_session.lock);
    }
    pthread_mutex_unlock(&g_session.lock);
  }
  release_pcsc_handles(ctx, card);
  if (pending != 0 && pending != ctx) {
    (void)SCardReleaseContext(pending);
  }
}

void pcsc_fido_session_cancel(void) {
  SCARDCONTEXT ctx = 0;
  SCARDCONTEXT pending = 0;
  pthread_mutex_lock(&g_session.lock);
  atomic_store(&g_session.cancel_requested, true);
  ctx = g_session.ctx;
  pending = g_session.pending_ctx;
  pthread_mutex_unlock(&g_session.lock);
  if (ctx != 0) {
    (void)SCardCancel(ctx);
  }
  if (pending != 0 && pending != ctx) {
    (void)SCardCancel(pending);
  }
}

bool pcsc_fido_session_cancel_requested(void) {
  return atomic_load(&g_session.cancel_requested);
}

void pcsc_fido_session_clear_cancel(void) {
  atomic_store(&g_session.cancel_requested, false);
}

static bool transmit_apdu(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci, const uint8_t *capdu,
                          size_t capdu_len, uint8_t *rapdu, size_t rapdu_cap, size_t *rapdu_len,
                          char *err, size_t err_cap) {
  DWORD recv_len = (DWORD)rapdu_cap;
  LONG rv;
  if (send_pci == nullptr || capdu == nullptr || rapdu == nullptr || rapdu_len == nullptr ||
      capdu_len > (size_t)UINT32_MAX || rapdu_cap > (size_t)UINT32_MAX) {
    pcsc_fido_set_err(err, err_cap, "invalid APDU transmit arguments");
    return false;
  }
  rv = SCardTransmit(card, send_pci, capdu, (DWORD)capdu_len, nullptr, rapdu, &recv_len);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardTransmit", rv);
    return false;
  }
  *rapdu_len = (size_t)recv_len;
  return true;
}

typedef struct {
  SCARDHANDLE card;
  const SCARD_IO_REQUEST *send_pci;
} session_transmit_ctx_t;

static bool session_transmit_apdu(void *ctx, const uint8_t *capdu, size_t capdu_len, uint8_t *rapdu,
                                  size_t rapdu_cap, size_t *rapdu_len, char *err, size_t err_cap) {
  const session_transmit_ctx_t *tx = (const session_transmit_ctx_t *)ctx;
  if (tx == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid APDU transmit context");
    return false;
  }
  return transmit_apdu(tx->card, tx->send_pci, capdu, capdu_len, rapdu, rapdu_cap, rapdu_len, err,
                       err_cap);
}

static bool session_cancel_check(void *ctx) {
  (void)ctx;
  return pcsc_fido_session_cancel_requested();
}

bool pcsc_fido_session_transmit_chained(const pcsc_fido_session_tx_t *tx, const uint8_t *capdu,
                                        size_t capdu_len, uint8_t *rapdu, size_t rapdu_cap,
                                        size_t *rapdu_len, char *err, size_t err_cap) {
  session_transmit_ctx_t ctx;
  bool ok;
  bool current;
  pthread_mutex_lock(&g_session.lock);
  if (tx == nullptr || g_session.card != tx->card || g_session.send_pci != tx->send_pci ||
      g_session.generation != tx->generation) {
    pthread_mutex_unlock(&g_session.lock);
    pcsc_fido_set_err(err, err_cap, "PC/SC session no longer matches transmit handles");
    return false;
  }
  g_session.active_transmits++;
  ctx.card = tx->card;
  ctx.send_pci = tx->send_pci;
  pthread_mutex_unlock(&g_session.lock);
  ok = pcsc_fido_apdu_transmit_chained_cancel(&ctx, session_transmit_apdu, session_cancel_check,
                                              nullptr, capdu, capdu_len, rapdu, rapdu_cap,
                                              rapdu_len, err, err_cap);
  pthread_mutex_lock(&g_session.lock);
  if (g_session.active_transmits > 0u) {
    g_session.active_transmits--;
  }
  current = g_session.card == tx->card && g_session.send_pci == tx->send_pci &&
            g_session.generation == tx->generation;
  if (g_session.active_transmits == 0u) {
    (void)pthread_cond_broadcast(&g_session.idle);
  }
  pthread_mutex_unlock(&g_session.lock);
  if (!current && ok) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session changed during transmit");
    return false;
  }
  return ok;
}

static const char *pcsc_protocol_name(DWORD active) {
  if ((active & SCARD_PROTOCOL_T1) != 0u) {
    return "T=1";
  }
  if ((active & SCARD_PROTOCOL_T0) != 0u) {
    return "T=0";
  }
  if ((active & SCARD_PROTOCOL_RAW) != 0u) {
    return "RAW";
  }
  return "unknown";
}

static bool connect_card(SCARDCONTEXT ctx, const char *reader, SCARDHANDLE *card,
                         const SCARD_IO_REQUEST **send_pci, char *err, size_t err_cap) {
  DWORD active = 0u;
  if (reader == nullptr || card == nullptr || send_pci == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid card connect arguments");
    return false;
  }
  if (!pcsc_fido_reader_confirm_card_present(ctx, reader, err, err_cap)) {
    return false;
  }
  LONG rv = SCardConnect(ctx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                         card, &active);
  if (rv == SCARD_E_PROTO_MISMATCH) {
    rv = SCardConnect(ctx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_RAW, card, &active);
  }
  if (rv != SCARD_S_SUCCESS) {
    pcsc_fido_set_pcsc_err(err, err_cap, "SCardConnect", rv);
    return false;
  }
  *send_pci = pcsc_fido_reader_pci_for_protocol(active);
  if (*send_pci == nullptr) {
    (void)SCardDisconnect(*card, SCARD_LEAVE_CARD);
    pcsc_fido_set_err(err, err_cap, "reader did not negotiate T=0/T=1/RAW");
    return false;
  }
  pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "SCardConnect ok active_protocol=%s",
                pcsc_protocol_name(active));
  return true;
}

static bool select_fido(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci, char *err,
                        size_t err_cap) {
  {
    uint8_t apdu[32];
    uint8_t rapdu[PCSC_FIDO_BRIDGE_MAX_RESPONSE];
    size_t apdu_len = 0u;
    size_t rapdu_len = 0u;
    session_transmit_ctx_t tx_ctx = {.card = card, .send_pci = send_pci};
    if (pcsc_fido_pack_select_fido_apdu(apdu, sizeof(apdu), &apdu_len, true) &&
        pcsc_fido_apdu_transmit_chained(&tx_ctx, session_transmit_apdu, apdu, apdu_len, rapdu,
                                        sizeof(rapdu), &rapdu_len, err, err_cap) &&
        pcsc_fido_apdu_status_word(rapdu, rapdu_len) == 0x9000u) {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "FIDO SELECT preferred returned SW=9000");
      return true;
    }
    if (pcsc_fido_pack_select_fido_apdu(apdu, sizeof(apdu), &apdu_len, false) &&
        pcsc_fido_apdu_transmit_chained(&tx_ctx, session_transmit_apdu, apdu, apdu_len, rapdu,
                                        sizeof(rapdu), &rapdu_len, err, err_cap) &&
        pcsc_fido_apdu_status_word(rapdu, rapdu_len) == 0x9000u) {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "FIDO SELECT fallback returned SW=9000");
      return true;
    }
  }
  pcsc_fido_set_err(err, err_cap, "FIDO AID select failed");
  return false;
}

bool pcsc_fido_session_ensure(const char *reader_needle, char *err, size_t err_cap) {
  SCARDCONTEXT ctx = 0;
  SCARDHANDLE card = 0;
  const SCARD_IO_REQUEST *send_pci = nullptr;
  char reader[PCSC_FIDO_READER_NAME_MAX];
  if (pcsc_fido_session_verify_ready(err, err_cap)) {
    return true;
  }
  pcsc_fido_session_reset();
  if (!pcsc_fido_reader_establish_context(&ctx, PCSC_FIDO_READER_CTX_DAEMON, err, err_cap)) {
    return false;
  }
  pthread_mutex_lock(&g_session.lock);
  g_session.pending_ctx = ctx;
  pthread_mutex_unlock(&g_session.lock);
  if (!pcsc_fido_reader_select_and_wait(ctx, reader_needle, reader, sizeof(reader), err, err_cap) ||
      !connect_card(ctx, reader, &card, &send_pci, err, err_cap) ||
      !select_fido(card, send_pci, err, err_cap)) {
    pthread_mutex_lock(&g_session.lock);
    if (g_session.pending_ctx == ctx) {
      g_session.pending_ctx = 0;
    }
    pthread_mutex_unlock(&g_session.lock);
    release_pcsc_handles(ctx, card);
    return false;
  }
  if (!commit_session(ctx, card, send_pci, reader)) {
    pthread_mutex_lock(&g_session.lock);
    if (g_session.pending_ctx == ctx) {
      g_session.pending_ctx = 0;
    }
    pthread_mutex_unlock(&g_session.lock);
    release_pcsc_handles(ctx, card);
    pcsc_fido_set_err(err, err_cap, "PC/SC reader name too long");
    return false;
  }
  pthread_mutex_lock(&g_session.lock);
  if (g_session.pending_ctx == ctx) {
    g_session.pending_ctx = 0;
  }
  pthread_mutex_unlock(&g_session.lock);
  return true;
}
