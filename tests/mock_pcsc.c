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

#include "mock_pcsc.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include "pcsc_fido/mem_util.h"

enum {
  MS_PER_SEC = 1000,
  NS_PER_MS = 1000000,
  NS_PER_SEC = 1000000000,
};

static void mock_sleep_status_timeout(DWORD timeout_ms) {
  struct timespec ts;
  long ms;
  if (timeout_ms == 0u) {
    return;
  }
  ms = (long)timeout_ms;
  ts.tv_sec = ms / MS_PER_SEC;
  ts.tv_nsec = (ms % MS_PER_SEC) * NS_PER_MS;
  (void)nanosleep(&ts, PCSC_FIDO_NULL);
}

static LONG mock_return_status_timeout(DWORD timeout_ms) {
  mock_sleep_status_timeout(timeout_ms);
  return SCARD_E_TIMEOUT;
}

const SCARD_IO_REQUEST g_rgSCardT0Pci = {
    .dwProtocol = SCARD_PROTOCOL_T0,
    .cbPciLength = sizeof(SCARD_IO_REQUEST),
};
const SCARD_IO_REQUEST g_rgSCardT1Pci = {
    .dwProtocol = SCARD_PROTOCOL_T1,
    .cbPciLength = sizeof(SCARD_IO_REQUEST),
};
const SCARD_IO_REQUEST g_rgSCardRawPci = {
    .dwProtocol = SCARD_PROTOCOL_RAW,
    .cbPciLength = sizeof(SCARD_IO_REQUEST),
};

enum {
  MOCK_READERS_CAP = PCSC_FIDO_READER_LIST_BUF_MAX,
  MOCK_TRANSMIT_CAP = 65538u,
  MOCK_STATUS_SEQUENCE_CAP = 64u,
  MSZ_DOUBLE_NUL = 2,
  MOCK_CARD_HANDLE = 2,
  SW_LEN = 2,
  SELECT_APDU_LEN = 13,
  APDU_OFF_DATA = 5,
  SW_NO_ERROR_HI = 0x90,
  SW_FILE_NOT_FOUND_HI = 0x6A,
  SW_FILE_NOT_FOUND_LO = 0x82,
  TRANSMIT_CANCEL_WAIT_MS = 200,
};

typedef struct {
  char readers[MOCK_READERS_CAP];
  size_t readers_msz_len;
  LONG establish_fail;
  bool establish_fail_system_scope;
  LONG list_probe_fail;
  DWORD list_probe_needed;
  unsigned list_probe_no_readers_retries;
  bool list_probe_always_no_readers;
  LONG list_fill_fail;
  LONG get_status_fail;
  LONG connect_fail;
  bool connect_proto_mismatch_once;
  bool connect_proto_mismatch_used;
  DWORD connect_active_protocol;
  bool card_present_immediately;
  bool status_present_sequence[MOCK_STATUS_SEQUENCE_CAP];
  size_t status_present_sequence_len;
  size_t status_present_sequence_pos;
  unsigned get_status_timeouts_before_present;
  bool multi_present_readers;
  bool transmit_fail;
  bool transmit_fail_once;
  bool transmit_fail_once_used;
  bool select_first_fail;
  uint8_t transmit_response[MOCK_TRANSMIT_CAP];
  size_t transmit_response_len;
  unsigned transmit_calls;
  unsigned get_status_calls;
} mock_pcsc_state_t;

static mock_pcsc_state_t g_mock;
static atomic_bool g_transmit_wait_for_cancel;
static atomic_bool g_transmit_waiting;
static atomic_bool g_transmit_cancelled;
static atomic_bool g_cancel_during_transmit;
static pthread_mutex_t g_transmit_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_transmit_cond = PTHREAD_COND_INITIALIZER;

static void deadline_from_now(struct timespec* deadline, unsigned timeout_ms) {
  (void)clock_gettime(CLOCK_REALTIME, deadline);
  deadline->tv_sec += (time_t)(timeout_ms / MS_PER_SEC);
  deadline->tv_nsec += (long)((timeout_ms % MS_PER_SEC) * NS_PER_MS);
  if (deadline->tv_nsec >= NS_PER_SEC) {
    deadline->tv_sec++;
    deadline->tv_nsec -= NS_PER_SEC;
  }
}

static const uint8_t FIDO_AID[] = {0xA0u, 0x00u, 0x00u, 0x06u,
                                   0x47u, 0x2Fu, 0x00u, 0x01u};

void mock_pcsc_reset(void) {
  pcsc_fido_zero_bytes(&g_mock, sizeof(g_mock));
  pthread_mutex_lock(&g_transmit_lock);
  atomic_store(&g_transmit_wait_for_cancel, false);
  atomic_store(&g_transmit_waiting, false);
  atomic_store(&g_transmit_cancelled, false);
  atomic_store(&g_cancel_during_transmit, false);
  (void)pthread_cond_broadcast(&g_transmit_cond);
  pthread_mutex_unlock(&g_transmit_lock);
  g_mock.connect_active_protocol = SCARD_PROTOCOL_T1;
  g_mock.card_present_immediately = true;
  {
    static const uint8_t MOCK_DEFAULT_RESPONSE[] = {0x00u, 0xA1u, 0x01u,
                                                    0x02u, 0x90u, 0x00u};
    (void)pcsc_fido_copy_bytes(
        g_mock.transmit_response, sizeof(MOCK_DEFAULT_RESPONSE), 0u,
        MOCK_DEFAULT_RESPONSE, sizeof(MOCK_DEFAULT_RESPONSE));
    g_mock.transmit_response_len = sizeof(MOCK_DEFAULT_RESPONSE);
  }
}

static size_t mock_readers_msz_len(void) {
  if (g_mock.readers_msz_len != 0u) {
    return g_mock.readers_msz_len;
  }
  if (g_mock.readers[0] == '\0') {
    return 0u;
  }
  return strlen(g_mock.readers) + MSZ_DOUBLE_NUL;
}

void mock_pcsc_set_readers(const char* readers) {
  if (readers == PCSC_FIDO_NULL) {
    g_mock.readers[0] = '\0';
    g_mock.readers_msz_len = 0u;
    return;
  }
  pcsc_fido_zero_bytes(g_mock.readers, sizeof(g_mock.readers));
  if (!pcsc_fido_copy_cstr(g_mock.readers, sizeof(g_mock.readers), readers)) {
    g_mock.readers[0] = '\0';
  }
  g_mock.readers_msz_len = 0u;
}

void mock_pcsc_set_reader_pair(const char* reader_a, const char* reader_b) {
  size_t alen;
  size_t blen;
  size_t total;
  if (reader_a == PCSC_FIDO_NULL || reader_b == PCSC_FIDO_NULL) {
    g_mock.readers[0] = '\0';
    g_mock.readers_msz_len = 0u;
    return;
  }
  alen = strlen(reader_a);
  blen = strlen(reader_b);
  total = alen + 1u + blen + MSZ_DOUBLE_NUL;
  if (total > MOCK_READERS_CAP) {
    total = MOCK_READERS_CAP;
  }
  pcsc_fido_zero_bytes(g_mock.readers, sizeof(g_mock.readers));
  (void)pcsc_fido_copy_bytes(g_mock.readers, alen + 1u, 0u, reader_a,
                             alen + 1u);
  (void)pcsc_fido_copy_bytes(g_mock.readers + alen + 1u, blen + 1u, 0u,
                             reader_b, blen + 1u);
  g_mock.readers_msz_len = total;
}

void mock_pcsc_set_list_probe_needed(DWORD needed) {
  g_mock.list_probe_needed = needed;
}

void mock_pcsc_set_list_probe_no_readers_retries(unsigned retries) {
  g_mock.list_probe_no_readers_retries = retries;
}

void mock_pcsc_set_list_probe_always_no_readers(bool enabled) {
  g_mock.list_probe_always_no_readers = enabled;
}

void mock_pcsc_set_establish_fail_system_scope(bool enabled) {
  g_mock.establish_fail_system_scope = enabled;
}

void mock_pcsc_set_establish_fail(LONG rv) { g_mock.establish_fail = rv; }

void mock_pcsc_set_list_probe_fail(LONG rv) { g_mock.list_probe_fail = rv; }

void mock_pcsc_set_list_fill_fail(LONG rv) { g_mock.list_fill_fail = rv; }

void mock_pcsc_set_get_status_fail(LONG rv) { g_mock.get_status_fail = rv; }

void mock_pcsc_set_connect_fail(LONG rv) { g_mock.connect_fail = rv; }

void mock_pcsc_set_connect_proto_mismatch_once(bool enabled) {
  g_mock.connect_proto_mismatch_once = enabled;
}

void mock_pcsc_set_connect_active_protocol(DWORD protocol) {
  g_mock.connect_active_protocol = protocol;
}

void mock_pcsc_set_card_present_immediately(bool enabled) {
  g_mock.card_present_immediately = enabled;
}

void mock_pcsc_set_status_present_sequence(const bool* present, size_t len) {
  if (present == PCSC_FIDO_NULL || len == 0u) {
    g_mock.status_present_sequence_len = 0u;
    g_mock.status_present_sequence_pos = 0u;
    return;
  }
  if (len > MOCK_STATUS_SEQUENCE_CAP) {
    len = MOCK_STATUS_SEQUENCE_CAP;
  }
  (void)pcsc_fido_copy_bytes(g_mock.status_present_sequence,
                             len * sizeof(present[0]), 0u, present,
                             len * sizeof(present[0]));
  g_mock.status_present_sequence_len = len;
  g_mock.status_present_sequence_pos = 0u;
}

void mock_pcsc_set_get_status_timeouts_before_present(unsigned count) {
  g_mock.get_status_timeouts_before_present = count;
}

void mock_pcsc_set_multi_present_readers(bool enabled) {
  g_mock.multi_present_readers = enabled;
}

void mock_pcsc_set_transmit_fail(bool enabled) {
  g_mock.transmit_fail = enabled;
}

void mock_pcsc_set_transmit_fail_once(bool enabled) {
  g_mock.transmit_fail_once = enabled;
  g_mock.transmit_fail_once_used = false;
}

void mock_pcsc_set_transmit_wait_for_cancel(bool enabled) {
  pthread_mutex_lock(&g_transmit_lock);
  atomic_store(&g_transmit_wait_for_cancel, enabled);
  atomic_store(&g_transmit_waiting, false);
  atomic_store(&g_transmit_cancelled, false);
  atomic_store(&g_cancel_during_transmit, false);
  (void)pthread_cond_broadcast(&g_transmit_cond);
  pthread_mutex_unlock(&g_transmit_lock);
}

void mock_pcsc_set_transmit_response(const uint8_t* data, size_t len) {
  if (data == PCSC_FIDO_NULL || len > sizeof(g_mock.transmit_response)) {
    g_mock.transmit_response_len = 0u;
    return;
  }
  (void)pcsc_fido_copy_bytes(g_mock.transmit_response, len, 0u, data, len);
  g_mock.transmit_response_len = len;
}

void mock_pcsc_set_select_first_fail(bool enabled) {
  g_mock.select_first_fail = enabled;
}

unsigned mock_pcsc_transmit_call_count(void) { return g_mock.transmit_calls; }

unsigned mock_pcsc_get_status_call_count(void) {
  return g_mock.get_status_calls;
}

bool mock_pcsc_cancel_during_transmit(void) {
  return atomic_load(&g_cancel_during_transmit);
}

bool mock_pcsc_wait_for_transmit_waiting(unsigned timeout_ms) {
  struct timespec deadline;
  bool waiting;
  deadline_from_now(&deadline, timeout_ms);
  pthread_mutex_lock(&g_transmit_lock);
  while (!atomic_load(&g_transmit_waiting)) {
    if (pthread_cond_timedwait(&g_transmit_cond, &g_transmit_lock, &deadline) !=
        0) {
      break;
    }
  }
  waiting = atomic_load(&g_transmit_waiting);
  pthread_mutex_unlock(&g_transmit_lock);
  return waiting;
}

static bool is_select_apdu(const uint8_t* capdu, DWORD capdu_len,
                           bool* with_le) {
  static const uint8_t SELECT_PREFIX[] = {0x00u, 0xA4u, 0x04u, 0x00u,
                                          (uint8_t)sizeof(FIDO_AID)};
  *with_le = false;
  if (capdu == PCSC_FIDO_NULL || capdu_len < SELECT_APDU_LEN) {
    return false;
  }
  if (memcmp(capdu, SELECT_PREFIX, sizeof(SELECT_PREFIX)) != 0 ||
      memcmp(capdu + APDU_OFF_DATA, FIDO_AID, sizeof(FIDO_AID)) != 0) {
    return false;
  }
  if (capdu_len == SELECT_APDU_LEN + 1u) {
    *with_le = true;
  }
  return true;
}

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

LONG scard_establish_context(DWORD scope, LPCVOID reserved1, LPCVOID reserved2,
                             LPSCARDCONTEXT context_out) {
  (void)scope;
  (void)reserved1;
  (void)reserved2;
  if (context_out == PCSC_FIDO_NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.establish_fail_system_scope && scope == SCARD_SCOPE_SYSTEM) {
    return SCARD_F_INTERNAL_ERROR;
  }
  if (g_mock.establish_fail != 0) {
    return g_mock.establish_fail;
  }
  *context_out = 1;
  return SCARD_S_SUCCESS;
}

LONG scard_release_context(SCARDCONTEXT context) {
  (void)context;
  return SCARD_S_SUCCESS;
}

LONG scard_list_readers(SCARDCONTEXT context, LPCSTR groups, LPSTR readers,
                        LPDWORD readers_len) {
  (void)context;
  (void)groups;
  if (readers_len == PCSC_FIDO_NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (readers == PCSC_FIDO_NULL) {
    if (g_mock.list_probe_fail != 0) {
      return g_mock.list_probe_fail;
    }
    if (g_mock.list_probe_no_readers_retries > 0u) {
      g_mock.list_probe_no_readers_retries--;
      return SCARD_E_NO_READERS_AVAILABLE;
    }
    if (g_mock.list_probe_always_no_readers && g_mock.readers[0] != '\0') {
      return SCARD_E_NO_READERS_AVAILABLE;
    }
    if (g_mock.readers[0] == '\0') {
      return SCARD_E_NO_READERS_AVAILABLE;
    }
    if (g_mock.list_probe_needed != 0u) {
      *readers_len = g_mock.list_probe_needed;
      return SCARD_S_SUCCESS;
    }
    *readers_len = (DWORD)mock_readers_msz_len();
    return SCARD_S_SUCCESS;
  }
  if (g_mock.list_fill_fail != 0) {
    return g_mock.list_fill_fail;
  }
  if (g_mock.readers[0] == '\0') {
    return SCARD_E_NO_READERS_AVAILABLE;
  }
  {
    const DWORD needed = (DWORD)mock_readers_msz_len();
    if (*readers_len < needed) {
      return SCARD_E_INSUFFICIENT_BUFFER;
    }
    (void)pcsc_fido_copy_bytes(readers, needed, 0u, g_mock.readers, needed);
    *readers_len = needed;
  }
  return SCARD_S_SUCCESS;
}

LONG scard_get_status_change(SCARDCONTEXT context, DWORD timeout_ms,
                             LPSCARD_READERSTATE reader_states,
                             DWORD readers_count) {
  (void)context;
  g_mock.get_status_calls++;
  if (g_mock.get_status_fail != 0) {
    return g_mock.get_status_fail;
  }
  if (reader_states == PCSC_FIDO_NULL || readers_count == 0u) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.get_status_timeouts_before_present > 0u) {
    g_mock.get_status_timeouts_before_present--;
    return mock_return_status_timeout(timeout_ms);
  }
  bool present = g_mock.card_present_immediately;
  if (g_mock.status_present_sequence_len > 0u) {
    size_t pos = g_mock.status_present_sequence_pos;
    if (pos >= g_mock.status_present_sequence_len) {
      pos = g_mock.status_present_sequence_len - 1u;
    } else {
      g_mock.status_present_sequence_pos++;
    }
    present = g_mock.status_present_sequence[pos];
  }
  if (!present && g_mock.status_present_sequence_len == 0u) {
    return mock_return_status_timeout(timeout_ms);
  }
  for (DWORD i = 0u; i < readers_count; i++) {
    reader_states[i].dwEventState = SCARD_STATE_CHANGED | SCARD_STATE_UNPOWERED;
    if (present) {
      reader_states[i].dwEventState |= SCARD_STATE_PRESENT;
    } else {
      reader_states[i].dwEventState |= SCARD_STATE_EMPTY;
    }
    if (g_mock.multi_present_readers && readers_count > 1u) {
      continue;
    }
  }
  return SCARD_S_SUCCESS;
}

LONG scard_connect(SCARDCONTEXT context, LPCSTR reader, DWORD share_mode,
                   DWORD preferred_protocols, LPSCARDHANDLE card_out,
                   LPDWORD active_protocol_out) {
  (void)context;
  (void)reader;
  (void)share_mode;
  (void)preferred_protocols;
  if (card_out == PCSC_FIDO_NULL || active_protocol_out == PCSC_FIDO_NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.connect_fail != 0) {
    return g_mock.connect_fail;
  }
  if (g_mock.connect_proto_mismatch_once &&
      !g_mock.connect_proto_mismatch_used) {
    g_mock.connect_proto_mismatch_used = true;
    return SCARD_E_PROTO_MISMATCH;
  }
  *card_out = MOCK_CARD_HANDLE;
  *active_protocol_out = g_mock.connect_active_protocol;
  return SCARD_S_SUCCESS;
}

LONG scard_disconnect(SCARDHANDLE card, DWORD disposition) {
  (void)card;
  (void)disposition;
  return SCARD_S_SUCCESS;
}

LONG scard_status(SCARDHANDLE card, LPSTR reader_name_out,
                  LPDWORD reader_name_len_out, LPDWORD state_out,
                  LPDWORD protocol_out, LPBYTE atr_out, LPDWORD atr_len_out) {
  if (card == 0) {
    return SCARD_E_INVALID_HANDLE;
  }
  if (state_out == PCSC_FIDO_NULL || protocol_out == PCSC_FIDO_NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (reader_name_out != PCSC_FIDO_NULL &&
      reader_name_len_out != PCSC_FIDO_NULL) {
    reader_name_out[0] = '\0';
    *reader_name_len_out = 1u;
  }
  if (atr_out != PCSC_FIDO_NULL && atr_len_out != PCSC_FIDO_NULL) {
    atr_out[0] = 0u;
    *atr_len_out = 0u;
  }
  *protocol_out = g_mock.connect_active_protocol;
  *state_out = 0u;
  if (g_mock.card_present_immediately) {
    *state_out |= SCARD_STATE_PRESENT;
  } else {
    *state_out |= SCARD_STATE_EMPTY;
  }
  return SCARD_S_SUCCESS;
}

LONG scard_transmit(SCARDHANDLE card, const SCARD_IO_REQUEST* send_pci,
                    LPCBYTE send_buffer, DWORD send_length,
                    LPSCARD_IO_REQUEST recv_pci, LPBYTE recv_buffer,
                    LPDWORD recv_length) {
  bool with_le = false;
  (void)card;
  (void)send_pci;
  (void)recv_pci;
  g_mock.transmit_calls++;
  if (recv_buffer == PCSC_FIDO_NULL || recv_length == PCSC_FIDO_NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (!is_select_apdu(send_buffer, send_length, &with_le) &&
      atomic_load(&g_transmit_wait_for_cancel)) {
    struct timespec deadline;
    LONG rv = SCARD_F_COMM_ERROR;
    deadline_from_now(&deadline, TRANSMIT_CANCEL_WAIT_MS);
    pthread_mutex_lock(&g_transmit_lock);
    atomic_store(&g_transmit_waiting, true);
    (void)pthread_cond_broadcast(&g_transmit_cond);
    while (!atomic_load(&g_transmit_cancelled)) {
      if (pthread_cond_timedwait(&g_transmit_cond, &g_transmit_lock,
                                 &deadline) != 0) {
        break;
      }
    }
    if (atomic_load(&g_transmit_cancelled)) {
      rv = SCARD_E_CANCELLED;
    }
    atomic_store(&g_transmit_waiting, false);
    (void)pthread_cond_broadcast(&g_transmit_cond);
    pthread_mutex_unlock(&g_transmit_lock);
    return rv;
  }
  if (g_mock.transmit_fail ||
      (g_mock.transmit_fail_once && !g_mock.transmit_fail_once_used)) {
    if (g_mock.transmit_fail_once) {
      g_mock.transmit_fail_once_used = true;
    }
    return SCARD_F_COMM_ERROR;
  }
  if (is_select_apdu(send_buffer, send_length, &with_le)) {
    if (g_mock.select_first_fail && with_le) {
      recv_buffer[0] = SW_FILE_NOT_FOUND_HI;
      recv_buffer[1] = SW_FILE_NOT_FOUND_LO;
      *recv_length = SW_LEN;
      return SCARD_S_SUCCESS;
    }
    recv_buffer[0] = SW_NO_ERROR_HI;
    recv_buffer[1] = 0x00u;
    *recv_length = SW_LEN;
    return SCARD_S_SUCCESS;
  }
  if (g_mock.transmit_response_len > *recv_length) {
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  (void)pcsc_fido_copy_bytes(recv_buffer, g_mock.transmit_response_len, 0u,
                             g_mock.transmit_response,
                             g_mock.transmit_response_len);
  *recv_length = (DWORD)g_mock.transmit_response_len;
  return SCARD_S_SUCCESS;
}

LONG scard_cancel(SCARDCONTEXT context) {
  (void)context;
  pthread_mutex_lock(&g_transmit_lock);
  if (atomic_load(&g_transmit_waiting)) {
    atomic_store(&g_cancel_during_transmit, true);
  }
  atomic_store(&g_transmit_cancelled, true);
  (void)pthread_cond_broadcast(&g_transmit_cond);
  pthread_mutex_unlock(&g_transmit_lock);
  return SCARD_S_SUCCESS;
}
