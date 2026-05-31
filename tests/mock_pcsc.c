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

#include "mock_pcsc.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

enum {
  MOCK_SCARD_WAIT_INFINITE = 0xFFFFFFFFu,
};

static void mock_sleep_status_timeout(DWORD dwTimeout) {
  struct timespec ts;
  long ms;
  if (dwTimeout == 0u || dwTimeout == MOCK_SCARD_WAIT_INFINITE) {
    return;
  }
  ms = (long)dwTimeout;
  ts.tv_sec = ms / 1000L;
  ts.tv_nsec = (long)(ms % 1000L) * 1000000L;
  (void)nanosleep(&ts, nullptr);
}

static LONG mock_return_status_timeout(DWORD dwTimeout) {
  mock_sleep_status_timeout(dwTimeout);
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

static void deadline_from_now(struct timespec *deadline, unsigned timeout_ms) {
  (void)clock_gettime(CLOCK_REALTIME, deadline);
  deadline->tv_sec += (time_t)(timeout_ms / 1000u);
  deadline->tv_nsec += (long)((timeout_ms % 1000u) * 1000000u);
  if (deadline->tv_nsec >= 1000000000L) {
    deadline->tv_sec++;
    deadline->tv_nsec -= 1000000000L;
  }
}

static const uint8_t k_fido_aid[] = {0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u};

void mock_pcsc_reset(void) {
  memset(&g_mock, 0, sizeof(g_mock));
  pthread_mutex_lock(&g_transmit_lock);
  atomic_store(&g_transmit_wait_for_cancel, false);
  atomic_store(&g_transmit_waiting, false);
  atomic_store(&g_transmit_cancelled, false);
  atomic_store(&g_cancel_during_transmit, false);
  (void)pthread_cond_broadcast(&g_transmit_cond);
  pthread_mutex_unlock(&g_transmit_lock);
  g_mock.connect_active_protocol = SCARD_PROTOCOL_T1;
  g_mock.card_present_immediately = true;
  g_mock.transmit_response[0] = 0x00u;
  g_mock.transmit_response[1] = 0xA1u;
  g_mock.transmit_response[2] = 0x01u;
  g_mock.transmit_response[3] = 0x02u;
  g_mock.transmit_response[4] = 0x90u;
  g_mock.transmit_response[5] = 0x00u;
  g_mock.transmit_response_len = 6u;
}

static size_t mock_readers_msz_len(void) {
  if (g_mock.readers_msz_len != 0u) {
    return g_mock.readers_msz_len;
  }
  if (g_mock.readers[0] == '\0') {
    return 0u;
  }
  return strlen(g_mock.readers) + 2u;
}

void mock_pcsc_set_readers(const char *readers) {
  if (readers == nullptr) {
    g_mock.readers[0] = '\0';
    g_mock.readers_msz_len = 0u;
    return;
  }
  memset(g_mock.readers, 0, sizeof(g_mock.readers));
  snprintf(g_mock.readers, sizeof(g_mock.readers), "%s", readers);
  g_mock.readers_msz_len = 0u;
}

void mock_pcsc_set_reader_pair(const char *reader_a, const char *reader_b) {
  size_t alen;
  size_t blen;
  size_t total;
  if (reader_a == nullptr || reader_b == nullptr) {
    g_mock.readers[0] = '\0';
    g_mock.readers_msz_len = 0u;
    return;
  }
  alen = strlen(reader_a);
  blen = strlen(reader_b);
  total = alen + 1u + blen + 2u;
  if (total > MOCK_READERS_CAP) {
    total = MOCK_READERS_CAP;
  }
  memset(g_mock.readers, 0, sizeof(g_mock.readers));
  memcpy(g_mock.readers, reader_a, alen + 1u);
  memcpy(g_mock.readers + alen + 1u, reader_b, blen + 1u);
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

void mock_pcsc_set_establish_fail(LONG rv) {
  g_mock.establish_fail = rv;
}

void mock_pcsc_set_list_probe_fail(LONG rv) {
  g_mock.list_probe_fail = rv;
}

void mock_pcsc_set_list_fill_fail(LONG rv) {
  g_mock.list_fill_fail = rv;
}

void mock_pcsc_set_get_status_fail(LONG rv) {
  g_mock.get_status_fail = rv;
}

void mock_pcsc_set_connect_fail(LONG rv) {
  g_mock.connect_fail = rv;
}

void mock_pcsc_set_connect_proto_mismatch_once(bool enabled) {
  g_mock.connect_proto_mismatch_once = enabled;
}

void mock_pcsc_set_connect_active_protocol(DWORD protocol) {
  g_mock.connect_active_protocol = protocol;
}

void mock_pcsc_set_card_present_immediately(bool enabled) {
  g_mock.card_present_immediately = enabled;
}

void mock_pcsc_set_status_present_sequence(const bool *present, size_t len) {
  if (present == nullptr || len == 0u) {
    g_mock.status_present_sequence_len = 0u;
    g_mock.status_present_sequence_pos = 0u;
    return;
  }
  if (len > MOCK_STATUS_SEQUENCE_CAP) {
    len = MOCK_STATUS_SEQUENCE_CAP;
  }
  memcpy(g_mock.status_present_sequence, present, len * sizeof(present[0]));
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

void mock_pcsc_set_transmit_response(const uint8_t *data, size_t len) {
  if (data == nullptr || len > sizeof(g_mock.transmit_response)) {
    g_mock.transmit_response_len = 0u;
    return;
  }
  memcpy(g_mock.transmit_response, data, len);
  g_mock.transmit_response_len = len;
}

void mock_pcsc_set_select_first_fail(bool enabled) {
  g_mock.select_first_fail = enabled;
}

unsigned mock_pcsc_transmit_call_count(void) {
  return g_mock.transmit_calls;
}

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
    if (pthread_cond_timedwait(&g_transmit_cond, &g_transmit_lock, &deadline) != 0) {
      break;
    }
  }
  waiting = atomic_load(&g_transmit_waiting);
  pthread_mutex_unlock(&g_transmit_lock);
  return waiting;
}

static bool is_select_apdu(const uint8_t *capdu, DWORD capdu_len, bool *with_le) {
  *with_le = false;
  if (capdu == nullptr || capdu_len < 13u) {
    return false;
  }
  if (capdu[0] != 0x00u || capdu[1] != 0xA4u || capdu[2] != 0x04u || capdu[3] != 0x00u ||
      capdu[4] != (uint8_t)sizeof(k_fido_aid) ||
      memcmp(capdu + 5u, k_fido_aid, sizeof(k_fido_aid)) != 0) {
    return false;
  }
  if (capdu_len == 13u + 1u) {
    *with_le = true;
  }
  return true;
}

LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2,
                           LPSCARDCONTEXT phContext) {
  (void)dwScope;
  (void)pvReserved1;
  (void)pvReserved2;
  if (phContext == nullptr) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.establish_fail_system_scope && dwScope == SCARD_SCOPE_SYSTEM) {
    return SCARD_F_INTERNAL_ERROR;
  }
  if (g_mock.establish_fail != 0) {
    return g_mock.establish_fail;
  }
  *phContext = 1;
  return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT hContext) {
  (void)hContext;
  return SCARD_S_SUCCESS;
}

LONG SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders,
                      LPDWORD pcchReaders) {
  (void)hContext;
  (void)mszGroups;
  if (pcchReaders == nullptr) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (mszReaders == nullptr) {
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
      *pcchReaders = g_mock.list_probe_needed;
      return SCARD_S_SUCCESS;
    }
    *pcchReaders = (DWORD)mock_readers_msz_len();
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
    if (*pcchReaders < needed) {
      return SCARD_E_INSUFFICIENT_BUFFER;
    }
    memcpy(mszReaders, g_mock.readers, needed);
    *pcchReaders = needed;
  }
  return SCARD_S_SUCCESS;
}

LONG SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                          LPSCARD_READERSTATE rgReaderStates, DWORD cReaders) {
  (void)hContext;
  g_mock.get_status_calls++;
  if (g_mock.get_status_fail != 0) {
    return g_mock.get_status_fail;
  }
  if (rgReaderStates == nullptr || cReaders == 0u) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.get_status_timeouts_before_present > 0u) {
    g_mock.get_status_timeouts_before_present--;
    return mock_return_status_timeout(dwTimeout);
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
    return mock_return_status_timeout(dwTimeout);
  }
  for (DWORD i = 0u; i < cReaders; i++) {
    rgReaderStates[i].dwEventState = SCARD_STATE_CHANGED | SCARD_STATE_UNPOWERED;
    if (present) {
      rgReaderStates[i].dwEventState |= SCARD_STATE_PRESENT;
    } else {
      rgReaderStates[i].dwEventState |= SCARD_STATE_EMPTY;
    }
    if (g_mock.multi_present_readers && cReaders > 1u) {
      continue;
    }
  }
  return SCARD_S_SUCCESS;
}

LONG SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
                  DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol) {
  (void)hContext;
  (void)szReader;
  (void)dwShareMode;
  (void)dwPreferredProtocols;
  if (phCard == nullptr || pdwActiveProtocol == nullptr) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (g_mock.connect_fail != 0) {
    return g_mock.connect_fail;
  }
  if (g_mock.connect_proto_mismatch_once && !g_mock.connect_proto_mismatch_used) {
    g_mock.connect_proto_mismatch_used = true;
    return SCARD_E_PROTO_MISMATCH;
  }
  *phCard = 2;
  *pdwActiveProtocol = g_mock.connect_active_protocol;
  return SCARD_S_SUCCESS;
}

LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition) {
  (void)hCard;
  (void)dwDisposition;
  return SCARD_S_SUCCESS;
}

LONG SCardStatus(SCARDHANDLE hCard, LPSTR mszReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState,
                 LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen) {
  (void)mszReaderName;
  (void)pcchReaderLen;
  (void)pbAtr;
  (void)pcbAtrLen;
  if (hCard == 0) {
    return SCARD_E_INVALID_HANDLE;
  }
  if (pdwState == nullptr || pdwProtocol == nullptr) {
    return SCARD_E_INVALID_PARAMETER;
  }
  *pdwProtocol = g_mock.connect_active_protocol;
  *pdwState = 0u;
  if (g_mock.card_present_immediately) {
    *pdwState |= SCARD_STATE_PRESENT;
  } else {
    *pdwState |= SCARD_STATE_EMPTY;
  }
  return SCARD_S_SUCCESS;
}

LONG SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci, LPCBYTE pbSendBuffer,
                   DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer,
                   LPDWORD pcbRecvLength) {
  bool with_le = false;
  (void)hCard;
  (void)pioSendPci;
  (void)pioRecvPci;
  g_mock.transmit_calls++;
  if (pbRecvBuffer == nullptr || pcbRecvLength == nullptr) {
    return SCARD_E_INVALID_PARAMETER;
  }
  if (!is_select_apdu(pbSendBuffer, cbSendLength, &with_le) &&
      atomic_load(&g_transmit_wait_for_cancel)) {
    struct timespec deadline;
    LONG rv = SCARD_F_COMM_ERROR;
    deadline_from_now(&deadline, 200u);
    pthread_mutex_lock(&g_transmit_lock);
    atomic_store(&g_transmit_waiting, true);
    (void)pthread_cond_broadcast(&g_transmit_cond);
    while (!atomic_load(&g_transmit_cancelled)) {
      if (pthread_cond_timedwait(&g_transmit_cond, &g_transmit_lock, &deadline) != 0) {
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
  if (g_mock.transmit_fail || (g_mock.transmit_fail_once && !g_mock.transmit_fail_once_used)) {
    if (g_mock.transmit_fail_once) {
      g_mock.transmit_fail_once_used = true;
    }
    return SCARD_F_COMM_ERROR;
  }
  if (is_select_apdu(pbSendBuffer, cbSendLength, &with_le)) {
    if (g_mock.select_first_fail && with_le) {
      pbRecvBuffer[0] = 0x6Au;
      pbRecvBuffer[1] = 0x82u;
      *pcbRecvLength = 2u;
      return SCARD_S_SUCCESS;
    }
    pbRecvBuffer[0] = 0x90u;
    pbRecvBuffer[1] = 0x00u;
    *pcbRecvLength = 2u;
    return SCARD_S_SUCCESS;
  }
  if (g_mock.transmit_response_len > *pcbRecvLength) {
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  memcpy(pbRecvBuffer, g_mock.transmit_response, g_mock.transmit_response_len);
  *pcbRecvLength = (DWORD)g_mock.transmit_response_len;
  return SCARD_S_SUCCESS;
}

LONG SCardCancel(SCARDCONTEXT hContext) {
  (void)hContext;
  pthread_mutex_lock(&g_transmit_lock);
  if (atomic_load(&g_transmit_waiting)) {
    atomic_store(&g_cancel_during_transmit, true);
  }
  atomic_store(&g_transmit_cancelled, true);
  (void)pthread_cond_broadcast(&g_transmit_cond);
  pthread_mutex_unlock(&g_transmit_lock);
  return SCARD_S_SUCCESS;
}
