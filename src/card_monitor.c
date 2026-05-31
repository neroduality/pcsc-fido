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

#include "pcsc_fido/card_monitor.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_reader_ops.h"
#include "pcsc_fido/pcsc_util.h"
#include "pcsc_fido/reader_select.h"

#include <winscard.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void short_sleep(void) {
  pcsc_fido_sleep_ms((long)PCSC_FIDO_READER_STATUS_POLL_MS);
}

static bool any_eligible_card_present(const SCARD_READERSTATE states[PCSC_FIDO_BRIDGE_MAX_READERS],
                                      size_t count) {
  for (size_t i = 0u; i < count; i++) {
    if (pcsc_fido_reader_state_has_card((const pcsc_fido_reader_state_t *)&states[i])) {
      return true;
    }
  }
  return false;
}

static void *monitor_main(void *arg) {
  pcsc_fido_card_monitor_t *monitor = (pcsc_fido_card_monitor_t *)arg;
  bool saw_eligible_present = false;
  bool have_observation = false;
  if (monitor == nullptr) {
    return nullptr;
  }
  while (!atomic_load_explicit(&monitor->stop, memory_order_relaxed)) {
    SCARDCONTEXT ctx = 0;
    char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
    DWORD readers_len = sizeof(readers);
    SCARD_READERSTATE states[PCSC_FIDO_BRIDGE_MAX_READERS];
    size_t count;
    if (!pcsc_fido_reader_establish_context(&ctx, PCSC_FIDO_READER_CTX_DAEMON, nullptr, 0u)) {
      short_sleep();
      continue;
    }
    memset(readers, 0, sizeof(readers));
    memset(states, 0, sizeof(states));
    if (!pcsc_fido_reader_list_snapshot(ctx, readers, &readers_len, nullptr, 0u)) {
      (void)SCardReleaseContext(ctx);
      short_sleep();
      continue;
    }
    count = pcsc_fido_reader_fill_status_states(readers, readers_len, states,
                                                PCSC_FIDO_BRIDGE_MAX_READERS);
    if (count == 0u) {
      (void)SCardReleaseContext(ctx);
      short_sleep();
      continue;
    }
    if (SCardGetStatusChange(ctx, PCSC_FIDO_READER_STATUS_POLL_MS, states, (DWORD)count) ==
        SCARD_S_SUCCESS) {
      bool eligible_present = any_eligible_card_present(states, count);
      if (have_observation && !saw_eligible_present && eligible_present &&
          monitor->wake != nullptr) {
        monitor->wake(monitor->wake_ctx);
      }
      saw_eligible_present = eligible_present;
      have_observation = true;
    }
    (void)SCardReleaseContext(ctx);
    short_sleep();
  }
  return nullptr;
}

bool pcsc_fido_card_monitor_start(pcsc_fido_card_monitor_t *monitor,
                                  pcsc_fido_card_monitor_wake_fn wake, void *wake_ctx) {
  if (monitor == nullptr || wake == nullptr) {
    return false;
  }
  memset(monitor, 0, sizeof(*monitor));
  atomic_init(&monitor->stop, false);
  monitor->wake = wake;
  monitor->wake_ctx = wake_ctx;
  int rc = pthread_create(&monitor->thread, nullptr, monitor_main, monitor);
  if (rc != 0) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "card monitor thread start failed: %s", strerror(rc));
    return false;
  }
  monitor->running = true;
  return true;
}

void pcsc_fido_card_monitor_stop(pcsc_fido_card_monitor_t *monitor) {
  if (monitor == nullptr || !monitor->running) {
    return;
  }
  atomic_store_explicit(&monitor->stop, true, memory_order_relaxed);
  (void)pthread_join(monitor->thread, nullptr);
  monitor->running = false;
}
