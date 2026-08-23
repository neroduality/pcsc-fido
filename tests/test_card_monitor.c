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

#include "pcsc_fido/card_monitor.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "pcsc_fido/pcsc_log.h"

enum {
  WAIT_TIMEOUT_SEC = 5,
};

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec* req, struct timespec* rem) {
  (void)req;
  (void)rem;
  return 0;
}

static int failures;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  pcsc_fido_card_monitor_t* monitor;
  unsigned count;
} wake_state_t;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void wake_count(void* ctx) {
  wake_state_t* state = (wake_state_t*)ctx;
  if (state != PCSC_FIDO_NULL) {
    pthread_mutex_lock(&state->mutex);
    state->count++;
    if (state->monitor != PCSC_FIDO_NULL) {
      atomic_store_explicit(&state->monitor->stop, true, memory_order_relaxed);
    }
    pthread_cond_signal(&state->cond);
    pthread_mutex_unlock(&state->mutex);
  }
}

static unsigned wait_for_wake(wake_state_t* state) {
  struct timespec deadline;
  unsigned count;
  if (state == PCSC_FIDO_NULL) {
    return 0u;
  }
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    return 0u;
  }
  deadline.tv_sec += WAIT_TIMEOUT_SEC;
  pthread_mutex_lock(&state->mutex);
  while (state->count == 0u) {
    if (pthread_cond_timedwait(&state->cond, &state->mutex, &deadline) ==
        ETIMEDOUT) {
      break;
    }
  }
  count = state->count;
  pthread_mutex_unlock(&state->mutex);
  return count;
}

static void absent_to_present_wakes(void) {
  static const bool PRESENT_EDGE_SEQUENCE[] = {false, true, true};
  pcsc_fido_card_monitor_t monitor;
  wake_state_t wakeups = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER,
                          &monitor, 0u};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Monitor Test Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      PRESENT_EDGE_SEQUENCE,
      sizeof(PRESENT_EDGE_SEQUENCE) / sizeof(PRESENT_EDGE_SEQUENCE[0]));
  expect_true(pcsc_fido_card_monitor_start(&monitor, wake_count, &wakeups),
              "monitor starts");
  unsigned count = wait_for_wake(&wakeups);
  pcsc_fido_card_monitor_stop(&monitor);
  expect_true(count > 0u, "absent-to-present edge wakes daemon");
  pthread_cond_destroy(&wakeups.cond);
  pthread_mutex_destroy(&wakeups.mutex);
}

static void initially_present_requires_fresh_edge(void) {
  static const bool FRESH_EDGE_SEQUENCE[] = {true, true, false, true};
  pcsc_fido_card_monitor_t monitor;
  wake_state_t wakeups = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER,
                          &monitor, 0u};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Monitor Test Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      FRESH_EDGE_SEQUENCE,
      sizeof(FRESH_EDGE_SEQUENCE) / sizeof(FRESH_EDGE_SEQUENCE[0]));
  expect_true(pcsc_fido_card_monitor_start(&monitor, wake_count, &wakeups),
              "monitor starts");
  unsigned count = wait_for_wake(&wakeups);
  pcsc_fido_card_monitor_stop(&monitor);
  expect_true(count > 0u,
              "initially present card requires absent-to-present edge");
  pthread_cond_destroy(&wakeups.cond);
  pthread_mutex_destroy(&wakeups.mutex);
}

static void monitor_survives_establish_failure(void) {
  pcsc_fido_card_monitor_t monitor;
  wake_state_t wakeups = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER,
                          &monitor, 0u};
  mock_pcsc_reset();
  mock_pcsc_set_establish_fail(1);
  expect_true(pcsc_fido_card_monitor_start(&monitor, wake_count, &wakeups),
              "monitor starts");
  pcsc_fido_card_monitor_stop(&monitor);
  expect_true(wakeups.count == 0u, "establish failure does not wake");
  pthread_cond_destroy(&wakeups.cond);
  pthread_mutex_destroy(&wakeups.mutex);
}

int main(void) {
  absent_to_present_wakes();
  initially_present_requires_fresh_edge();
  monitor_survives_establish_failure();
  return failures == 0 ? 0 : 1;
}
