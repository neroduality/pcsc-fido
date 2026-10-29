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

#include "scrub_hook.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#include "pcsc_fido/pcsc_fido_null.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  /* Distinct wipe lengths per scenario. Counting per length rather than
   * logging each call keeps the counts exact however many keepalive passes
   * a timing-dependent exchange makes. */
  SCRUB_HOOK_LEN_SLOTS = 64,
};

/* Wipes fire from the keepalive worker and the main thread concurrently in the
 * exchange-orchestrator tests, so every counter below is guarded. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_calls;
static size_t g_bytes;
static size_t g_max_len;
static bool g_all_zero = true;
static size_t g_lens[SCRUB_HOOK_LEN_SLOTS];
static unsigned g_len_calls[SCRUB_HOOK_LEN_SLOTS];
static unsigned g_len_slots_used;

extern void __real_pcsc_fido_secure_clear(void* ptr, size_t len);

static void count_len_locked(size_t len) {
  for (unsigned i = 0u; i < g_len_slots_used; i++) {
    if (g_lens[i] == len) {
      g_len_calls[i]++;
      return;
    }
  }
  if (g_len_slots_used == SCRUB_HOOK_LEN_SLOTS) {
    /* An undercount would pass or fail assertions at random. */
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR,
                  "scrub_hook: more than %d distinct wipe lengths",
                  SCRUB_HOOK_LEN_SLOTS);
    abort();
  }
  g_lens[g_len_slots_used] = len;
  g_len_calls[g_len_slots_used] = 1u;
  g_len_slots_used++;
}

void __wrap_pcsc_fido_secure_clear(void* ptr, size_t len) {
  const uint8_t* bytes = (const uint8_t*)ptr;
  bool all_zero = true;
  __real_pcsc_fido_secure_clear(ptr, len);
  for (size_t i = 0u; bytes != PCSC_FIDO_NULL && i < len; i++) {
    if (bytes[i] != 0u) {
      all_zero = false;
    }
  }
  pthread_mutex_lock(&g_lock);
  g_calls++;
  g_bytes += len;
  if (len > g_max_len) {
    g_max_len = len;
  }
  count_len_locked(len);
  if (!all_zero) {
    g_all_zero = false;
  }
  pthread_mutex_unlock(&g_lock);
}

void scrub_hook_reset(void) {
  pthread_mutex_lock(&g_lock);
  g_calls = 0u;
  g_bytes = 0u;
  g_max_len = 0u;
  g_all_zero = true;
  g_len_slots_used = 0u;
  pthread_mutex_unlock(&g_lock);
}

unsigned scrub_hook_calls(void) {
  pthread_mutex_lock(&g_lock);
  const unsigned calls = g_calls;
  pthread_mutex_unlock(&g_lock);
  return calls;
}

size_t scrub_hook_bytes(void) {
  pthread_mutex_lock(&g_lock);
  const size_t bytes = g_bytes;
  pthread_mutex_unlock(&g_lock);
  return bytes;
}

size_t scrub_hook_max_len(void) {
  pthread_mutex_lock(&g_lock);
  const size_t max_len = g_max_len;
  pthread_mutex_unlock(&g_lock);
  return max_len;
}

bool scrub_hook_all_zero(void) {
  pthread_mutex_lock(&g_lock);
  const bool all_zero = g_all_zero;
  pthread_mutex_unlock(&g_lock);
  return all_zero;
}

unsigned scrub_hook_calls_with_len(size_t len) {
  unsigned hits = 0u;
  pthread_mutex_lock(&g_lock);
  for (unsigned i = 0u; i < g_len_slots_used; i++) {
    if (g_lens[i] == len) {
      hits = g_len_calls[i];
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return hits;
}
