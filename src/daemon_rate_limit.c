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

#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_fido_parse.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_util.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pcsc_fido/mem_util.h"

/* Spec prefixes for docs/spec-traceability.yaml: IMPL-POLICY */
enum {
  PCSC_FIDO_RATE_WINDOW_SEC_DEFAULT = 90u,
  PCSC_FIDO_RATE_CTAPHID_DEFAULT = 60u,
  PCSC_FIDO_RATE_EXCHANGE_DEFAULT = 24u,
  PCSC_FIDO_RATE_VALUE_MAX = 1000000u,
};

/* Token bucket holding up to `limit` tokens and refilling from empty to full
 * over `window_sec`. Credit is kept in units of 1/window_sec token so refill
 * stays exact in integer arithmetic (limit * window_sec <= 10^12). */
typedef struct {
  bool started;
  time_t last_refill;
  uint64_t credit;
} pcsc_fido_rate_bucket_t;

/* Environment settings are parsed on first use after a reset and cached, so
 * an invalid value is logged once instead of on every frame. */
typedef struct {
  bool loaded;
  unsigned value;
} pcsc_fido_rate_setting_t;

static pthread_mutex_t g_rate_lock = PTHREAD_MUTEX_INITIALIZER;
/* Charges this thread has made and not yet released or detached. */
static _Thread_local unsigned t_outstanding;
/* Charges no bridge exchange has adopted yet. A bool cannot tell two
 * threads' charges apart, so a loser of the in-flight race used to clear
 * the winner's mark and the winner was billed a second token. */
static atomic_uint g_unclaimed;
static pcsc_fido_rate_bucket_t g_ctaphid_bucket;
static pcsc_fido_rate_bucket_t g_exchange_bucket;
static pcsc_fido_rate_setting_t g_enabled_setting;
static pcsc_fido_rate_setting_t g_window_setting;
static pcsc_fido_rate_setting_t g_ctaphid_setting;
static pcsc_fido_rate_setting_t g_exchange_setting;

static bool rate_limit_enabled(void) {
  if (!g_enabled_setting.loaded) {
    const char* v = getenv("PCSC_FIDO_RATE_LIMIT");
    g_enabled_setting.value =
        (v == PCSC_FIDO_NULL || v[0] == '\0' || strcmp(v, "0") != 0) ? 1u : 0u;
    g_enabled_setting.loaded = true;
  }
  return g_enabled_setting.value != 0u;
}

static unsigned read_rate_env(const char* name, unsigned default_value) {
  const char* v = getenv(name);
  uint32_t parsed = 0u;
  if (v == PCSC_FIDO_NULL || v[0] == '\0') {
    return default_value;
  }
  if (!pcsc_fido_parse_u32(v, &parsed) || parsed == 0u ||
      parsed > (uint32_t)PCSC_FIDO_RATE_VALUE_MAX) {
    pcsc_fido_log(PCSC_FIDO_LOG_INFO, "invalid %s=%s; using default %u", name,
                  v, default_value);
    return default_value;
  }
  return (unsigned)parsed;
}

static unsigned cached_rate_env(pcsc_fido_rate_setting_t* setting,
                                const char* name, unsigned default_value) {
  if (!setting->loaded) {
    setting->value = read_rate_env(name, default_value);
    setting->loaded = true;
  }
  return setting->value;
}

static bool allow_bucket(pcsc_fido_rate_bucket_t* bucket, unsigned limit,
                         unsigned window_sec) {
  const time_t now = pcsc_fido_monotonic_sec();
  const uint64_t capacity = (uint64_t)limit * (uint64_t)window_sec;
  if (bucket == PCSC_FIDO_NULL) {
    return false;
  }
  /* LONG_MAX is a failed or negative clock. A negative timestamp must not
   * start a full bucket, and LONG_MAX must not look like a full window. */
  if (now < 0 || now == (time_t)LONG_MAX) {
    return false;
  }
  if (!bucket->started) {
    bucket->started = true;
    bucket->last_refill = now;
    bucket->credit = capacity;
  } else if (now > bucket->last_refill) {
    const time_t elapsed = now - bucket->last_refill;
    const uint64_t capped = elapsed >= (time_t)window_sec ? (uint64_t)window_sec
                                                          : (uint64_t)elapsed;
    bucket->credit += capped * (uint64_t)limit;
    if (bucket->credit > capacity) {
      bucket->credit = capacity;
    }
    bucket->last_refill = now;
  }
  /* now <= last_refill is the same second, or a step backward. Leave
   * last_refill where it is so that interval is not credited again. */
  if (bucket->credit < (uint64_t)window_sec) {
    return false;
  }
  bucket->credit -= (uint64_t)window_sec;
  return true;
}

static bool allow_with_limit(pcsc_fido_rate_bucket_t* bucket,
                             pcsc_fido_rate_setting_t* limit_setting,
                             const char* limit_env, unsigned default_limit) {
  bool allowed = true;
  pthread_mutex_lock(&g_rate_lock);
  if (rate_limit_enabled()) {
    const unsigned window_sec =
        cached_rate_env(&g_window_setting, "PCSC_FIDO_RATE_WINDOW_SEC",
                        PCSC_FIDO_RATE_WINDOW_SEC_DEFAULT);
    const unsigned limit =
        cached_rate_env(limit_setting, limit_env, default_limit);
    allowed = allow_bucket(bucket, limit, window_sec);
  }
  pthread_mutex_unlock(&g_rate_lock);
  return allowed;
}

bool pcsc_fido_rate_limit_allow_ctaphid(void) {
  return allow_with_limit(&g_ctaphid_bucket, &g_ctaphid_setting,
                          "PCSC_FIDO_RATE_CTAPHID",
                          PCSC_FIDO_RATE_CTAPHID_DEFAULT);
}

bool pcsc_fido_rate_limit_allow_exchange(void) {
  return allow_with_limit(&g_exchange_bucket, &g_exchange_setting,
                          "PCSC_FIDO_RATE_EXCHANGE",
                          PCSC_FIDO_RATE_EXCHANGE_DEFAULT);
}

static bool unclaimed_decrement(void) {
  unsigned current = atomic_load_explicit(&g_unclaimed, memory_order_acquire);
  while (current > 0u) {
    if (atomic_compare_exchange_weak_explicit(
            &g_unclaimed, &current, current - 1u, memory_order_acq_rel,
            memory_order_acquire)) {
      return true;
    }
  }
  return false;
}

bool pcsc_fido_rate_limit_charge_exchange(void) {
  if (!pcsc_fido_rate_limit_allow_exchange()) {
    return false;
  }
  t_outstanding++;
  atomic_fetch_add_explicit(&g_unclaimed, 1u, memory_order_acq_rel);
  return true;
}

bool pcsc_fido_rate_limit_take_exchange_charge(void) {
  if (!unclaimed_decrement()) {
    return false;
  }
  /* Same-thread adopt (the bridge test charges and exchanges on one
   * thread). The worker's count is zero, so it does not clear the
   * joiner's. */
  if (t_outstanding > 0u) {
    t_outstanding--;
  }
  return true;
}

void pcsc_fido_rate_limit_release_exchange_charge(void) {
  while (t_outstanding > 0u) {
    t_outstanding--;
    (void)unclaimed_decrement();
  }
}

void pcsc_fido_rate_limit_detach_local_charge(void) { t_outstanding = 0u; }

void pcsc_fido_rate_limit_reset(void) {
  pcsc_fido_rate_limit_detach_local_charge();
  atomic_store_explicit(&g_unclaimed, 0u, memory_order_release);
  pthread_mutex_lock(&g_rate_lock);
  pcsc_fido_zero_bytes(&g_ctaphid_bucket, sizeof(g_ctaphid_bucket));
  pcsc_fido_zero_bytes(&g_exchange_bucket, sizeof(g_exchange_bucket));
  pcsc_fido_zero_bytes(&g_enabled_setting, sizeof(g_enabled_setting));
  pcsc_fido_zero_bytes(&g_window_setting, sizeof(g_window_setting));
  pcsc_fido_zero_bytes(&g_ctaphid_setting, sizeof(g_ctaphid_setting));
  pcsc_fido_zero_bytes(&g_exchange_setting, sizeof(g_exchange_setting));
  pthread_mutex_unlock(&g_rate_lock);
}
