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

#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/pcsc_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
  PCSC_FIDO_RATE_WINDOW_SEC_DEFAULT = 90u,
  PCSC_FIDO_RATE_CTAPHID_DEFAULT = 30u,
  PCSC_FIDO_RATE_EXCHANGE_DEFAULT = 10u,
  PCSC_FIDO_RATE_VALUE_MAX = 1000000u,
};

typedef struct {
  time_t window_start;
  unsigned count;
} pcsc_fido_rate_bucket_t;

static pthread_mutex_t g_rate_lock = PTHREAD_MUTEX_INITIALIZER;
static pcsc_fido_rate_bucket_t g_ctaphid_bucket;
static pcsc_fido_rate_bucket_t g_exchange_bucket;

static bool rate_limit_enabled(void) {
  const char *v = getenv("PCSC_FIDO_RATE_LIMIT");
  return v == nullptr || v[0] == '\0' || strcmp(v, "0") != 0;
}

static unsigned read_rate_env(const char *name, unsigned default_value) {
  const char *v = getenv(name);
  char *end = nullptr;
  unsigned long parsed;
  if (v == nullptr || v[0] == '\0') {
    return default_value;
  }
  errno = 0;
  parsed = strtoul(v, &end, 10);
  if (errno != 0 || end == v || *end != '\0' || parsed == 0UL ||
      parsed > (unsigned long)PCSC_FIDO_RATE_VALUE_MAX) {
    pcsc_fido_log(PCSC_FIDO_LOG_INFO, "invalid %s=%s; using default %u", name, v, default_value);
    return default_value;
  }
  return (unsigned)parsed;
}

static bool allow_bucket(pcsc_fido_rate_bucket_t *bucket, unsigned limit, unsigned window_sec) {
  const time_t now = time(nullptr);
  if (bucket == nullptr) {
    return false;
  }
  if (bucket->window_start == 0 || now < bucket->window_start ||
      now - bucket->window_start >= (time_t)window_sec) {
    bucket->window_start = now;
    bucket->count = 0u;
  }
  if (bucket->count >= limit) {
    return false;
  }
  bucket->count++;
  return true;
}

static bool allow_with_limit(pcsc_fido_rate_bucket_t *bucket, const char *limit_env,
                             unsigned default_limit) {
  bool allowed;
  const unsigned window_sec =
    read_rate_env("PCSC_FIDO_RATE_WINDOW_SEC", PCSC_FIDO_RATE_WINDOW_SEC_DEFAULT);
  const unsigned limit = read_rate_env(limit_env, default_limit);
  if (!rate_limit_enabled()) {
    return true;
  }
  pthread_mutex_lock(&g_rate_lock);
  allowed = allow_bucket(bucket, limit, window_sec);
  pthread_mutex_unlock(&g_rate_lock);
  return allowed;
}

bool pcsc_fido_rate_limit_allow_ctaphid(void) {
  return allow_with_limit(&g_ctaphid_bucket, "PCSC_FIDO_RATE_CTAPHID",
                          PCSC_FIDO_RATE_CTAPHID_DEFAULT);
}

bool pcsc_fido_rate_limit_allow_exchange(void) {
  return allow_with_limit(&g_exchange_bucket, "PCSC_FIDO_RATE_EXCHANGE",
                          PCSC_FIDO_RATE_EXCHANGE_DEFAULT);
}

void pcsc_fido_rate_limit_reset(void) {
  pthread_mutex_lock(&g_rate_lock);
  memset(&g_ctaphid_bucket, 0, sizeof(g_ctaphid_bucket));
  memset(&g_exchange_bucket, 0, sizeof(g_exchange_bucket));
  pthread_mutex_unlock(&g_rate_lock);
}
