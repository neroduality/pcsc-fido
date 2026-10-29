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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "pcsc_fido/pcsc_fido_null.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  FAKE_TIME_START = 1000,
  RATE_TOKEN_REFILL_SEC = 5, /* window 10 s / limit 2 */
  RATE_LONG_IDLE_SEC = 1000,
  DISABLED_LIMITER_ITERS = 8,
  WALL_TIME_START = 1800000000,
  WALL_CLOCK_STEP_BACK_SEC = 3600,
};

static time_t g_fake_time = FAKE_TIME_START;
static time_t g_wall_time = WALL_TIME_START;
static bool g_monotonic_fail;
static int failures;

/* Wall clock under test control; the limiter must not read it. */
time_t __wrap_time(time_t* t) {
  if (t != PCSC_FIDO_NULL) {
    *t = g_wall_time;
  }
  return g_wall_time;
}

extern int __real_clock_gettime(clockid_t clock_id, struct timespec* ts);

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* ts) {
  if (clock_id != CLOCK_MONOTONIC || ts == PCSC_FIDO_NULL) {
    return __real_clock_gettime(clock_id, ts);
  }
  if (g_monotonic_fail) {
    return -1;
  }
  ts->tv_sec = g_fake_time;
  ts->tv_nsec = 0;
  return 0;
}

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void reset_env(void) {
  unsetenv("PCSC_FIDO_RATE_LIMIT");
  unsetenv("PCSC_FIDO_RATE_WINDOW_SEC");
  unsetenv("PCSC_FIDO_RATE_CTAPHID");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
  g_fake_time = FAKE_TIME_START;
  g_monotonic_fail = false;
  pcsc_fido_rate_limit_reset();
}

static void ctaphid_limit_blocks_then_refills_gradually(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "2", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
              "first CTAPHID frame allowed");
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
              "second CTAPHID frame allowed");
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "third CTAPHID frame blocked");
  g_fake_time += RATE_TOKEN_REFILL_SEC - 1;
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "a partially refilled token is not spendable");
  g_fake_time += 1;
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
              "one token refills after window / limit seconds");
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(), "only one token refilled");
}

static void idle_refill_caps_at_burst(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "2", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "first frame allowed");
  g_fake_time += RATE_LONG_IDLE_SEC;
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "burst token 1 allowed");
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "burst token 2 allowed");
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "a long idle period does not bank more than the burst");
}

static void exchange_limit_blocks_and_reset_clears(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "first exchange allowed");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "second exchange blocked");
  pcsc_fido_rate_limit_reset();
  expect_true(pcsc_fido_rate_limit_allow_exchange(),
              "reset clears exchange bucket");
}

static void disabled_limiter_allows_requests(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_LIMIT", "0", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  for (unsigned i = 0; i < DISABLED_LIMITER_ITERS; i++) {
    expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
                "disabled CTAPHID limiter allows frame");
    expect_true(pcsc_fido_rate_limit_allow_exchange(),
                "disabled exchange limiter allows exchange");
  }
}

static void invalid_rate_env_uses_default(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_CTAPHID", "not-a-number", 1);
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
              "invalid CTAPHID env falls back without breaking");
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(),
              "exchange allowed with explicit limit");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "exchange blocked at configured limit");
}

static void clock_failure_does_not_refill(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(),
              "first exchange allowed before the clock fails");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "second exchange is over the limit");
  g_monotonic_fail = true;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "a failed monotonic clock denies a token");
  g_monotonic_fail = false;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "a failed clock did not refill the bucket");
}

static void negative_clock_does_not_grant_a_token(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  g_fake_time = -1;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "a negative monotonic clock denies a token");
  g_fake_time = FAKE_TIME_START;
  expect_true(pcsc_fido_rate_limit_allow_exchange(),
              "a later valid clock still has its first token");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "the negative reading did not leave a full bucket");
}

static void clock_step_back_does_not_refill(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(),
              "first exchange allowed before the step back");
  g_fake_time -= RATE_LONG_IDLE_SEC;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "a monotonic step backward does not grant credit");
  g_fake_time += RATE_LONG_IDLE_SEC;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "returning to the earlier timestamp does not refill");
}

static int g_other_charge_ok;

static void* charge_then_release(void* arg) {
  (void)arg;
  g_other_charge_ok = pcsc_fido_rate_limit_charge_exchange() ? 1 : 0;
  pcsc_fido_rate_limit_release_exchange_charge();
  return PCSC_FIDO_NULL;
}

/* Two threads each spend a token. The second thread dropping its own
 * unadopted charge must leave the first thread's charge to be taken. */
static void release_keeps_another_threads_charge(void) {
  pthread_t thread;
  reset_env();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_EXCHANGE", "2", 1);
  expect_true(pcsc_fido_rate_limit_charge_exchange(),
              "first thread can charge an exchange");
  g_other_charge_ok = 0;
  expect_true(pthread_create(&thread, PCSC_FIDO_NULL, charge_then_release,
                             PCSC_FIDO_NULL) == 0,
              "second charger thread starts");
  expect_true(pthread_join(thread, PCSC_FIDO_NULL) == 0,
              "second charger thread joins");
  expect_true(g_other_charge_ok == 1, "second thread charged its own token");
  expect_true(pcsc_fido_rate_limit_take_exchange_charge(),
              "first thread's charge survives the other release");
  expect_true(!pcsc_fido_rate_limit_take_exchange_charge(),
              "only one unadopted charge remained");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "both charged tokens stay spent");
}

static void wall_clock_step_does_not_refill_budget(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  g_wall_time = WALL_TIME_START;
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "first exchange allowed");
  g_wall_time -= WALL_CLOCK_STEP_BACK_SEC;
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "a wall-clock step back does not refill the exchange budget");
}

int main(void) {
  ctaphid_limit_blocks_then_refills_gradually();
  idle_refill_caps_at_burst();
  exchange_limit_blocks_and_reset_clears();
  disabled_limiter_allows_requests();
  invalid_rate_env_uses_default();
  wall_clock_step_does_not_refill_budget();
  clock_failure_does_not_refill();
  negative_clock_does_not_grant_a_token();
  clock_step_back_does_not_refill();
  release_keeps_another_threads_charge();
  reset_env();
  return failures == 0 ? 0 : 1;
}
