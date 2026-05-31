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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static time_t g_fake_time = 1000;
static int failures;

time_t __wrap_time(time_t *t) {
  if (t != nullptr) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void reset_env(void) {
  unsetenv("PCSC_FIDO_RATE_LIMIT");
  unsetenv("PCSC_FIDO_RATE_WINDOW_SEC");
  unsetenv("PCSC_FIDO_RATE_CTAPHID");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
  g_fake_time = 1000;
  pcsc_fido_rate_limit_reset();
}

static void ctaphid_limit_blocks_then_window_resets(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "2", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "first CTAPHID frame allowed");
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "second CTAPHID frame allowed");
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(), "third CTAPHID frame blocked");
  g_fake_time += 10;
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "CTAPHID window reset allows frame");
}

static void exchange_limit_blocks_and_reset_clears(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "first exchange allowed");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(), "second exchange blocked");
  pcsc_fido_rate_limit_reset();
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "reset clears exchange bucket");
}

static void disabled_limiter_allows_requests(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_LIMIT", "0", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  for (unsigned i = 0; i < 8u; i++) {
    expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "disabled CTAPHID limiter allows frame");
    expect_true(pcsc_fido_rate_limit_allow_exchange(), "disabled exchange limiter allows exchange");
  }
}

static void invalid_rate_env_uses_default(void) {
  reset_env();
  setenv("PCSC_FIDO_RATE_CTAPHID", "not-a-number", 1);
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(),
              "invalid CTAPHID env falls back without breaking");
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "exchange allowed with explicit limit");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(), "exchange blocked at configured limit");
}

int main(void) {
  ctaphid_limit_blocks_then_window_resets();
  exchange_limit_blocks_and_reset_clears();
  disabled_limiter_allows_requests();
  invalid_rate_env_uses_default();
  reset_env();
  return failures == 0 ? 0 : 1;
}
