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

#include "test_caps.h"

#include "pcsc_fido/pcsc_bridge.h"

#include <pthread.h>
#include <stdio.h>
#include "pcsc_fido/pcsc_log.h"

enum {
  ITERATIONS = 10000,
};

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void* cancel_loop(void* arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    pcsc_fido_bridge_cancel();
  }
  return PCSC_FIDO_NULL;
}

static void* reset_loop(void* arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    pcsc_fido_bridge_reset();
  }
  return PCSC_FIDO_NULL;
}

static void* exchange_invalid_loop(void* arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    uint8_t response[TEST_LIT_8];
    char err[TEST_CAP_128];
    (void)pcsc_fido_bridge_exchange(
        PCSC_FIDO_NULL, TEST_LIT_0XFFU, PCSC_FIDO_NULL, 0u, response,
        sizeof(response), PCSC_FIDO_NULL, err, sizeof(err));
  }
  return PCSC_FIDO_NULL;
}

int main(void) {
  pthread_t cancel_thread;
  pthread_t reset_thread;
  pthread_t exchange_thread;
  expect_true(pthread_create(&cancel_thread, PCSC_FIDO_NULL, cancel_loop,
                             PCSC_FIDO_NULL) == 0,
              "cancel thread starts");
  expect_true(pthread_create(&reset_thread, PCSC_FIDO_NULL, reset_loop,
                             PCSC_FIDO_NULL) == 0,
              "reset thread starts");
  expect_true(pthread_create(&exchange_thread, PCSC_FIDO_NULL,
                             exchange_invalid_loop, PCSC_FIDO_NULL) == 0,
              "exchange thread starts");
  expect_true(pthread_join(cancel_thread, PCSC_FIDO_NULL) == 0,
              "cancel thread joins");
  expect_true(pthread_join(reset_thread, PCSC_FIDO_NULL) == 0,
              "reset thread joins");
  expect_true(pthread_join(exchange_thread, PCSC_FIDO_NULL) == 0,
              "exchange thread joins");
  pcsc_fido_bridge_reset();
  return failures == 0 ? 0 : 1;
}
