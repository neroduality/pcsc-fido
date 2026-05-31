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

#include "pcsc_fido/pcsc_bridge.h"

#include <pthread.h>
#include <stdio.h>

enum {
  ITERATIONS = 10000,
};

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void *cancel_loop(void *arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    pcsc_fido_bridge_cancel();
  }
  return nullptr;
}

static void *reset_loop(void *arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    pcsc_fido_bridge_reset();
  }
  return nullptr;
}

static void *exchange_invalid_loop(void *arg) {
  (void)arg;
  for (int i = 0; i < ITERATIONS; i++) {
    uint8_t response[8];
    char err[128];
    (void)pcsc_fido_bridge_exchange(nullptr, 0xFFu, nullptr, 0u, response, sizeof(response),
                                    nullptr, err, sizeof(err));
  }
  return nullptr;
}

int main(void) {
  pthread_t cancel_thread;
  pthread_t reset_thread;
  pthread_t exchange_thread;
  expect_true(pthread_create(&cancel_thread, nullptr, cancel_loop, nullptr) == 0,
              "cancel thread starts");
  expect_true(pthread_create(&reset_thread, nullptr, reset_loop, nullptr) == 0,
              "reset thread starts");
  expect_true(pthread_create(&exchange_thread, nullptr, exchange_invalid_loop, nullptr) == 0,
              "exchange thread starts");
  expect_true(pthread_join(cancel_thread, nullptr) == 0, "cancel thread joins");
  expect_true(pthread_join(reset_thread, nullptr) == 0, "reset thread joins");
  expect_true(pthread_join(exchange_thread, nullptr) == 0, "exchange thread joins");
  pcsc_fido_bridge_reset();
  return failures == 0 ? 0 : 1;
}
