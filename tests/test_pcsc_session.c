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

#include "pcsc_fido/pcsc_session.h"

#include "mock_pcsc.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void generation_invalidated_by_reset(void) {
  pcsc_fido_session_tx_t tx;
  char err[128];
  mock_pcsc_reset();
  mock_pcsc_set_readers("Reader PICC 00 00");
  mock_pcsc_set_card_present_immediately(true);
  expect_true(pcsc_fido_session_ensure(nullptr, err, sizeof(err)), "session ensure");
  expect_true(pcsc_fido_session_snapshot_tx(&tx, err, sizeof(err)), "snapshot tx");
  expect_true(pcsc_fido_session_tx_is_current(&tx), "snapshot current before reset");
  pcsc_fido_session_reset();
  expect_true(!pcsc_fido_session_tx_is_current(&tx), "snapshot stale after reset");
}

static void verify_ready_tracks_card_presence(void) {
  char err[128];
  mock_pcsc_reset();
  mock_pcsc_set_readers("Reader PICC 00 00");
  mock_pcsc_set_card_present_immediately(true);
  expect_true(pcsc_fido_session_ensure(nullptr, err, sizeof(err)), "establish session");
  expect_true(pcsc_fido_session_verify_ready(err, sizeof(err)), "verify ready while present");
  mock_pcsc_set_card_present_immediately(false);
  expect_true(!pcsc_fido_session_verify_ready(err, sizeof(err)), "verify fails when card empty");
  pcsc_fido_session_reset();
}

int main(void) {
  generation_invalidated_by_reset();
  verify_ready_tracks_card_presence();
  pcsc_fido_session_reset();
  return failures == 0 ? 0 : 1;
}
