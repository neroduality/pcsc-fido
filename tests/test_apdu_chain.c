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
#include "pcsc_fido/apdu_chain.h"

#include <stdio.h>
#include <string.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  TEST_LIT_0X10U = 0x10u,
  TEST_LIT_0X6110U = 0x6110u,
  TEST_LIT_0XC0U = 0xC0u,
};

typedef struct {
  const uint8_t* responses[TEST_LIT_8];
  size_t response_lens[TEST_LIT_8];
  size_t response_count;
  size_t response_index;
  unsigned get_response_calls;
  uint8_t last_get_response_le;
} mock_tx_t;

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static bool mock_transmit(void* ctx, const uint8_t* capdu, size_t capdu_len,
                          uint8_t* rapdu, size_t rapdu_cap, size_t* rapdu_len,
                          char* err, size_t err_cap) {
  mock_tx_t* mock = (mock_tx_t*)ctx;
  (void)capdu;
  (void)capdu_len;
  if (err != PCSC_FIDO_NULL && err_cap > 0u) {
    err[0] = '\0';
  }
  if (mock->response_index >= mock->response_count ||
      rapdu_cap < mock->response_lens[mock->response_index]) {
    return false;
  }
  if (pcsc_fido_span_ok(0u, TEST_LIT_5U, capdu_len) &&
      pcsc_fido_span_ok(1u, 1u, capdu_len) &&
      pcsc_fido_span_ok(TEST_LIT_4U, 1u, capdu_len) && capdu[0] == 0x00u &&
      capdu[1] == TEST_LIT_0XC0U) {
    mock->get_response_calls++;
    mock->last_get_response_le = capdu[TEST_LIT_4];
  }
  if (!pcsc_fido_copy_bytes(rapdu, rapdu_cap, 0u,
                            mock->responses[mock->response_index],
                            mock->response_lens[mock->response_index])) {
    return false;
  }
  *rapdu_len = mock->response_lens[mock->response_index];
  mock->response_index++;
  return true;
}

static void status_word_helpers(void) {
  const uint8_t rapdu[] = {0xAAu, 0xBBu, 0x61u, 0x10u};
  expect_true(
      pcsc_fido_apdu_status_word(rapdu, sizeof(rapdu)) == TEST_LIT_0X6110U,
      "status word parsed");
  expect_true(pcsc_fido_apdu_status_word(PCSC_FIDO_NULL, TEST_LIT_4U) == 0u,
              "PCSC_FIDO_NULL rapdu yields zero SW");
  expect_true(pcsc_fido_apdu_status_word(rapdu, 1u) == 0u,
              "short rapdu yields zero SW");
}

static void append_response_body(void) {
  uint8_t out[TEST_LIT_8];
  size_t out_len = 0u;
  char err[TEST_LIT_64];
  const uint8_t chunk[] = {0x01u, 0x02u, 0x61u, 0x05u};
  expect_true(
      pcsc_fido_apdu_append_response_body(out, sizeof(out), &out_len, chunk,
                                          sizeof(chunk), err, sizeof(err)),
      "append body succeeds");
  expect_true(
      out_len == TEST_LIT_2U && out[0] == 0x01u && out[1] == TEST_LIT_0X02U,
      "body bytes copied");
  expect_true(
      !pcsc_fido_apdu_append_response_body(out, TEST_LIT_2U, &out_len, chunk,
                                           sizeof(chunk), err, sizeof(err)),
      "append overflow rejected");
  expect_true(!pcsc_fido_apdu_append_response_body(out, sizeof(out), &out_len,
                                                   chunk, 1u, err, sizeof(err)),
              "missing SW rejected");
}

static void chains_get_response(void) {
  mock_tx_t mock;
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  const uint8_t chunk1[] = {0xAAu, 0x61u, 0x10u};
  const uint8_t chunk2[] = {0xBBu, 0x90u, 0x00u};
  uint8_t rapdu[TEST_LIT_16];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  pcsc_fido_zero_bytes(&mock, sizeof(mock));
  mock.responses[0] = chunk1;
  mock.response_lens[0] = sizeof(chunk1);
  mock.responses[1] = chunk2;
  mock.response_lens[1] = sizeof(chunk2);
  mock.response_count = TEST_LIT_2U;
  expect_true(pcsc_fido_apdu_transmit_chained(
                  &mock, mock_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "chained transmit succeeds");
  expect_true(rapdu_len == TEST_LIT_4U && rapdu[0] == TEST_LIT_0XAAU &&
                  rapdu[1] == TEST_LIT_0XBBU &&
                  rapdu[TEST_SOCKETPAIR_FDS] == TEST_LIT_0X90U &&
                  rapdu[TEST_LIT_3] == 0x00u,
              "chained response assembled");
  expect_true(mock.get_response_calls == 1u, "one GET RESPONSE issued");
}

static void chains_sw6100_with_zero_le_and_status_only_final(void) {
  mock_tx_t mock;
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  const uint8_t chunk1[] = {0x61u, 0x00u};
  const uint8_t chunk2[] = {0x90u, 0x00u};
  uint8_t rapdu[TEST_LIT_8];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  pcsc_fido_zero_bytes(&mock, sizeof(mock));
  mock.responses[0] = chunk1;
  mock.response_lens[0] = sizeof(chunk1);
  mock.responses[1] = chunk2;
  mock.response_lens[1] = sizeof(chunk2);
  mock.response_count = TEST_LIT_2U;
  expect_true(pcsc_fido_apdu_transmit_chained(
                  &mock, mock_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "SW=6100 chain succeeds");
  expect_true(
      mock.get_response_calls == 1u && mock.last_get_response_le == 0x00u,
      "SW=6100 requests Le=0");
  expect_true(rapdu_len == TEST_LIT_2U && rapdu[0] == TEST_LIT_0X90U &&
                  rapdu[1] == 0x00u,
              "status-only final response preserved");
}

static void rejects_invalid_arguments(void) {
  uint8_t rapdu[TEST_LIT_8];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  expect_true(!pcsc_fido_apdu_transmit_chained(
                  PCSC_FIDO_NULL, mock_transmit, PCSC_FIDO_NULL, 0u, rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "PCSC_FIDO_NULL transmit args rejected");
  expect_true(!pcsc_fido_apdu_append_response_body(
                  PCSC_FIDO_NULL, sizeof(rapdu), &rapdu_len, rapdu,
                  sizeof(rapdu), err, sizeof(err)),
              "append PCSC_FIDO_NULL out rejected");
}

static bool failing_transmit(void* ctx, const uint8_t* capdu, size_t capdu_len,
                             uint8_t* rapdu, size_t rapdu_cap,
                             size_t* rapdu_len, char* err, size_t err_cap) {
  (void)ctx;
  (void)capdu;
  (void)capdu_len;
  if (rapdu != PCSC_FIDO_NULL && rapdu_cap > 0u) {
    rapdu[0] ^= 0u;
  }
  if (rapdu_len != PCSC_FIDO_NULL) {
    *rapdu_len = 0u;
  }
  if (err != PCSC_FIDO_NULL && err_cap > 0u) {
    static const char FAIL_MSG[] = "mock transmit failed";
    if (!pcsc_fido_copy_bytes(err, err_cap, 0u, FAIL_MSG, sizeof(FAIL_MSG))) {
      err[0] = '\0';
    }
  }
  return false;
}

static void rejects_too_many_get_response_chunks(void) {
  mock_tx_t mock;
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  const uint8_t chunk[] = {0xAAu, 0x61u, 0xFFu};
  uint8_t rapdu[TEST_LIT_4];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  pcsc_fido_zero_bytes(&mock, sizeof(mock));
  mock.responses[0] = chunk;
  mock.response_lens[0] = sizeof(chunk);
  mock.responses[1] = chunk;
  mock.response_lens[1] = sizeof(chunk);
  mock.responses[TEST_SOCKETPAIR_FDS] = chunk;
  mock.response_lens[TEST_SOCKETPAIR_FDS] = sizeof(chunk);
  mock.response_count = TEST_LIT_3U;
  expect_true(!pcsc_fido_apdu_transmit_chained(
                  &mock, mock_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "too many GET RESPONSE chunks rejected");
  expect_true(strstr(err, "too many") != PCSC_FIDO_NULL,
              "too many chunks error message");
}

static void rejects_final_response_overflow(void) {
  mock_tx_t mock;
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  const uint8_t chunk[] = {0xAAu, 0xBBu, 0xCCu, 0x90u, 0x00u};
  uint8_t rapdu[TEST_LIT_3];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  pcsc_fido_zero_bytes(&mock, sizeof(mock));
  mock.responses[0] = chunk;
  mock.response_lens[0] = sizeof(chunk);
  mock.response_count = 1u;
  expect_true(!pcsc_fido_apdu_transmit_chained(
                  &mock, mock_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "final response overflow rejected");
  expect_true(strstr(err, "too large") != PCSC_FIDO_NULL,
              "overflow error message");
}

static void rejects_initial_transmit_failure(void) {
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  uint8_t rapdu[TEST_LIT_8];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  expect_true(!pcsc_fido_apdu_transmit_chained(
                  PCSC_FIDO_NULL, failing_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "initial transmit failure propagated");
}

static void rejects_final_response_missing_status_word(void) {
  mock_tx_t mock;
  uint8_t capdu[] = {TEST_LIT_0X80U, TEST_LIT_0X10U, 0x00u, 0x00u,
                     0x01u,          TEST_LIT_0X04U, 0x00u};
  const uint8_t chunk[] = {0xAAu};
  uint8_t rapdu[TEST_LIT_8];
  size_t rapdu_len = 0u;
  char err[TEST_LIT_64];
  pcsc_fido_zero_bytes(&mock, sizeof(mock));
  mock.responses[0] = chunk;
  mock.response_lens[0] = sizeof(chunk);
  mock.response_count = 1u;
  expect_true(!pcsc_fido_apdu_transmit_chained(
                  &mock, mock_transmit, capdu, sizeof(capdu), rapdu,
                  sizeof(rapdu), &rapdu_len, err, sizeof(err)),
              "final response without status word rejected");
  expect_true(strstr(err, "status word") != PCSC_FIDO_NULL,
              "missing status word error message");
}

int main(void) {
  status_word_helpers();
  append_response_body();
  chains_get_response();
  chains_sw6100_with_zero_le_and_status_only_final();
  rejects_invalid_arguments();
  rejects_too_many_get_response_chunks();
  rejects_final_response_overflow();
  rejects_initial_transmit_failure();
  rejects_final_response_missing_status_word();
  return failures == 0 ? 0 : 1;
}
