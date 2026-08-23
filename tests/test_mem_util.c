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
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_err.h"

#include <stdio.h>
#include <string.h>
#include "pcsc_fido/pcsc_log.h"

enum {
  TEST_LIT_0X11U = 0x11u,
  TEST_LIT_0X22U = 0x22u,
  TEST_LIT_0XCCU = 0xCCu,
  TEST_LIT_0XDDU = 0xDDu,
  TEST_LIT_0XEEU = 0xEEu,
  TEST_LIT_10 = 10,
  TEST_LIT_100U = 100u,
  TEST_LIT_10U = 10u,
  TEST_LIT_11 = 11,
  TEST_LIT_12 = 12,
  TEST_LIT_12U = 12u,
  TEST_LIT_13 = 13,
  TEST_LIT_14 = 14,
  TEST_LIT_14U = 14u,
  TEST_LIT_15U = 15u,
  TEST_LIT_6U = 6u,
  TEST_LIT_7U = 7u,
};

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void checked_arithmetic(void) {
  size_t out = 0u;
  expect_true(pcsc_fido_try_add_size(TEST_LIT_10U, TEST_LIT_5U, &out) &&
                  out == TEST_LIT_15U,
              "add ok");
  expect_true(!pcsc_fido_try_add_size(SIZE_MAX, 1u, &out), "add overflow");
  expect_true(pcsc_fido_try_sub_size(TEST_LIT_10U, TEST_LIT_3U, &out) &&
                  out == TEST_LIT_7U,
              "sub ok");
  expect_true(!pcsc_fido_try_sub_size(TEST_LIT_2U, TEST_LIT_3U, &out),
              "sub underflow");
  expect_true(pcsc_fido_span_ok(TEST_LIT_4U, TEST_LIT_6U, TEST_LIT_10U),
              "span ok");
  expect_true(!pcsc_fido_span_ok(TEST_LIT_8U, TEST_LIT_4U, TEST_LIT_10U),
              "span overflow");
}

static void copy_and_move(void) {
  uint8_t buf[TEST_LIT_16] = {
      0,           1,           TEST_SOCKETPAIR_FDS, TEST_LIT_3,
      TEST_LIT_4,  TEST_LIT_5,  TEST_LIT_6,          TEST_LIT_7,
      TEST_LIT_8,  TEST_LIT_9,  TEST_LIT_10,         TEST_LIT_11,
      TEST_LIT_12, TEST_LIT_13, TEST_LIT_14,         TEST_LIT_15};
  size_t len = TEST_LIT_16U;
  expect_true(
      pcsc_fido_copy_bytes(buf, sizeof(buf), TEST_LIT_2U, "AB", TEST_LIT_2U),
      "copy bytes");
  expect_true(buf[TEST_SOCKETPAIR_FDS] == 'A' && buf[TEST_LIT_3] == 'B',
              "copy contents");
  expect_true(pcsc_fido_copy_bytes(buf, sizeof(buf), 0u, PCSC_FIDO_NULL, 0u),
              "zero copy permits null source");
  expect_true(
      !pcsc_fido_copy_bytes(buf, sizeof(buf), TEST_LIT_15U, "X", TEST_LIT_2U),
      "copy overflow");
  expect_true(pcsc_fido_move_bytes(buf, &len, TEST_LIT_2U, TEST_LIT_2U) &&
                  len == TEST_LIT_14U,
              "move bytes");
  expect_true(
      buf[TEST_SOCKETPAIR_FDS] == TEST_LIT_4U && buf[TEST_LIT_3] == TEST_LIT_5U,
      "move shifted");
  expect_true(pcsc_fido_move_bytes(buf, &len, len - TEST_LIT_2U, TEST_LIT_2U) &&
                  len == TEST_LIT_12U,
              "move tail bytes");
  expect_true(!pcsc_fido_move_bytes(buf, &len, TEST_LIT_100U, 1u),
              "move invalid offset");
}

static void copy_cstr_and_format_err(void) {
  char dst[TEST_LIT_8];
  char err[TEST_LIT_32];
  expect_true(pcsc_fido_copy_cstr(dst, sizeof(dst), "ok"), "short cstr copy");
  expect_true(strcmp(dst, "ok") == 0, "cstr contents");
  expect_true(!pcsc_fido_copy_cstr(dst, sizeof(dst), "too-long-name"),
              "reject long cstr");
  expect_true(!pcsc_fido_copy_cstr_len(dst, sizeof(dst), "x", SIZE_MAX),
              "reject cstr length overflow");
  expect_true(pcsc_fido_format_err(err, sizeof(err), "%s", "short"),
              "short format fits");
  expect_true(strcmp(err, "short") == 0, "formatted message");
  expect_true(!pcsc_fido_format_err(err, TEST_LIT_16, "%s",
                                    "this message does not fit"),
              "long format reports truncation");
  expect_true(strstr(err, "(truncated)") != PCSC_FIDO_NULL,
              "truncation marker");
}

static void secure_clear_smoke(void) {
  uint8_t secret[TEST_LIT_8] = {TEST_LIT_0XAAU, TEST_LIT_0XBBU, TEST_LIT_0XCCU,
                                TEST_LIT_0XDDU, TEST_LIT_0XEEU, TEST_LIT_0XFFU,
                                TEST_LIT_0X11U, TEST_LIT_0X22U};
  pcsc_fido_secure_clear(secret, sizeof(secret));
  for (size_t i = 0u; i < sizeof(secret); i++) {
    expect_true(secret[i] == 0u, "secure clear zeroed byte");
  }
}

int main(void) {
  checked_arithmetic();
  copy_and_move();
  copy_cstr_and_format_err();
  secure_clear_smoke();
  return failures == 0 ? 0 : 1;
}
