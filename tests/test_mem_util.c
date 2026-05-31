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

#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_err.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void checked_arithmetic(void) {
  size_t out = 0u;
  expect_true(pcsc_fido_try_add_size(10u, 5u, &out) && out == 15u, "add ok");
  expect_true(!pcsc_fido_try_add_size(SIZE_MAX, 1u, &out), "add overflow");
  expect_true(pcsc_fido_try_sub_size(10u, 3u, &out) && out == 7u, "sub ok");
  expect_true(!pcsc_fido_try_sub_size(2u, 3u, &out), "sub underflow");
  expect_true(pcsc_fido_span_ok(4u, 6u, 10u), "span ok");
  expect_true(!pcsc_fido_span_ok(8u, 4u, 10u), "span overflow");
}

static void copy_and_move(void) {
  uint8_t buf[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  size_t len = 16u;
  expect_true(pcsc_fido_copy_bytes(buf, sizeof(buf), 2u, "AB", 2u), "copy bytes");
  expect_true(buf[2] == 'A' && buf[3] == 'B', "copy contents");
  expect_true(pcsc_fido_copy_bytes(buf, sizeof(buf), 0u, nullptr, 0u),
              "zero copy permits null source");
  expect_true(!pcsc_fido_copy_bytes(buf, sizeof(buf), 15u, "X", 2u), "copy overflow");
  expect_true(pcsc_fido_move_bytes(buf, &len, 2u, 2u) && len == 14u, "move bytes");
  expect_true(buf[2] == 4u && buf[3] == 5u, "move shifted");
  expect_true(pcsc_fido_move_bytes(buf, &len, len - 2u, 2u) && len == 12u, "move tail bytes");
  expect_true(!pcsc_fido_move_bytes(buf, &len, 100u, 1u), "move invalid offset");
}

static void copy_cstr_and_format_err(void) {
  char dst[8];
  char err[32];
  expect_true(pcsc_fido_copy_cstr(dst, sizeof(dst), "ok"), "short cstr copy");
  expect_true(strcmp(dst, "ok") == 0, "cstr contents");
  expect_true(!pcsc_fido_copy_cstr(dst, sizeof(dst), "too-long-name"), "reject long cstr");
  expect_true(!pcsc_fido_copy_cstr_len(dst, sizeof(dst), "x", SIZE_MAX),
              "reject cstr length overflow");
  expect_true(pcsc_fido_format_err(err, sizeof(err), "%s", "short"), "short format fits");
  expect_true(strcmp(err, "short") == 0, "formatted message");
  expect_true(!pcsc_fido_format_err(err, 16, "%s", "this message does not fit"),
              "long format reports truncation");
  expect_true(strstr(err, "(truncated)") != nullptr, "truncation marker");
}

static void secure_clear_smoke(void) {
  uint8_t secret[8] = {0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x11u, 0x22u};
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
