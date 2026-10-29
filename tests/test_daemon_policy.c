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
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_policy.h"

#include <stdio.h>
#include <string.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  TEST_LIT_0X11 = 0x11,
  TEST_LIT_0X20U = 0x20u,
  TEST_LIT_0X22 = 0x22,
  TEST_LIT_0X33 = 0x33,
  TEST_LIT_0X58U = 0x58u,
  TEST_LIT_0X62U = 0x62u,
  TEST_LIT_0X64U = 0x64u,
  TEST_LIT_0X69U = 0x69u,
  TEST_LIT_0XA1U = 0xA1u,
  TEST_LIT_0XA2U = 0xA2u,
  TEST_LIT_37U = 37u,
  TEST_LIT_38U = 38u,
  TEST_LIT_39U = 39u,
  TEST_LIT_40U = 40u,
};

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void detects_empty_client_data_hash(void) {
  // getAssertion (0x02) + CBOR map{1}: key 0x02 -> byte string(32) =
  // SHA-256("").
  uint8_t empty_probe[TEST_LIT_5U + TEST_LIT_32U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA1U, TEST_LIT_0X02U, TEST_LIT_0X58U,
      TEST_LIT_0X20U};
  uint8_t real_login[TEST_LIT_5U + TEST_LIT_32U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA1U, TEST_LIT_0X02U, TEST_LIT_0X58U,
      TEST_LIT_0X20U};
  // clientDataHash not first: map{2} key 0x01 -> "id", key 0x02 -> empty hash.
  uint8_t empty_second[TEST_LIT_9U + TEST_LIT_32U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA2U, 0x01u,
      TEST_LIT_0X62U, TEST_LIT_0X69U, TEST_LIT_0X64U,
      TEST_LIT_0X02U, TEST_LIT_0X58U, TEST_LIT_0X20U};
  // Real (non-empty) clientDataHash, but the empty hash bytes appear under a
  // later key (0x03). The structured parser must NOT be fooled by this.
  uint8_t empty_in_other_field[TEST_LIT_9U + TEST_LIT_64U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA2U, TEST_LIT_0X02U, TEST_LIT_0X58U,
      TEST_LIT_0X20U};
  (void)pcsc_fido_copy_bytes(empty_probe + TEST_LIT_5U,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH), 0u,
                             PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  pcsc_fido_fill_bytes(real_login + TEST_LIT_5U, TEST_LIT_32U,
                       (uint8_t)TEST_LIT_0X11);
  (void)pcsc_fido_copy_bytes(empty_second + TEST_LIT_9U,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH), 0u,
                             PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  pcsc_fido_fill_bytes(empty_in_other_field + TEST_LIT_5U, TEST_LIT_32U,
                       (uint8_t)TEST_LIT_0X22);
  empty_in_other_field[TEST_LIT_37U] = TEST_LIT_0X03U;
  empty_in_other_field[TEST_LIT_38U] = TEST_LIT_0X58U;
  empty_in_other_field[TEST_LIT_39U] = TEST_LIT_0X20U;
  (void)pcsc_fido_copy_bytes(empty_in_other_field + TEST_LIT_40U,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH), 0u,
                             PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));

  expect_true(pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  empty_probe, sizeof(empty_probe)),
              "empty clientDataHash detected");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  real_login, sizeof(real_login)),
              "non-empty clientDataHash not flagged");
  expect_true(pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  empty_second, sizeof(empty_second)),
              "empty clientDataHash detected when not first key");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  empty_in_other_field, sizeof(empty_in_other_field)),
              "empty hash in another field is not a false positive");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  empty_probe, TEST_LIT_8U),
              "truncated payload rejected");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                  PCSC_FIDO_NULL, TEST_LIT_4U),
              "PCSC_FIDO_NULL payload rejected");
}

static void classifies_terminal_requests(void) {
  const uint8_t make_cred[] = {0x01u, 0xA0u};
  uint8_t preflight[TEST_LIT_5U + TEST_LIT_32U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA1U, TEST_LIT_0X02U, TEST_LIT_0X58U,
      TEST_LIT_0X20U};
  uint8_t real_assertion[TEST_LIT_5U + TEST_LIT_32U] = {
      TEST_LIT_0X02U, TEST_LIT_0XA1U, TEST_LIT_0X02U, TEST_LIT_0X58U,
      TEST_LIT_0X20U};
  (void)pcsc_fido_copy_bytes(preflight + TEST_LIT_5U,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH), 0u,
                             PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
                             sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  pcsc_fido_fill_bytes(real_assertion + TEST_LIT_5U, TEST_LIT_32U,
                       (uint8_t)TEST_LIT_0X33);
  expect_true(pcsc_fido_daemon_is_terminal_webauthn_request(
                  PCSC_FIDO_HID_CMD_CBOR, make_cred, sizeof(make_cred)),
              "makeCredential is terminal");
  expect_true(!pcsc_fido_daemon_is_terminal_webauthn_request(
                  PCSC_FIDO_HID_CMD_CBOR, preflight, sizeof(preflight)),
              "preflight getAssertion is not terminal");
  expect_true(
      pcsc_fido_daemon_is_terminal_webauthn_request(
          PCSC_FIDO_HID_CMD_CBOR, real_assertion, sizeof(real_assertion)),
      "real getAssertion is terminal");
  expect_true(!pcsc_fido_daemon_is_terminal_webauthn_request(
                  PCSC_FIDO_HID_CMD_PING, make_cred, sizeof(make_cred)),
              "non-CBOR cmd is not terminal");
}

static void classifies_get_assertion(void) {
  const uint8_t get_assertion[] = {0x02u, 0xA0u};
  const uint8_t make_cred[] = {0x01u, 0xA0u};
  expect_true(pcsc_fido_daemon_is_get_assertion(
                  PCSC_FIDO_HID_CMD_CBOR, get_assertion, sizeof(get_assertion)),
              "getAssertion recognized");
  expect_true(!pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR,
                                                 make_cred, sizeof(make_cred)),
              "makeCredential is not getAssertion");
  expect_true(!pcsc_fido_daemon_is_get_assertion(
                  PCSC_FIDO_HID_CMD_MSG, get_assertion, sizeof(get_assertion)),
              "non-CBOR command is not getAssertion");
  expect_true(!pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR,
                                                 PCSC_FIDO_NULL, 1u),
              "PCSC_FIDO_NULL payload rejected");
  expect_true(!pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR,
                                                 get_assertion, 0u),
              "zero-length payload rejected");
}

static void classifies_get_next_assertion(void) {
  const uint8_t get_next[] = {0x08u};
  const uint8_t get_assertion[] = {0x02u, 0xA0u};
  expect_true(pcsc_fido_daemon_is_get_next_assertion(
                  PCSC_FIDO_HID_CMD_CBOR, get_next, sizeof(get_next)),
              "getNextAssertion recognized");
  expect_true(!pcsc_fido_daemon_is_get_next_assertion(
                  PCSC_FIDO_HID_CMD_CBOR, get_assertion, sizeof(get_assertion)),
              "getAssertion is not getNextAssertion");
  expect_true(!pcsc_fido_daemon_is_get_next_assertion(
                  PCSC_FIDO_HID_CMD_MSG, get_next, sizeof(get_next)),
              "non-CBOR command is not getNextAssertion");
  expect_true(!pcsc_fido_daemon_is_get_next_assertion(PCSC_FIDO_HID_CMD_CBOR,
                                                      PCSC_FIDO_NULL, 1u),
              "PCSC_FIDO_NULL payload rejected");
  expect_true(!pcsc_fido_daemon_is_get_next_assertion(PCSC_FIDO_HID_CMD_CBOR,
                                                      get_next, 0u),
              "zero-length payload rejected");
}

static void reads_number_of_credentials(void) {
  // OK, map{2}: 0x01 -> {"id": h'AABB'}, 0x05 -> 3.
  const uint8_t three[] = {0x00u, 0xA2u, 0x01u, 0xA1u, 0x62u, 0x69u,
                           0x64u, 0x42u, 0xAAu, 0xBBu, 0x05u, 0x03u};
  // OK, map{1}: 0x05 -> 32 (one-byte argument).
  const uint8_t thirty_two[] = {0x00u, 0xA1u, 0x05u, 0x18u, 0x20u};
  // OK, map{1}: 0x01 -> h'AA'; no numberOfCredentials.
  const uint8_t absent[] = {0x00u, 0xA1u, 0x01u, 0x41u, 0xAAu};
  // CTAP2_ERR_NO_CREDENTIALS (0x2E), then a map that would say 3.
  const uint8_t error_status[] = {0x2Eu, 0xA1u, 0x05u, 0x03u};
  // map{2} cut off inside the first value, before key 0x05.
  const uint8_t truncated[] = {0x00u, 0xA2u, 0x01u, 0x42u, 0xAAu};
  // numberOfCredentials as a text string.
  const uint8_t not_uint[] = {0x00u, 0xA1u, 0x05u, 0x61u, 0x33u};
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  three, sizeof(three)) == TEST_LIT_3U,
              "numberOfCredentials read after a nested map");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  thirty_two, sizeof(thirty_two)) == TEST_LIT_32U,
              "numberOfCredentials with a one-byte argument");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  absent, sizeof(absent)) == 0u,
              "absent numberOfCredentials reads as 0");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  error_status, sizeof(error_status)) == 0u,
              "error status reads as 0");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  truncated, sizeof(truncated)) == 0u,
              "truncated response reads as 0");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  not_uint, sizeof(not_uint)) == 0u,
              "non-integer numberOfCredentials reads as 0");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(three, 1u) == 0u,
              "status byte alone reads as 0");
  expect_true(pcsc_fido_daemon_get_assertion_credential_count(
                  PCSC_FIDO_NULL, sizeof(three)) == 0u,
              "PCSC_FIDO_NULL response reads as 0");
}

int main(void) {
  detects_empty_client_data_hash();
  classifies_terminal_requests();
  classifies_get_assertion();
  classifies_get_next_assertion();
  reads_number_of_credentials();
  return failures == 0 ? 0 : 1;
}
