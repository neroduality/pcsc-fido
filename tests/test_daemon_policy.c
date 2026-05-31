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

#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_policy.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void detects_empty_client_data_hash(void) {
  // getAssertion (0x02) + CBOR map{1}: key 0x02 -> byte string(32) = SHA-256("").
  uint8_t empty_probe[5u + 32u] = {0x02u, 0xA1u, 0x02u, 0x58u, 0x20u};
  uint8_t real_login[5u + 32u] = {0x02u, 0xA1u, 0x02u, 0x58u, 0x20u};
  // clientDataHash not first: map{2} key 0x01 -> "id", key 0x02 -> empty hash.
  uint8_t empty_second[9u + 32u] = {0x02u, 0xA2u, 0x01u, 0x62u, 0x69u, 0x64u, 0x02u, 0x58u, 0x20u};
  // Real (non-empty) clientDataHash, but the empty hash bytes appear under a
  // later key (0x03). The structured parser must NOT be fooled by this.
  uint8_t empty_in_other_field[9u + 64u] = {0x02u, 0xA2u, 0x02u, 0x58u, 0x20u};
  memcpy(empty_probe + 5u, PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
         sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  memset(real_login + 5u, 0x11, 32u);
  memcpy(empty_second + 9u, PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
         sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  memset(empty_in_other_field + 5u, 0x22, 32u);
  empty_in_other_field[37u] = 0x03u;
  empty_in_other_field[38u] = 0x58u;
  empty_in_other_field[39u] = 0x20u;
  memcpy(empty_in_other_field + 40u, PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
         sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));

  expect_true(
    pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(empty_probe, sizeof(empty_probe)),
    "empty clientDataHash detected");
  expect_true(
    !pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(real_login, sizeof(real_login)),
    "non-empty clientDataHash not flagged");
  expect_true(
    pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(empty_second, sizeof(empty_second)),
    "empty clientDataHash detected when not first key");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
                empty_in_other_field, sizeof(empty_in_other_field)),
              "empty hash in another field is not a false positive");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(empty_probe, 8u),
              "truncated payload rejected");
  expect_true(!pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(nullptr, 4u),
              "nullptr payload rejected");
}

static void classifies_terminal_requests(void) {
  const uint8_t make_cred[] = {0x01u, 0xA0u};
  uint8_t preflight[5u + 32u] = {0x02u, 0xA1u, 0x02u, 0x58u, 0x20u};
  uint8_t real_assertion[5u + 32u] = {0x02u, 0xA1u, 0x02u, 0x58u, 0x20u};
  memcpy(preflight + 5u, PCSC_FIDO_EMPTY_CLIENT_DATA_HASH,
         sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH));
  memset(real_assertion + 5u, 0x33, 32u);
  expect_true(pcsc_fido_daemon_is_terminal_webauthn_request(PCSC_FIDO_HID_CMD_CBOR, make_cred,
                                                            sizeof(make_cred)),
              "makeCredential is terminal");
  expect_true(!pcsc_fido_daemon_is_terminal_webauthn_request(PCSC_FIDO_HID_CMD_CBOR, preflight,
                                                             sizeof(preflight)),
              "preflight getAssertion is not terminal");
  expect_true(pcsc_fido_daemon_is_terminal_webauthn_request(PCSC_FIDO_HID_CMD_CBOR, real_assertion,
                                                            sizeof(real_assertion)),
              "real getAssertion is terminal");
  expect_true(!pcsc_fido_daemon_is_terminal_webauthn_request(PCSC_FIDO_HID_CMD_PING, make_cred,
                                                             sizeof(make_cred)),
              "non-CBOR cmd is not terminal");
}

static void classifies_get_assertion(void) {
  const uint8_t get_assertion[] = {0x02u, 0xA0u};
  const uint8_t make_cred[] = {0x01u, 0xA0u};
  expect_true(
    pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR, get_assertion, sizeof(get_assertion)),
    "getAssertion recognized");
  expect_true(
    !pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR, make_cred, sizeof(make_cred)),
    "makeCredential is not getAssertion");
  expect_true(
    !pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_MSG, get_assertion, sizeof(get_assertion)),
    "non-CBOR command is not getAssertion");
  expect_true(!pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR, nullptr, 1u),
              "nullptr payload rejected");
  expect_true(!pcsc_fido_daemon_is_get_assertion(PCSC_FIDO_HID_CMD_CBOR, get_assertion, 0u),
              "zero-length payload rejected");
}

int main(void) {
  detects_empty_client_data_hash();
  classifies_terminal_requests();
  classifies_get_assertion();
  return failures == 0 ? 0 : 1;
}
