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
#include "pcsc_fido/daemon_hid.h"

#include <stdio.h>
#include "pcsc_fido/pcsc_log.h"

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void packet_cid_and_cancel(void) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE] = {0};
  packet[0] = 0x01u;
  packet[1] = TEST_LIT_0X02U;
  packet[TEST_SOCKETPAIR_FDS] = TEST_LIT_0X03U;
  packet[TEST_LIT_3] = TEST_LIT_0X04U;
  packet[TEST_LIT_4] = (uint8_t)(TEST_LIT_0X80U | PCSC_FIDO_HID_CMD_CANCEL);
  expect_true(pcsc_fido_daemon_hid_packet_cid(packet) == TEST_CID,
              "CID decoded");
  expect_true(pcsc_fido_daemon_hid_is_cancel_packet(packet, TEST_CID),
              "cancel packet detected");
  expect_true(!pcsc_fido_daemon_hid_is_cancel_packet(packet, TEST_CID_OTHER),
              "cancel requires matching CID");
}

static void decode_init_header(void) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  const uint8_t payload[] = {0x04u};
  expect_true(
      pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_CBOR,
                                       payload, sizeof(payload), packet),
      "encode init packet");
  expect_true(pcsc_fido_daemon_hid_decode_init_header(packet, &cid, &cmd, &len),
              "daemon init decode succeeds");
  expect_true(cid == TEST_CID && cmd == PCSC_FIDO_HID_CMD_CBOR && len == 1u,
              "init header fields");
  packet[TEST_LIT_4] = 0u;
  expect_true(
      !pcsc_fido_daemon_hid_decode_init_header(packet, &cid, &cmd, &len),
      "continuation packet rejected by init decoder");
}

static void null_argument_guards(void) {
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  expect_true(!pcsc_fido_daemon_hid_is_cancel_packet(PCSC_FIDO_NULL, 0u),
              "PCSC_FIDO_NULL cancel packet");
  expect_true(!pcsc_fido_daemon_hid_decode_init_header(PCSC_FIDO_NULL, &cid,
                                                       &cmd, &len),
              "PCSC_FIDO_NULL init header packet");
}

int main(void) {
  packet_cid_and_cancel();
  decode_init_header();
  null_argument_guards();
  return failures == 0 ? 0 : 1;
}
