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
#include "pcsc_fido/request_assembly.h"
#include "pcsc_fido/uhid_transport.h"

#include <stdio.h>
#include <string.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

extern uint32_t g_stub_last_error_cid;
extern uint8_t g_stub_last_error_code;
extern int g_stub_error_calls;

static int failures;
static int handled_calls;
static uint32_t handled_cid;
static uint8_t handled_cmd;
static size_t handled_len;
static uint8_t handled_payload_head;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void handle_request(const void* ctx, uint32_t request_cid, uint8_t cmd,
                           const uint8_t* payload, size_t payload_len) {
  (void)ctx;
  (void)payload;
  handled_calls++;
  handled_cid = request_cid;
  handled_cmd = cmd;
  handled_len = payload_len;
  handled_payload_head = (payload_len > 0u) ? payload[0] : 0u;
}

static void single_packet_request(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t payload[] = {0x04u};
  handled_calls = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(
      pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_CBOR,
                                       payload, sizeof(payload), packet),
      "encode init packet");
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, packet, handle_request, PCSC_FIDO_NULL),
              "single packet feed succeeds");
  expect_true(handled_calls == 1u && handled_cid == TEST_CID &&
                  handled_cmd == PCSC_FIDO_HID_CMD_CBOR && handled_len == 1u,
              "single packet request completed");
  expect_true(handled_payload_head == TEST_LIT_0X04U,
              "single packet payload preserved");
}

static void multi_packet_request(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t cont[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t request[TEST_LIT_80];
  handled_calls = 0;
  pcsc_fido_fill_bytes(request, sizeof(request), (uint8_t)TEST_LIT_0XA5);
  request[0] = 0x01u;
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, request,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, init),
              "encode large init packet");
  init[TEST_LIT_5] = 0u;
  init[TEST_LIT_6] = sizeof(request);
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, init, handle_request, PCSC_FIDO_NULL),
              "init packet accepted");
  expect_true(pending.active, "large request stays active");
  expect_true(pcsc_fido_hid_encode_cont_packet(
                  TEST_CID, 0u, request + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  sizeof(request) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX, cont),
              "encode continuation packet");
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, cont, handle_request, PCSC_FIDO_NULL),
              "continuation accepted");
  expect_true(handled_calls == 1u && handled_len == sizeof(request),
              "multi-packet request completed");
  expect_true(handled_payload_head == 0x01u, "multi-packet payload preserved");
}

static void rejects_bad_sequence(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t bad_cont[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t request[TEST_LIT_80];
  g_stub_error_calls = 0;
  pcsc_fido_fill_bytes(request, sizeof(request), (uint8_t)TEST_LIT_0XA5);
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, request,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, init),
              "encode init packet");
  init[TEST_LIT_5] = 0u;
  init[TEST_LIT_6] = sizeof(request);
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, init, handle_request, PCSC_FIDO_NULL),
              "init packet accepted");
  expect_true(pcsc_fido_hid_encode_cont_packet(
                  TEST_CID, 1u, request + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  sizeof(request) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX, bad_cont),
              "encode bad continuation");
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, bad_cont, handle_request, PCSC_FIDO_NULL),
              "bad continuation handled");
  expect_true(g_stub_error_calls == 1u &&
                  g_stub_last_error_code == PCSC_FIDO_DAEMON_ERR_INVALID_SEQ,
              "invalid sequence returns error");
}

static void rejects_oversized_expected(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  g_stub_error_calls = 0;
  handled_calls = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  pcsc_fido_zero_bytes(init, sizeof(init));
  init[0] = 0x01u;
  init[1] = TEST_LIT_0X02U;
  init[TEST_SOCKETPAIR_FDS] = TEST_LIT_0X03U;
  init[TEST_LIT_3] = TEST_LIT_0X04U;
  init[TEST_LIT_4] = (uint8_t)(TEST_LIT_0X80U | PCSC_FIDO_HID_CMD_PING);
  init[TEST_LIT_5] =
      (uint8_t)(((PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 1u) >> TEST_LIT_8U) &
                TEST_LIT_0XFFU);
  init[TEST_LIT_6] =
      (uint8_t)((PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 1u) & TEST_LIT_0XFFU);
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, init, handle_request, PCSC_FIDO_NULL),
              "oversized expected handled");
  expect_true(g_stub_error_calls == 1u &&
                  g_stub_last_error_code == PCSC_FIDO_DAEMON_ERR_INVALID_LEN,
              "oversized expected returns INVALID_LEN");
  expect_true(handled_calls == 0u,
              "oversized expected does not invoke handler");
}

static void rejects_unframable_expected(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  const size_t unframable = PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u;
  g_stub_error_calls = 0;
  handled_calls = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  pcsc_fido_zero_bytes(init, sizeof(init));
  init[0] = 0x01u;
  init[1] = TEST_LIT_0X02U;
  init[TEST_SOCKETPAIR_FDS] = TEST_LIT_0X03U;
  init[TEST_LIT_3] = TEST_LIT_0X04U;
  init[TEST_LIT_4] = (uint8_t)(TEST_LIT_0X80U | PCSC_FIDO_HID_CMD_CBOR);
  init[TEST_LIT_5] = (uint8_t)((unframable >> TEST_LIT_8U) & TEST_LIT_0XFFU);
  init[TEST_LIT_6] = (uint8_t)(unframable & TEST_LIT_0XFFU);
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, init, handle_request, PCSC_FIDO_NULL),
              "unframable expected handled");
  expect_true(g_stub_error_calls == 1u &&
                  g_stub_last_error_code == PCSC_FIDO_DAEMON_ERR_INVALID_LEN,
              "unframable expected returns INVALID_LEN");
  expect_true(handled_calls == 0u && !pending.active,
              "unframable expected does not invoke handler");
}

static void rejects_null_arguments(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(!pcsc_fido_daemon_request_assembler_feed(
                  -1, PCSC_FIDO_NULL, packet, handle_request, PCSC_FIDO_NULL),
              "PCSC_FIDO_NULL pending rejected");
  expect_true(!pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, PCSC_FIDO_NULL, handle_request, PCSC_FIDO_NULL),
              "PCSC_FIDO_NULL packet rejected");
  expect_true(!pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, packet, PCSC_FIDO_NULL, PCSC_FIDO_NULL),
              "PCSC_FIDO_NULL handler rejected");
}

static void reset_pending_null_safe(void) {
  pcsc_fido_daemon_pending_request_reset(PCSC_FIDO_NULL);
}

// Regression: pcsc_fido_daemon_pending_request_reset must wipe the entire
// payload buffer (it holds plaintext CTAP requests: clientDataHash and
// authenticatorClientPIN material). Guards against the reset being weakened
// back to a partial/no-op clear.
static void reset_wipes_full_payload(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t residue = 0u;
  size_t i;
  pcsc_fido_fill_bytes(pending.payload, sizeof(pending.payload),
                       (uint8_t)TEST_LIT_0XA5);
  pending.active = true;
  pending.cid = TEST_CID;
  pcsc_fido_daemon_pending_request_reset(&pending);
  for (i = 0u; i < sizeof(pending.payload); i++) {
    residue |= pending.payload[i];
  }
  expect_true(residue == 0u, "reset wipes entire pending payload");
  expect_true(!pending.active && pending.cid == 0u,
              "reset clears pending state");
}

// Regression: once a request is fully assembled and dispatched, the plaintext
// payload must be scrubbed from the reassembly buffer so it does not linger
// between operations. Guards the secure-clear added to complete_request.
static void completed_request_scrubs_pending(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t payload[] = {0x04u};
  uint8_t residue = 0u;
  size_t i;
  handled_calls = 0;
  handled_payload_head = 0u;
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(
      pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_CBOR,
                                       payload, sizeof(payload), packet),
      "encode init packet for scrub test");
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, packet, handle_request, PCSC_FIDO_NULL),
              "completed request feed succeeds");
  expect_true(handled_calls == 1u && handled_payload_head == TEST_LIT_0X04U,
              "handler observed payload before scrub");
  for (i = 0u; i < sizeof(pending.payload); i++) {
    residue |= pending.payload[i];
  }
  expect_true(residue == 0u,
              "completed request scrubs pending payload after dispatch");
  expect_true(!pending.active && pending.cid == 0u,
              "completed request clears pending state");
}

// Regression: a partially assembled (mid-transfer) request must be wiped when
// the daemon resets/shuts down (tap_arm.c and daemon_uhid_loop.c out: paths).
// Guards against partial CTAP plaintext surviving a shutdown.
static void partial_request_reset_wipes_payload(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t request[TEST_LIT_80];
  uint8_t residue = 0u;
  size_t i;
  handled_calls = 0;
  pcsc_fido_fill_bytes(request, sizeof(request), (uint8_t)TEST_LIT_0XA5);
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, request,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, init),
              "encode partial init packet");
  init[TEST_LIT_5] = 0u;
  init[TEST_LIT_6] = sizeof(request);
  expect_true(pcsc_fido_daemon_request_assembler_feed(
                  -1, &pending, init, handle_request, PCSC_FIDO_NULL),
              "partial init accepted");
  expect_true(pending.active && handled_calls == 0u,
              "partial request stays active, not dispatched");
  pcsc_fido_daemon_pending_request_reset(&pending);
  for (i = 0u; i < sizeof(pending.payload); i++) {
    residue |= pending.payload[i];
  }
  expect_true(residue == 0u,
              "shutdown reset wipes partially assembled payload");
  expect_true(!pending.active, "shutdown reset clears active flag");
}

int main(void) {
  single_packet_request();
  multi_packet_request();
  rejects_bad_sequence();
  rejects_oversized_expected();
  rejects_unframable_expected();
  rejects_null_arguments();
  reset_pending_null_safe();
  reset_wipes_full_payload();
  completed_request_scrubs_pending();
  partial_request_reset_wipes_payload();
  return failures == 0 ? 0 : 1;
}
