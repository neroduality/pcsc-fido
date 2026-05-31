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
#include "pcsc_fido/request_assembly.h"
#include "pcsc_fido/uhid_transport.h"

#include <stdio.h>
#include <string.h>

extern uint32_t g_stub_last_error_cid;
extern uint8_t g_stub_last_error_code;
extern int g_stub_error_calls;

static int failures;
static int handled_calls;
static uint32_t handled_cid;
static uint8_t handled_cmd;
static size_t handled_len;
static uint8_t handled_payload_head;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void handle_request(const void *ctx, uint32_t request_cid, uint8_t cmd,
                           const uint8_t *payload, size_t payload_len) {
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
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, payload,
                                               sizeof(payload), packet),
              "encode init packet");
  expect_true(
    pcsc_fido_daemon_request_assembler_feed(-1, &pending, packet, handle_request, nullptr),
    "single packet feed succeeds");
  expect_true(handled_calls == 1u && handled_cid == 0x01020304u &&
                handled_cmd == PCSC_FIDO_HID_CMD_CBOR && handled_len == 1u,
              "single packet request completed");
  expect_true(handled_payload_head == 0x04u, "single packet payload preserved");
}

static void multi_packet_request(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t cont[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t request[80];
  handled_calls = 0;
  memset(request, 0xA5, sizeof(request));
  request[0] = 0x01u;
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, request,
                                               PCSC_FIDO_HID_INIT_PAYLOAD_MAX, init),
              "encode large init packet");
  init[5] = 0u;
  init[6] = sizeof(request);
  expect_true(pcsc_fido_daemon_request_assembler_feed(-1, &pending, init, handle_request, nullptr),
              "init packet accepted");
  expect_true(pending.active, "large request stays active");
  expect_true(
    pcsc_fido_hid_encode_cont_packet(0x01020304u, 0u, request + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                                     sizeof(request) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX, cont),
    "encode continuation packet");
  expect_true(pcsc_fido_daemon_request_assembler_feed(-1, &pending, cont, handle_request, nullptr),
              "continuation accepted");
  expect_true(handled_calls == 1u && handled_len == sizeof(request),
              "multi-packet request completed");
  expect_true(handled_payload_head == 0x01u, "multi-packet payload preserved");
}

static void rejects_bad_sequence(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t bad_cont[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t request[80];
  g_stub_error_calls = 0;
  memset(request, 0xA5, sizeof(request));
  pcsc_fido_daemon_pending_request_reset(&pending);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, request,
                                               PCSC_FIDO_HID_INIT_PAYLOAD_MAX, init),
              "encode init packet");
  init[5] = 0u;
  init[6] = sizeof(request);
  expect_true(pcsc_fido_daemon_request_assembler_feed(-1, &pending, init, handle_request, nullptr),
              "init packet accepted");
  expect_true(
    pcsc_fido_hid_encode_cont_packet(0x01020304u, 1u, request + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                                     sizeof(request) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX, bad_cont),
    "encode bad continuation");
  expect_true(
    pcsc_fido_daemon_request_assembler_feed(-1, &pending, bad_cont, handle_request, nullptr),
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
  memset(init, 0, sizeof(init));
  init[0] = 0x01u;
  init[1] = 0x02u;
  init[2] = 0x03u;
  init[3] = 0x04u;
  init[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_PING);
  init[5] = (uint8_t)(((PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 1u) >> 8u) & 0xFFu);
  init[6] = (uint8_t)((PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 1u) & 0xFFu);
  expect_true(pcsc_fido_daemon_request_assembler_feed(-1, &pending, init, handle_request, nullptr),
              "oversized expected handled");
  expect_true(g_stub_error_calls == 1u &&
                g_stub_last_error_code == PCSC_FIDO_DAEMON_ERR_INVALID_LEN,
              "oversized expected returns INVALID_LEN");
  expect_true(handled_calls == 0u, "oversized expected does not invoke handler");
}

static void rejects_unframable_expected(void) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t init[PCSC_FIDO_HID_PACKET_SIZE];
  const size_t unframable = PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u;
  g_stub_error_calls = 0;
  handled_calls = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  memset(init, 0, sizeof(init));
  init[0] = 0x01u;
  init[1] = 0x02u;
  init[2] = 0x03u;
  init[3] = 0x04u;
  init[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_CBOR);
  init[5] = (uint8_t)((unframable >> 8u) & 0xFFu);
  init[6] = (uint8_t)(unframable & 0xFFu);
  expect_true(pcsc_fido_daemon_request_assembler_feed(-1, &pending, init, handle_request, nullptr),
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
  expect_true(
    !pcsc_fido_daemon_request_assembler_feed(-1, nullptr, packet, handle_request, nullptr),
    "nullptr pending rejected");
  expect_true(
    !pcsc_fido_daemon_request_assembler_feed(-1, &pending, nullptr, handle_request, nullptr),
    "nullptr packet rejected");
  expect_true(!pcsc_fido_daemon_request_assembler_feed(-1, &pending, packet, nullptr, nullptr),
              "nullptr handler rejected");
}

static void reset_pending_null_safe(void) {
  pcsc_fido_daemon_pending_request_reset(nullptr);
}

int main(void) {
  single_packet_request();
  multi_packet_request();
  rejects_bad_sequence();
  rejects_oversized_expected();
  rejects_unframable_expected();
  rejects_null_arguments();
  reset_pending_null_safe();
  return failures == 0 ? 0 : 1;
}
