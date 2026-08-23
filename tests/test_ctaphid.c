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

#include <stdio.h>
#include <string.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  TEST_LIT_0X11223344U = 0x11223344u,
  TEST_LIT_0X7FU = 0x7Fu,
  TEST_LIT_100 = 100,
  TEST_LIT_1234 = 1234,
  TEST_LIT_17 = 17,
  TEST_LIT_17U = 17u,
  TEST_LIT_18 = 18,
  TEST_LIT_250 = 250,
  TEST_LIT_96 = 96,
};

typedef struct {
  uint8_t written[TEST_LIT_8][PCSC_FIDO_HID_PACKET_SIZE];
  size_t written_count;
  uint8_t reads[TEST_LIT_8][PCSC_FIDO_HID_PACKET_SIZE];
  size_t read_count;
  size_t read_index;
  size_t read_attempt_count;
  int last_timeout_ms;
} fake_io_t;

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static int fake_write(void* ctx, const uint8_t* packet, size_t packet_len) {
  fake_io_t* fake = (fake_io_t*)ctx;
  if (fake->written_count >= TEST_LIT_8U || packet_len != TEST_LIT_64U) {
    return -1;
  }
  (void)pcsc_fido_copy_bytes(fake->written[fake->written_count], TEST_LIT_64U,
                             0u, packet, TEST_LIT_64U);
  fake->written_count++;
  return 0;
}

static int fake_read(void* ctx, uint8_t* packet, size_t packet_len,
                     int timeout_ms) {
  fake_io_t* fake = (fake_io_t*)ctx;
  fake->read_attempt_count++;
  fake->last_timeout_ms = timeout_ms;
  if (fake->read_index >= fake->read_count || packet_len != TEST_LIT_64U) {
    return -1;
  }
  (void)pcsc_fido_copy_bytes(packet, packet_len, 0u,
                             fake->reads[fake->read_index], TEST_LIT_64U);
  fake->read_index++;
  return 0;
}

static void init_fake_io(fake_io_t* fake, pcsc_fido_hid_io_t* io) {
  pcsc_fido_zero_bytes(fake, sizeof(*fake));
  io->ctx = fake;
  io->write_packet = fake_write;
  io->read_packet = fake_read;
}

static void rejects_continuation_seq_above_max(void) {
  uint8_t packet[TEST_LIT_64];
  const uint8_t payload[] = {1u, 2u, 3u};
  expect_true(
      pcsc_fido_hid_encode_cont_packet(TEST_LIT_0X11223344U, TEST_LIT_0X7FU,
                                       payload, sizeof(payload), packet),
      "encode continuation with max valid seq 0x7F");
  expect_true(
      !pcsc_fido_hid_encode_cont_packet(TEST_LIT_0X11223344U, TEST_LIT_0X80U,
                                        payload, sizeof(payload), packet),
      "reject continuation seq 0x80 (would collide with init high bit)");
  expect_true(
      !pcsc_fido_hid_encode_cont_packet(TEST_LIT_0X11223344U, TEST_LIT_0XFFU,
                                        payload, sizeof(payload), packet),
      "reject continuation seq 0xFF");
}

static void encodes_headers(void) {
  uint8_t packet[TEST_LIT_64];
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  const uint8_t payload[] = {1u, 2u, 3u};
  expect_true(pcsc_fido_hid_encode_init_packet(TEST_LIT_0X11223344U,
                                               PCSC_FIDO_HID_CMD_CBOR, payload,
                                               sizeof(payload), packet),
              "encode init packet");
  expect_true(pcsc_fido_hid_decode_init_header(packet, &cid, &cmd, &len),
              "decode init header");
  expect_true(cid == TEST_LIT_0X11223344U && cmd == PCSC_FIDO_HID_CMD_CBOR &&
                  len == TEST_LIT_3U,
              "decoded init fields");
  expect_true(packet[TEST_LIT_7] == 1u && packet[TEST_LIT_9] == TEST_LIT_3U,
              "init payload copied");
}

static void prepare_init_response(fake_io_t* fake, uint32_t assigned_cid) {
  expect_true(pcsc_fido_hid_encode_init_packet(
                  PCSC_FIDO_HID_BROADCAST_CID, PCSC_FIDO_HID_CMD_INIT,
                  (const uint8_t*)"NEROFIDO", TEST_LIT_8U,
                  fake->reads[fake->read_count]),
              "prepare init response");
  fake->reads[fake->read_count][TEST_LIT_5] = 0x00u;
  fake->reads[fake->read_count][TEST_LIT_6] = TEST_LIT_17U;
  fake->reads[fake->read_count][TEST_LIT_15] =
      (uint8_t)((assigned_cid >> TEST_LIT_24U) & TEST_LIT_0XFFU);
  fake->reads[fake->read_count][TEST_LIT_16] =
      (uint8_t)((assigned_cid >> TEST_LIT_16U) & TEST_LIT_0XFFU);
  fake->reads[fake->read_count][TEST_LIT_17] =
      (uint8_t)((assigned_cid >> TEST_LIT_8U) & TEST_LIT_0XFFU);
  fake->reads[fake->read_count][TEST_LIT_18] =
      (uint8_t)(assigned_cid & TEST_LIT_0XFFU);
  fake->read_count++;
}

static void exchanges_cbor(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x00u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                  sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "exchange succeeds");
  expect_true(fake.written_count == TEST_LIT_2U,
              "init and cbor packets written");
  expect_true(response_len == sizeof(cbor_response) &&
                  memcmp(response, cbor_response, sizeof(cbor_response)) == 0,
              "response payload copied");
}

static void exchanges_large_request_with_continuation(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t request[TEST_LIT_80];
  uint8_t response[TEST_LIT_4];
  size_t response_len = 0u;
  const uint8_t cbor_response[] = {0x00u};
  init_fake_io(&fake, &io);
  pcsc_fido_fill_bytes(request, sizeof(request), (uint8_t)TEST_LIT_0XA5);
  request[0] = 0x01u;

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                  sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "large exchange succeeds");
  expect_true(fake.written_count == TEST_LIT_3U,
              "init, request init, and continuation packets written");
  expect_true(fake.written[1][TEST_LIT_5] == 0u &&
                  fake.written[1][TEST_LIT_6] == sizeof(request),
              "large request length encoded");
  expect_true(fake.written[TEST_SOCKETPAIR_FDS][TEST_LIT_4] == 0u,
              "first continuation sequence is zero");
}

static void rejects_unframable_exchange_lengths(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t request[PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u];
  uint8_t response[PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u];
  size_t response_len = 0u;
  init_fake_io(&fake, &io);
  pcsc_fido_fill_bytes(request, sizeof(request), (uint8_t)TEST_LIT_0XA5);
  prepare_init_response(&fake, TEST_CID);
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "unframable request rejected");

  init_fake_io(&fake, &io);
  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, response,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, fake.reads[fake.read_count]),
              "prepare unframable response init");
  fake.reads[fake.read_count][TEST_LIT_5] =
      (uint8_t)((sizeof(response) >> TEST_LIT_8U) & TEST_LIT_0XFFU);
  fake.reads[fake.read_count][TEST_LIT_6] =
      (uint8_t)(sizeof(response) & TEST_LIT_0XFFU);
  fake.read_count++;
  expect_true(
      !pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR,
                              (const uint8_t[]){TEST_LIT_0X04U}, 1u, response,
                              sizeof(response), &response_len, TEST_LIT_100),
      "unframable response rejected");
}

static void ignores_keepalive_and_other_channel(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t keepalive[] = {0x01u};
  const uint8_t wrong_response[] = {0x00u, 0xFFu};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x00u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                  sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                  sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare second keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID_OTHER, PCSC_FIDO_HID_CMD_CBOR, wrong_response,
                  sizeof(wrong_response), fake.reads[fake.read_count]),
              "prepare wrong-channel response");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                  sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare final cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "exchange ignores keepalive and other channel");
  expect_true(response_len == sizeof(cbor_response) &&
                  memcmp(response, cbor_response, sizeof(cbor_response)) == 0,
              "final response copied");
}

static void rejects_bad_continuation_sequence(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_96];
  uint8_t long_response[TEST_LIT_80];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  pcsc_fido_fill_bytes(long_response, sizeof(long_response),
                       (uint8_t)TEST_LIT_0XA5);
  long_response[0] = 0x00u;

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, long_response,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, fake.reads[fake.read_count]),
              "prepare long response init");
  fake.reads[fake.read_count][TEST_LIT_5] = 0u;
  fake.reads[fake.read_count][TEST_LIT_6] = sizeof(long_response);
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_cont_packet(
                  TEST_CID, 1u, long_response + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  sizeof(long_response) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  fake.reads[fake.read_count]),
              "prepare bad sequence continuation");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "bad continuation sequence rejected");
}

static void propagates_init_read_timeout(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[1];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);

  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_1234),
              "init read timeout fails exchange");
  expect_true(fake.written_count == 1u, "timeout wrote only init packet");
  expect_true(
      fake.read_attempt_count == 1u && fake.last_timeout_ms == TEST_LIT_1234,
      "timeout passed to init read");
}

static void times_out_after_repeated_keepalives(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t keepalive[] = {0x01u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                  sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare first wait keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                  sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare second wait keepalive");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_250),
              "exchange times out after keepalives without final response");
  expect_true(fake.read_attempt_count == TEST_LIT_4U &&
                  fake.last_timeout_ms == TEST_LIT_250,
              "timeout follows init and repeated keepalive reads");
}

static void rejects_response_larger_than_buffer(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_4];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x03u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                  sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare oversized response");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "oversized response rejected");
}

static void rejects_invalid_arguments(void) {
  uint8_t packet[TEST_LIT_64];
  uint8_t payload[PCSC_FIDO_HID_CONT_PAYLOAD_MAX + 1u];
  uint8_t response[1];
  size_t response_len = 0u;
  pcsc_fido_zero_bytes(payload, sizeof(payload));
  expect_true(!pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, payload,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX + 1u, packet),
              "oversized init packet payload rejected");
  expect_true(!pcsc_fido_hid_encode_cont_packet(TEST_CID, 0u, payload,
                                                sizeof(payload), packet),
              "oversized continuation payload rejected");
  expect_true(pcsc_fido_hid_encode_cont_packet(TEST_CID, 0u, PCSC_FIDO_NULL, 0u,
                                               packet),
              "zero-length continuation with PCSC_FIDO_NULL payload");
  expect_true(!pcsc_fido_hid_encode_cont_packet(TEST_CID, 0u, PCSC_FIDO_NULL,
                                                1u, packet),
              "nonzero continuation with PCSC_FIDO_NULL payload rejected");
  expect_true(!pcsc_fido_hid_decode_init_header(packet, PCSC_FIDO_NULL,
                                                PCSC_FIDO_NULL, PCSC_FIDO_NULL),
              "invalid decode args rejected");
  expect_true(!pcsc_fido_hid_exchange(
                  PCSC_FIDO_NULL, PCSC_FIDO_HID_CMD_CBOR, PCSC_FIDO_NULL, 0u,
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "invalid exchange args rejected");
}

static void exchanges_large_response_with_continuation(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_96];
  uint8_t long_response[TEST_LIT_80];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  pcsc_fido_fill_bytes(long_response, sizeof(long_response),
                       (uint8_t)TEST_LIT_0XA5);
  long_response[0] = 0x00u;

  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_CBOR, long_response,
                  PCSC_FIDO_HID_INIT_PAYLOAD_MAX, fake.reads[fake.read_count]),
              "prepare long response init");
  fake.reads[fake.read_count][TEST_LIT_5] = 0u;
  fake.reads[fake.read_count][TEST_LIT_6] = sizeof(long_response);
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_cont_packet(
                  TEST_CID, 0u, long_response + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  sizeof(long_response) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                  fake.reads[fake.read_count]),
              "prepare response continuation");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "large response exchange succeeds");
  expect_true(response_len == sizeof(long_response) &&
                  memcmp(response, long_response, sizeof(long_response)) == 0,
              "large response reassembled");
}

static void rejects_init_handshake_failures(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "missing init response fails");
  prepare_init_response(&fake, 0u);
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "zero assigned CID fails");
  fake.read_index = 0u;
  fake.read_count = 0u;
  prepare_init_response(&fake, PCSC_FIDO_HID_BROADCAST_CID);
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "broadcast assigned CID fails");
}

static void rejects_continuation_as_init_header(void) {
  uint8_t packet[TEST_LIT_64];
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  expect_true(pcsc_fido_hid_encode_cont_packet(TEST_CID, 0u,
                                               (const uint8_t*)"x", 1u, packet),
              "encode continuation packet");
  expect_true(!pcsc_fido_hid_decode_init_header(packet, &cid, &cmd, &len),
              "continuation header rejected by init decoder");
}

static void exchanges_ping_and_msg(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_16];
  size_t response_len = 0u;
  const uint8_t ping[] = {0xAAu, 0xBBu};
  const uint8_t msg[] = {0x00u, 0x00u, 0x00u, 0x00u, 0x05u,
                         0x00u, 0x00u, 0x00u, 0x00u};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_PING,
                                               ping, sizeof(ping),
                                               fake.reads[fake.read_count]),
              "prepare ping response");
  fake.read_count++;
  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_PING, ping,
                                     sizeof(ping), response, sizeof(response),
                                     &response_len, TEST_LIT_100),
              "ping exchange succeeds");
  expect_true(
      response_len == sizeof(ping) && memcmp(response, ping, sizeof(ping)) == 0,
      "ping payload echoed");

  init_fake_io(&fake, &io);
  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_MSG,
                                               msg, sizeof(msg),
                                               fake.reads[fake.read_count]),
              "prepare MSG response");
  fake.read_count++;
  response_len = 0u;
  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_MSG, msg,
                                     sizeof(msg), response, sizeof(response),
                                     &response_len, TEST_LIT_100),
              "MSG exchange succeeds");
  expect_true(
      response_len == sizeof(msg) && memcmp(response, msg, sizeof(msg)) == 0,
      "MSG payload copied");
}

static int failing_write(void* ctx, const uint8_t* packet, size_t packet_len) {
  (void)ctx;
  (void)packet;
  (void)packet_len;
  return -1;
}

static void propagates_write_failure(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, TEST_CID);
  io.write_packet = failing_write;
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "write failure fails exchange");
}

static void rejects_wrong_response_command(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[TEST_LIT_8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t ping_response[] = {0xAAu};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, TEST_CID);
  expect_true(pcsc_fido_hid_encode_init_packet(
                  TEST_CID, PCSC_FIDO_HID_CMD_PING, ping_response,
                  sizeof(ping_response), fake.reads[fake.read_count]),
              "prepare wrong command response");
  fake.read_count++;
  expect_true(!pcsc_fido_hid_exchange(
                  &io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                  response, sizeof(response), &response_len, TEST_LIT_100),
              "wrong response command rejected");
}

static void rejects_init_packet_copy_overflow(void) {
  uint8_t packet[TEST_LIT_64];
  const uint8_t payload[PCSC_FIDO_HID_INIT_PAYLOAD_MAX + 1u] = {0};
  expect_true(
      !pcsc_fido_hid_encode_init_packet(TEST_CID, PCSC_FIDO_HID_CMD_CBOR,
                                        payload, sizeof(payload), packet),
      "init packet copy bounds enforced");
}

int main(void) {
  encodes_headers();
  rejects_continuation_seq_above_max();
  exchanges_cbor();
  exchanges_large_request_with_continuation();
  rejects_unframable_exchange_lengths();
  ignores_keepalive_and_other_channel();
  rejects_bad_continuation_sequence();
  propagates_init_read_timeout();
  times_out_after_repeated_keepalives();
  rejects_response_larger_than_buffer();
  rejects_invalid_arguments();
  exchanges_large_response_with_continuation();
  rejects_init_handshake_failures();
  rejects_continuation_as_init_header();
  exchanges_ping_and_msg();
  propagates_write_failure();
  rejects_wrong_response_command();
  rejects_init_packet_copy_overflow();
  return failures == 0 ? 0 : 1;
}
