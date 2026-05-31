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

#include <stdio.h>
#include <string.h>

typedef struct {
  uint8_t written[8][PCSC_FIDO_HID_PACKET_SIZE];
  size_t written_count;
  uint8_t reads[8][PCSC_FIDO_HID_PACKET_SIZE];
  size_t read_count;
  size_t read_index;
  size_t read_attempt_count;
  int last_timeout_ms;
} fake_io_t;

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static int fake_write(void *ctx, const uint8_t *packet, size_t packet_len) {
  fake_io_t *fake = (fake_io_t *)ctx;
  if (fake->written_count >= 8u || packet_len != 64u) {
    return -1;
  }
  memcpy(fake->written[fake->written_count], packet, 64u);
  fake->written_count++;
  return 0;
}

static int fake_read(void *ctx, uint8_t *packet, size_t packet_len, int timeout_ms) {
  fake_io_t *fake = (fake_io_t *)ctx;
  fake->read_attempt_count++;
  fake->last_timeout_ms = timeout_ms;
  if (fake->read_index >= fake->read_count || packet_len != 64u) {
    return -1;
  }
  memcpy(packet, fake->reads[fake->read_index], 64u);
  fake->read_index++;
  return 0;
}

static void init_fake_io(fake_io_t *fake, pcsc_fido_hid_io_t *io) {
  memset(fake, 0, sizeof(*fake));
  io->ctx = fake;
  io->write_packet = fake_write;
  io->read_packet = fake_read;
}

static void rejects_continuation_seq_above_max(void) {
  uint8_t packet[64];
  const uint8_t payload[] = {1u, 2u, 3u};
  expect_true(
    pcsc_fido_hid_encode_cont_packet(0x11223344u, 0x7Fu, payload, sizeof(payload), packet),
    "encode continuation with max valid seq 0x7F");
  expect_true(
    !pcsc_fido_hid_encode_cont_packet(0x11223344u, 0x80u, payload, sizeof(payload), packet),
    "reject continuation seq 0x80 (would collide with init high bit)");
  expect_true(
    !pcsc_fido_hid_encode_cont_packet(0x11223344u, 0xFFu, payload, sizeof(payload), packet),
    "reject continuation seq 0xFF");
}

static void encodes_headers(void) {
  uint8_t packet[64];
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  const uint8_t payload[] = {1u, 2u, 3u};
  expect_true(pcsc_fido_hid_encode_init_packet(0x11223344u, PCSC_FIDO_HID_CMD_CBOR, payload,
                                               sizeof(payload), packet),
              "encode init packet");
  expect_true(pcsc_fido_hid_decode_init_header(packet, &cid, &cmd, &len), "decode init header");
  expect_true(cid == 0x11223344u && cmd == PCSC_FIDO_HID_CMD_CBOR && len == 3u,
              "decoded init fields");
  expect_true(packet[7] == 1u && packet[9] == 3u, "init payload copied");
}

static void prepare_init_response(fake_io_t *fake, uint32_t assigned_cid) {
  expect_true(pcsc_fido_hid_encode_init_packet(PCSC_FIDO_HID_BROADCAST_CID, PCSC_FIDO_HID_CMD_INIT,
                                               (const uint8_t *)"NEROFIDO", 8u,
                                               fake->reads[fake->read_count]),
              "prepare init response");
  fake->reads[fake->read_count][5] = 0x00u;
  fake->reads[fake->read_count][6] = 17u;
  fake->reads[fake->read_count][15] = (uint8_t)((assigned_cid >> 24u) & 0xFFu);
  fake->reads[fake->read_count][16] = (uint8_t)((assigned_cid >> 16u) & 0xFFu);
  fake->reads[fake->read_count][17] = (uint8_t)((assigned_cid >> 8u) & 0xFFu);
  fake->reads[fake->read_count][18] = (uint8_t)(assigned_cid & 0xFFu);
  fake->read_count++;
}

static void exchanges_cbor(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x00u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                                               sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                     response, sizeof(response), &response_len, 100),
              "exchange succeeds");
  expect_true(fake.written_count == 2u, "init and cbor packets written");
  expect_true(response_len == sizeof(cbor_response) &&
                memcmp(response, cbor_response, sizeof(cbor_response)) == 0,
              "response payload copied");
}

static void exchanges_large_request_with_continuation(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t request[80];
  uint8_t response[4];
  size_t response_len = 0u;
  const uint8_t cbor_response[] = {0x00u};
  init_fake_io(&fake, &io);
  memset(request, 0xA5, sizeof(request));
  request[0] = 0x01u;

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                                               sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                     response, sizeof(response), &response_len, 100),
              "large exchange succeeds");
  expect_true(fake.written_count == 3u, "init, request init, and continuation packets written");
  expect_true(fake.written[1][5] == 0u && fake.written[1][6] == sizeof(request),
              "large request length encoded");
  expect_true(fake.written[2][4] == 0u, "first continuation sequence is zero");
}

static void rejects_unframable_exchange_lengths(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t request[PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u];
  uint8_t response[PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u];
  size_t response_len = 0u;
  init_fake_io(&fake, &io);
  memset(request, 0xA5, sizeof(request));
  prepare_init_response(&fake, 0x01020304u);
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "unframable request rejected");

  init_fake_io(&fake, &io);
  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, response,
                                               PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                                               fake.reads[fake.read_count]),
              "prepare unframable response init");
  fake.reads[fake.read_count][5] = (uint8_t)((sizeof(response) >> 8u) & 0xFFu);
  fake.reads[fake.read_count][6] = (uint8_t)(sizeof(response) & 0xFFu);
  fake.read_count++;
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, (const uint8_t[]){0x04u}, 1u,
                                      response, sizeof(response), &response_len, 100),
              "unframable response rejected");
}

static void ignores_keepalive_and_other_channel(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t keepalive[] = {0x01u};
  const uint8_t wrong_response[] = {0x00u, 0xFFu};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x00u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                                               sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                                               sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare second keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(0xAABBCCDDu, PCSC_FIDO_HID_CMD_CBOR, wrong_response,
                                               sizeof(wrong_response), fake.reads[fake.read_count]),
              "prepare wrong-channel response");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                                               sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare final cbor response");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                     response, sizeof(response), &response_len, 100),
              "exchange ignores keepalive and other channel");
  expect_true(response_len == sizeof(cbor_response) &&
                memcmp(response, cbor_response, sizeof(cbor_response)) == 0,
              "final response copied");
}

static void rejects_bad_continuation_sequence(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[96];
  uint8_t long_response[80];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  memset(long_response, 0xA5, sizeof(long_response));
  long_response[0] = 0x00u;

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, long_response,
                                               PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                                               fake.reads[fake.read_count]),
              "prepare long response init");
  fake.reads[fake.read_count][5] = 0u;
  fake.reads[fake.read_count][6] = sizeof(long_response);
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_cont_packet(
                0x01020304u, 1u, long_response + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                sizeof(long_response) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                fake.reads[fake.read_count]),
              "prepare bad sequence continuation");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "bad continuation sequence rejected");
}

static void propagates_init_read_timeout(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[1];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);

  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 1234),
              "init read timeout fails exchange");
  expect_true(fake.written_count == 1u, "timeout wrote only init packet");
  expect_true(fake.read_attempt_count == 1u && fake.last_timeout_ms == 1234,
              "timeout passed to init read");
}

static void times_out_after_repeated_keepalives(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t keepalive[] = {0x01u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                                               sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare first wait keepalive");
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_KEEPALIVE, keepalive,
                                               sizeof(keepalive), fake.reads[fake.read_count]),
              "prepare second wait keepalive");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 250),
              "exchange times out after keepalives without final response");
  expect_true(fake.read_attempt_count == 4u && fake.last_timeout_ms == 250,
              "timeout follows init and repeated keepalive reads");
}

static void rejects_response_larger_than_buffer(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[4];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t cbor_response[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x03u};
  init_fake_io(&fake, &io);

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, cbor_response,
                                               sizeof(cbor_response), fake.reads[fake.read_count]),
              "prepare oversized response");
  fake.read_count++;

  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "oversized response rejected");
}

static void rejects_invalid_arguments(void) {
  uint8_t packet[64];
  uint8_t payload[PCSC_FIDO_HID_CONT_PAYLOAD_MAX + 1u];
  uint8_t response[1];
  size_t response_len = 0u;
  memset(payload, 0, sizeof(payload));
  expect_true(!pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, payload,
                                                PCSC_FIDO_HID_INIT_PAYLOAD_MAX + 1u, packet),
              "oversized init packet payload rejected");
  expect_true(!pcsc_fido_hid_encode_cont_packet(0x01020304u, 0u, payload, sizeof(payload), packet),
              "oversized continuation payload rejected");
  expect_true(pcsc_fido_hid_encode_cont_packet(0x01020304u, 0u, nullptr, 0u, packet),
              "zero-length continuation with nullptr payload");
  expect_true(!pcsc_fido_hid_encode_cont_packet(0x01020304u, 0u, nullptr, 1u, packet),
              "nonzero continuation with nullptr payload rejected");
  expect_true(!pcsc_fido_hid_decode_init_header(packet, nullptr, nullptr, nullptr),
              "invalid decode args rejected");
  expect_true(!pcsc_fido_hid_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, nullptr, 0u, response,
                                      sizeof(response), &response_len, 100),
              "invalid exchange args rejected");
}

static void exchanges_large_response_with_continuation(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[96];
  uint8_t long_response[80];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  memset(long_response, 0xA5, sizeof(long_response));
  long_response[0] = 0x00u;

  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, long_response,
                                               PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                                               fake.reads[fake.read_count]),
              "prepare long response init");
  fake.reads[fake.read_count][5] = 0u;
  fake.reads[fake.read_count][6] = sizeof(long_response);
  fake.read_count++;
  expect_true(pcsc_fido_hid_encode_cont_packet(
                0x01020304u, 0u, long_response + PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                sizeof(long_response) - PCSC_FIDO_HID_INIT_PAYLOAD_MAX,
                fake.reads[fake.read_count]),
              "prepare response continuation");
  fake.read_count++;

  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                     response, sizeof(response), &response_len, 100),
              "large response exchange succeeds");
  expect_true(response_len == sizeof(long_response) &&
                memcmp(response, long_response, sizeof(long_response)) == 0,
              "large response reassembled");
}

static void rejects_init_handshake_failures(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "missing init response fails");
  prepare_init_response(&fake, 0u);
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "zero assigned CID fails");
  fake.read_index = 0u;
  fake.read_count = 0u;
  prepare_init_response(&fake, PCSC_FIDO_HID_BROADCAST_CID);
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "broadcast assigned CID fails");
}

static void rejects_continuation_as_init_header(void) {
  uint8_t packet[64];
  uint32_t cid = 0u;
  uint8_t cmd = 0u;
  size_t len = 0u;
  expect_true(pcsc_fido_hid_encode_cont_packet(0x01020304u, 0u, (const uint8_t *)"x", 1u, packet),
              "encode continuation packet");
  expect_true(!pcsc_fido_hid_decode_init_header(packet, &cid, &cmd, &len),
              "continuation header rejected by init decoder");
}

static void exchanges_ping_and_msg(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[16];
  size_t response_len = 0u;
  const uint8_t ping[] = {0xAAu, 0xBBu};
  const uint8_t msg[] = {0x00u, 0x00u, 0x00u, 0x00u, 0x05u, 0x00u, 0x00u, 0x00u, 0x00u};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_PING, ping,
                                               sizeof(ping), fake.reads[fake.read_count]),
              "prepare ping response");
  fake.read_count++;
  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_PING, ping, sizeof(ping), response,
                                     sizeof(response), &response_len, 100),
              "ping exchange succeeds");
  expect_true(response_len == sizeof(ping) && memcmp(response, ping, sizeof(ping)) == 0,
              "ping payload echoed");

  init_fake_io(&fake, &io);
  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_MSG, msg, sizeof(msg),
                                               fake.reads[fake.read_count]),
              "prepare MSG response");
  fake.read_count++;
  response_len = 0u;
  expect_true(pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_MSG, msg, sizeof(msg), response,
                                     sizeof(response), &response_len, 100),
              "MSG exchange succeeds");
  expect_true(response_len == sizeof(msg) && memcmp(response, msg, sizeof(msg)) == 0,
              "MSG payload copied");
}

static int failing_write(void *ctx, const uint8_t *packet, size_t packet_len) {
  (void)ctx;
  (void)packet;
  (void)packet_len;
  return -1;
}

static void propagates_write_failure(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, 0x01020304u);
  io.write_packet = failing_write;
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "write failure fails exchange");
}

static void rejects_wrong_response_command(void) {
  fake_io_t fake;
  pcsc_fido_hid_io_t io;
  uint8_t response[8];
  size_t response_len = 0u;
  const uint8_t request[] = {0x04u};
  const uint8_t ping_response[] = {0xAAu};
  init_fake_io(&fake, &io);
  prepare_init_response(&fake, 0x01020304u);
  expect_true(pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_PING, ping_response,
                                               sizeof(ping_response), fake.reads[fake.read_count]),
              "prepare wrong command response");
  fake.read_count++;
  expect_true(!pcsc_fido_hid_exchange(&io, PCSC_FIDO_HID_CMD_CBOR, request, sizeof(request),
                                      response, sizeof(response), &response_len, 100),
              "wrong response command rejected");
}

static void rejects_init_packet_copy_overflow(void) {
  uint8_t packet[64];
  const uint8_t payload[PCSC_FIDO_HID_INIT_PAYLOAD_MAX + 1u] = {0};
  expect_true(!pcsc_fido_hid_encode_init_packet(0x01020304u, PCSC_FIDO_HID_CMD_CBOR, payload,
                                                sizeof(payload), packet),
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
