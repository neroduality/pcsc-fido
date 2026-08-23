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

enum {
  SHORT_WRITE_DIVISOR = 2,
  TEST_CAP_200 = 200,
  MULTI_RESPONSE_FILL_BYTE = 0xABu,
  MULTI_RESPONSE_READ_LIMIT = 4,
  MULTI_RESPONSE_MIN_PACKETS = 2,
  OVERSIZE_RESPONSE_PAYLOAD_LENGTH = 0x10000u,
  OUTPUT_PACKET_FILL_BYTE = 0xCCu,
  SHORT_OUTPUT_SIZE = 8,
};
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/uhid_transport.h"

#include <linux/uhid.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

static int failures;
static unsigned g_eintr_writes_remaining;
static bool g_short_writes_enabled;

extern ssize_t __real_write(int fd, const void* buf, size_t count);

ssize_t __wrap_write(int fd, const void* buf, size_t count) {
  if (g_eintr_writes_remaining > 0u) {
    g_eintr_writes_remaining--;
    errno = EINTR;
    return -1;
  }
  if (g_short_writes_enabled && count > 1u) {
    return __real_write(fd, buf, count / SHORT_WRITE_DIVISOR);
  }
  return __real_write(fd, buf, count);
}

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static int uhid_pair(int sv[TEST_SOCKETPAIR_FDS]) {
  return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

static bool read_uhid_event(int fd, struct uhid_event* ev) {
  ssize_t got = read(fd, ev, sizeof(*ev));
  return got == (ssize_t)sizeof(*ev);
}

static void create_and_destroy_device(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  expect_true(uhid_pair(sv) == 0, "socketpair");
  expect_true(!pcsc_fido_daemon_create_uhid_device(-1), "invalid fd rejected");
  expect_true(pcsc_fido_daemon_create_uhid_device(sv[0]), "create uhid");
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "read create event");
    expect_true(ev.type == UHID_CREATE2, "UHID_CREATE2 emitted");
  }

  pcsc_fido_daemon_destroy_uhid_device(sv[0]);
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "read destroy event");
    expect_true(ev.type == UHID_DESTROY, "UHID_DESTROY emitted");
  }
  close(sv[0]);
  close(sv[1]);
}

static void uhid_write_retries_eintr_and_short_writes(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  expect_true(uhid_pair(sv) == 0, "socketpair for retrying write");
  g_eintr_writes_remaining = 1u;
  g_short_writes_enabled = true;
  expect_true(pcsc_fido_daemon_create_uhid_device(sv[0]),
              "create retries interrupted short writes");
  g_short_writes_enabled = false;
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "read retried create event");
    expect_true(ev.type == UHID_CREATE2, "retried UHID_CREATE2 emitted");
  }
  close(sv[0]);
  close(sv[1]);
}

static void send_hid_response_single_packet(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  const uint8_t payload[] = {0x04u, 0xA1u, 0x00u};
  expect_true(uhid_pair(sv) == 0, "socketpair for response");
  expect_true(
      pcsc_fido_daemon_send_hid_response(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload)),
      "send single-packet response");
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "response event read");
    expect_true(ev.type == UHID_INPUT2, "UHID_INPUT2 for response");
    expect_true(ev.u.input2.size == PCSC_FIDO_HID_PACKET_SIZE, "packet size");
  }
  close(sv[0]);
  close(sv[1]);
}

static void send_hid_response_multi_packet(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  uint8_t payload[TEST_CAP_200];
  pcsc_fido_fill_bytes(payload, sizeof(payload),
                       (uint8_t)MULTI_RESPONSE_FILL_BYTE);
  expect_true(uhid_pair(sv) == 0, "socketpair for multi");
  expect_true(
      pcsc_fido_daemon_send_hid_response(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload)),
      "send multi-packet response");
  {
    struct uhid_event ev;
    unsigned packets = 0u;
    while (packets < MULTI_RESPONSE_READ_LIMIT && read_uhid_event(sv[1], &ev)) {
      if (ev.type == UHID_INPUT2) {
        packets++;
      }
    }
    expect_true(packets >= MULTI_RESPONSE_MIN_PACKETS,
                "multi-packet emits continuation frames");
  }
  close(sv[0]);
  close(sv[1]);
}

static void send_hid_error_and_keepalive(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  expect_true(uhid_pair(sv) == 0, "socketpair for error");
  expect_true(pcsc_fido_daemon_send_hid_error(sv[0], TEST_CID,
                                              PCSC_FIDO_DAEMON_ERR_OTHER),
              "send error");
  expect_true(pcsc_fido_daemon_send_keepalive(sv[0], TEST_CID),
              "send keepalive");
  close(sv[0]);
  close(sv[1]);
}

static void send_hid_response_validation(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  const uint8_t byte = 0x01u;
  expect_true(uhid_pair(sv) == 0, "socketpair for validation");
  expect_true(!pcsc_fido_daemon_send_hid_response(
                  sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, PCSC_FIDO_NULL, 1u),
              "PCSC_FIDO_NULL payload with length rejected");
  expect_true(!pcsc_fido_daemon_send_hid_response(
                  sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, &byte,
                  OVERSIZE_RESPONSE_PAYLOAD_LENGTH),
              "oversize payload rejected");
  expect_true(!pcsc_fido_daemon_send_hid_response(
                  sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, &byte,
                  PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u),
              "unframable response payload rejected");
  close(sv[0]);
  close(sv[1]);
}

static void output_packet_data_paths(void) {
  struct uhid_event ev;
  const uint8_t* data = PCSC_FIDO_NULL;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  pcsc_fido_fill_bytes(packet, sizeof(packet),
                       (uint8_t)OUTPUT_PACKET_FILL_BYTE);
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(packet), 0u, packet,
                             sizeof(packet));
  expect_true(pcsc_fido_daemon_output_packet_data(&ev, &data),
              "direct output packet");
  expect_true(data != PCSC_FIDO_NULL, "output data pointer set");
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE + 1u;
  ev.u.output.data[0] = 0u;
  (void)pcsc_fido_copy_bytes(ev.u.output.data + 1u, sizeof(packet), 0u, packet,
                             sizeof(packet));
  expect_true(pcsc_fido_daemon_output_packet_data(&ev, &data),
              "report-id prefixed packet");
  ev.type = UHID_OPEN;
  expect_true(!pcsc_fido_daemon_output_packet_data(&ev, &data),
              "non-output rejected");
  expect_true(!pcsc_fido_daemon_output_packet_data(PCSC_FIDO_NULL, &data),
              "PCSC_FIDO_NULL event rejected");
  ev.type = UHID_OUTPUT;
  ev.u.output.size = SHORT_OUTPUT_SIZE;
  expect_true(!pcsc_fido_daemon_output_packet_data(&ev, &data),
              "short output rejected");
}

int main(void) {
  create_and_destroy_device();
  uhid_write_retries_eintr_and_short_writes();
  send_hid_response_single_packet();
  send_hid_response_multi_packet();
  send_hid_error_and_keepalive();
  send_hid_response_validation();
  output_packet_data_paths();
  return failures == 0 ? 0 : 1;
}
