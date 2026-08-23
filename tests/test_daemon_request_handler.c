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
#include "pcsc_fido/daemon_request_handler.h"
#include "pcsc_fido/pcsc_bridge.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <linux/uhid.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

#define U32_ALL_ONES 0xFFFFFFFFu

enum {
  FAKE_TIME_START = 1000000,
  SOCKET_PAIR_FD_COUNT = 2,
  INIT_CMD_NFC = 0x4E464301,
  TEST_INVALID_HID_CMD = 0xEE,
  CANCEL_INJECT_SPIN_LIMIT = 50000,
  UINT32_BYTE3_SHIFT = 24,
  UINT32_BYTE2_SHIFT = 16,
  UINT32_BYTE1_SHIFT = 8,
  BYTE_MASK = 0xFF,
  HID_CID_BYTE2_OFFSET = 2,
  HID_CID_BYTE3_OFFSET = 3,
  HID_CMD_OFFSET = 4,
  HID_INIT_PACKET_FLAG = 0x80,
};

static time_t g_fake_time = FAKE_TIME_START;

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec* req PCSC_FIDO_MAYBE_UNUSED,
                     struct timespec* rem PCSC_FIDO_MAYBE_UNUSED) {
  return 0;
}

time_t __wrap_time(time_t* t) {
  g_fake_time++;
  if (t != PCSC_FIDO_NULL) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static int uhid_pair(int sv[SOCKET_PAIR_FD_COUNT]) {
  return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

static bool read_uhid_event(int fd, struct uhid_event* ev) {
  ssize_t got = read(fd, ev, sizeof(*ev));
  return got == (ssize_t)sizeof(*ev);
}

typedef struct {
  int fd;
} socket_drain_arg_t;

static void* drain_socket_main(void* arg) {
  const socket_drain_arg_t* ctx = (const socket_drain_arg_t*)arg;
  const int fd = ctx->fd;
  uint8_t buf[TEST_CAP_4096];
  ssize_t got;
  while ((got = read(fd, buf, sizeof(buf))) > 0) {
    (void)got;
  }
  return PCSC_FIDO_NULL;
}

static void start_socket_drain(int fd, pthread_t* thread,
                               socket_drain_arg_t* arg) {
  arg->fd = fd;
  expect_true(
      pthread_create(thread, PCSC_FIDO_NULL, drain_socket_main, arg) == 0,
      "socket drain thread starts");
}

static void stop_socket_drain(int producer_fd, int drain_fd, pthread_t thread) {
  (void)close(producer_fd);
  (void)pthread_join(thread, PCSC_FIDO_NULL);
  (void)close(drain_fd);
}

static void handler_setup(void) {
  g_fake_time = FAKE_TIME_START;
  mock_pcsc_reset();
  pcsc_fido_bridge_reset();
}

static void init_valid(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair init");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(
      &ctx, U32_ALL_ONES, PCSC_FIDO_HID_CMD_INIT, nonce, sizeof(nonce));
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "init response event");
    expect_true(ev.type == UHID_INPUT2, "init UHID_INPUT2");
  }
  close(sv[0]);
  close(sv[1]);
}

static void init_invalid_length(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t short_nonce[4] = {1, 2, 3, 4};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair init bad len");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, U32_ALL_ONES,
                                      PCSC_FIDO_HID_CMD_INIT, short_nonce,
                                      sizeof(short_nonce));
  close(sv[0]);
  close(sv[1]);
}

static void wrong_cid(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t ping[] = {0xAAu};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair wrong cid");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, TEST_CID, PCSC_FIDO_HID_CMD_PING,
                                      ping, sizeof(ping));
  close(sv[0]);
  close(sv[1]);
}

static void ping_echo(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t ping[] = {0xAAu, 0xBBu};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair ping");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_PING, ping,
                                      sizeof(ping));
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "ping response");
    expect_true(ev.type == UHID_INPUT2, "ping UHID_INPUT2");
  }
  close(sv[0]);
  close(sv[1]);
}

static void cancel_resets_bridge(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  struct uhid_event ev;
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair cancel");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CANCEL,
                                      PCSC_FIDO_NULL, 0u);
  (void)shutdown(sv[0], SHUT_WR);
  expect_true(!read_uhid_event(sv[1], &ev),
              "standalone CANCEL has no direct response");
  close(sv[0]);
  close(sv[1]);
}

static void wink_and_lock(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair wink");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_WINK,
                                      PCSC_FIDO_NULL, 0u);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_LOCK,
                                      PCSC_FIDO_NULL, 0u);
  close(sv[0]);
  close(sv[1]);
}

static void invalid_command(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair invalid cmd");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, TEST_INVALID_HID_CMD,
                                      PCSC_FIDO_NULL, 0u);
  close(sv[0]);
  close(sv[1]);
}

static void cbor_getinfo(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair cbor");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void cbor_bridge_failure(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  handler_setup();
  mock_pcsc_set_list_probe_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(uhid_pair(sv) == 0, "socketpair cbor fail");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void terminal_make_credential_resets_session(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t make_cred[] = {0x01u, 0xA0u};
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair makeCred");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      make_cred, sizeof(make_cred));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

typedef struct {
  int inject_fd;
  struct uhid_event ev;
} uhid_inject_args_t;

static void* inject_uhid_event_main(void* arg) {
  const uhid_inject_args_t* args = (const uhid_inject_args_t*)arg;
  for (unsigned spin = 0u; spin < CANCEL_INJECT_SPIN_LIMIT; spin++) {
    (void)spin;
  }
  ssize_t inject_wr = write(args->inject_fd, &args->ev, sizeof(args->ev));
  (void)inject_wr;
  return PCSC_FIDO_NULL;
}

static void cbor_keepalive_cancel_response(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pthread_t inject_thread;
  uhid_inject_args_t inject_args;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  handler_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(uhid_pair(sv) == 0, "socketpair keepalive cancel");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  pcsc_fido_zero_bytes(packet, sizeof(packet));
  packet[0] = (uint8_t)((cid >> UINT32_BYTE3_SHIFT) & BYTE_MASK);
  packet[1] = (uint8_t)((cid >> UINT32_BYTE2_SHIFT) & BYTE_MASK);
  packet[HID_CID_BYTE2_OFFSET] =
      (uint8_t)((cid >> UINT32_BYTE1_SHIFT) & BYTE_MASK);
  packet[HID_CID_BYTE3_OFFSET] = (uint8_t)(cid & BYTE_MASK);
  packet[HID_CMD_OFFSET] =
      (uint8_t)(HID_INIT_PACKET_FLAG | PCSC_FIDO_HID_CMD_CANCEL);
  pcsc_fido_zero_bytes(&inject_args.ev, sizeof(inject_args.ev));
  inject_args.ev.type = UHID_OUTPUT;
  inject_args.ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(inject_args.ev.u.output.data, sizeof(packet), 0u,
                             packet, sizeof(packet));
  inject_args.inject_fd = sv[1];
  expect_true(pthread_create(&inject_thread, PCSC_FIDO_NULL,
                             inject_uhid_event_main, &inject_args) == 0,
              "cancel inject thread starts");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  (void)pthread_join(inject_thread, PCSC_FIDO_NULL);
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

int main(void) {
  init_valid();
  init_invalid_length();
  wrong_cid();
  ping_echo();
  cancel_resets_bridge();
  wink_and_lock();
  invalid_command();
  cbor_getinfo();
  cbor_bridge_failure();
  terminal_make_credential_resets_session();
  cbor_keepalive_cancel_response();
  return failures == 0 ? 0 : 1;
}
