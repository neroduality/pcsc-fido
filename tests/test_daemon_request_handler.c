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

#define _POSIX_C_SOURCE 200809L

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

static time_t g_fake_time = 1000000;

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec *req PCSC_FIDO_MAYBE_UNUSED,
                     // cppcheck-suppress constParameterPointer
                     struct timespec *rem PCSC_FIDO_MAYBE_UNUSED) {
  return 0;
}

time_t __wrap_time(time_t *t) {
  g_fake_time++;
  if (t != nullptr) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static int uhid_pair(int sv[2]) {
  return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

static bool read_uhid_event(int fd, struct uhid_event *ev) {
  ssize_t got = read(fd, ev, sizeof(*ev));
  return got == (ssize_t)sizeof(*ev);
}

typedef struct {
  int fd;
} socket_drain_arg_t;

static void *drain_socket_main(void *arg) {
  const socket_drain_arg_t *ctx = (const socket_drain_arg_t *)arg;
  const int fd = ctx->fd;
  uint8_t buf[4096];
  ssize_t got;
  while ((got = read(fd, buf, sizeof(buf))) > 0) {
    (void)got;
  }
  return nullptr;
}

static void start_socket_drain(int fd, pthread_t *thread, socket_drain_arg_t *arg) {
  arg->fd = fd;
  expect_true(pthread_create(thread, nullptr, drain_socket_main, arg) == 0,
              "socket drain thread starts");
}

static void stop_socket_drain(int producer_fd, int drain_fd, pthread_t thread) {
  (void)close(producer_fd);
  (void)pthread_join(thread, nullptr);
  (void)close(drain_fd);
}

static void handler_setup(void) {
  g_fake_time = 1000000;
  mock_pcsc_reset();
  pcsc_fido_bridge_reset();
}

static void init_valid(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair init");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, 0xFFFFFFFFu, PCSC_FIDO_HID_CMD_INIT, nonce,
                                      sizeof(nonce));
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "init response event");
    expect_true(ev.type == UHID_INPUT2, "init UHID_INPUT2");
  }
  close(sv[0]);
  close(sv[1]);
}

static void init_invalid_length(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t short_nonce[4] = {1, 2, 3, 4};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair init bad len");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, 0xFFFFFFFFu, PCSC_FIDO_HID_CMD_INIT, short_nonce,
                                      sizeof(short_nonce));
  close(sv[0]);
  close(sv[1]);
}

static void wrong_cid(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t ping[] = {0xAAu};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair wrong cid");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, 0x01020304u, PCSC_FIDO_HID_CMD_PING, ping,
                                      sizeof(ping));
  close(sv[0]);
  close(sv[1]);
}

static void ping_echo(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t ping[] = {0xAAu, 0xBBu};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair ping");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_PING, ping, sizeof(ping));
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "ping response");
    expect_true(ev.type == UHID_INPUT2, "ping UHID_INPUT2");
  }
  close(sv[0]);
  close(sv[1]);
}

static void cancel_resets_bridge(void) {
  int sv[2];
  struct uhid_event ev;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair cancel");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CANCEL, nullptr, 0u);
  (void)shutdown(sv[0], SHUT_WR);
  expect_true(!read_uhid_event(sv[1], &ev), "standalone CANCEL has no direct response");
  close(sv[0]);
  close(sv[1]);
}

static void wink_and_lock(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair wink");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_WINK, nullptr, 0u);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_LOCK, nullptr, 0u);
  close(sv[0]);
  close(sv[1]);
}

static void invalid_command(void) {
  int sv[2];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair invalid cmd");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, 0xEEu, nullptr, 0u);
  close(sv[0]);
  close(sv[1]);
}

static void cbor_getinfo(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = 0x4E464301u;
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
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                      sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void cbor_bridge_failure(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  handler_setup();
  mock_pcsc_set_list_probe_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(uhid_pair(sv) == 0, "socketpair cbor fail");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                      sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void terminal_make_credential_resets_session(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint32_t cid = 0x4E464301u;
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
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR, make_cred,
                                      sizeof(make_cred));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

typedef struct {
  int inject_fd;
  struct uhid_event ev;
} uhid_inject_args_t;

static void *inject_uhid_event_main(void *arg) {
  uhid_inject_args_t *args = (uhid_inject_args_t *)arg;
  for (unsigned spin = 0u; spin < 50000u; spin++) {
    (void)spin;
  }
  (void)write(args->inject_fd, &args->ev, sizeof(args->ev));
  return nullptr;
}

static void cbor_keepalive_cancel_response(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pthread_t inject_thread;
  uhid_inject_args_t inject_args;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  handler_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(uhid_pair(sv) == 0, "socketpair keepalive cancel");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  memset(packet, 0, sizeof(packet));
  packet[0] = (uint8_t)((cid >> 24u) & 0xFFu);
  packet[1] = (uint8_t)((cid >> 16u) & 0xFFu);
  packet[2] = (uint8_t)((cid >> 8u) & 0xFFu);
  packet[3] = (uint8_t)(cid & 0xFFu);
  packet[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_CANCEL);
  memset(&inject_args.ev, 0, sizeof(inject_args.ev));
  inject_args.ev.type = UHID_OUTPUT;
  inject_args.ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  memcpy(inject_args.ev.u.output.data, packet, sizeof(packet));
  inject_args.inject_fd = sv[1];
  expect_true(pthread_create(&inject_thread, nullptr, inject_uhid_event_main, &inject_args) == 0,
              "cancel inject thread starts");
  ctx.fd = sv[0];
  ctx.assigned_cid = &cid;
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                      sizeof(get_info));
  (void)pthread_join(inject_thread, nullptr);
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
