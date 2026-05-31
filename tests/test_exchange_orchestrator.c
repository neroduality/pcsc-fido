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
#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/exchange_orchestrator.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_err.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <errno.h>
#include <linux/uhid.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static time_t g_fake_time = 1000000;
static atomic_bool g_fail_pthread_create;

extern int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                 void *(*start_routine)(void *), void *arg);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine)(void *), void *arg) {
  if (atomic_load_explicit(&g_fail_pthread_create, memory_order_relaxed)) {
    return EAGAIN;
  }
  return __real_pthread_create(thread, attr, start_routine, arg);
}

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

static void exchange_setup(void) {
  g_fake_time = 1000000;
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
  mock_pcsc_reset();
  mock_pcsc_set_readers("Exchange Test Reader 00 00");
  pcsc_fido_bridge_reset();
  unsetenv("PCSC_FIDO_READER");
  unsetenv("PCSC_FIDO_READER");
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

static void exchange_getinfo_completes(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(pcsc_fido_daemon_run_exchange_with_keepalive(
                sv[0], 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "exchange with keepalive succeeds");
  expect_true(response_len == 4u, "response length");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void exchange_response_too_large_for_buffer(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[2];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair small buffer");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(!pcsc_fido_daemon_run_exchange_with_keepalive(
                sv[0], 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "too-small caller buffer fails");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void write_uhid_output(int fd, const struct uhid_event *ev) {
  (void)write(fd, ev, sizeof(*ev));
}

static void build_hid_packet(uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t cid, uint8_t cmd) {
  memset(packet, 0, PCSC_FIDO_HID_PACKET_SIZE);
  packet[0] = (uint8_t)((cid >> 24u) & 0xFFu);
  packet[1] = (uint8_t)((cid >> 16u) & 0xFFu);
  packet[2] = (uint8_t)((cid >> 8u) & 0xFFu);
  packet[3] = (uint8_t)(cid & 0xFFu);
  packet[4] = (uint8_t)(0x80u | cmd);
}

static void exchange_cancelled_by_uhid_packet(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair cancel");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_hid_packet(packet, 0x01020304u, PCSC_FIDO_HID_CMD_CANCEL);
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  memcpy(ev.u.output.data, packet, sizeof(packet));
  write_uhid_output(sv[1], &ev);
  expect_true(!pcsc_fido_daemon_run_exchange_with_keepalive(
                sv[0], 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "cancelled exchange fails");
  expect_true(strstr(err, "cancelled") != nullptr, "cancelled error message");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void exchange_uhid_close_cancels(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair close");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_CLOSE;
  write_uhid_output(sv[1], &ev);
  expect_true(!pcsc_fido_daemon_run_exchange_with_keepalive(
                sv[0], 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "UHID close cancels exchange");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void exchange_channel_busy_on_ping(void) {
  int sv[2];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair busy");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_hid_packet(packet, 0x01020304u, PCSC_FIDO_HID_CMD_PING);
  packet[7] = 0x01u;
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  memcpy(ev.u.output.data, packet, sizeof(packet));
  write_uhid_output(sv[1], &ev);
  expect_true(pcsc_fido_daemon_run_exchange_with_keepalive(
                sv[0], 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "exchange survives channel busy ping");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void exchange_thread_start_failure(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  exchange_setup();
  atomic_store_explicit(&g_fail_pthread_create, true, memory_order_relaxed);
  expect_true(!pcsc_fido_daemon_run_exchange_with_keepalive(
                -1, 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "pthread_create failure rejected");
  expect_true(strstr(err, "failed to start PC/SC exchange thread") != nullptr,
              "thread start error message");
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
}

static void exchange_stop_requested_cancels(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup for stop test");
  pcsc_fido_daemon_test_request_stop();
  expect_true(!pcsc_fido_daemon_run_exchange_with_keepalive(
                -1, 0x01020304u, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info), response,
                sizeof(response), &response_len, err, sizeof(err)),
              "stop request cancels exchange");
  expect_true(strstr(err, PCSC_FIDO_ERR_MSG_CANCELLED) != nullptr, "stop cancel message");
  pcsc_fido_daemon_signals_shutdown();
}

int main(void) {
  exchange_getinfo_completes();
  exchange_response_too_large_for_buffer();
  exchange_cancelled_by_uhid_packet();
  exchange_uhid_close_cancels();
  exchange_channel_busy_on_ping();
  exchange_thread_start_failure();
  exchange_stop_requested_cancels();
  return failures == 0 ? 0 : 1;
}
