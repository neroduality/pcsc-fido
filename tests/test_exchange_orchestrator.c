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
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/exchange_orchestrator.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/uhid_transport.h"

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
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"
#include "scrub_hook.h"

enum {
  FAKE_TIME_START = 1000000,
  GETINFO_RESPONSE_LEN = 4,
  SMALL_RESPONSE_CAPACITY = 2,
  UINT32_BYTE3_SHIFT = 24,
  UINT32_BYTE2_SHIFT = 16,
  UINT32_BYTE1_SHIFT = 8,
  BYTE_MASK = 0xFFu,
  HID_CID_BYTE2_OFFSET = 2,
  HID_CID_BYTE3_OFFSET = 3,
  HID_CMD_OFFSET = 4,
  HID_BCNTL_OFFSET = 6,
  HID_INIT_PACKET_FLAG = 0x80u,
  HID_INIT_DATA_OFFSET = 7,
  DRAIN_CAPTURE_EVENTS = 16,
  OTHER_CHANNEL_CID = 0x0BADC0DEu,
  /* The stalled transmit outlives the stop request by this long. */
  STOP_STALL_MS = 400,
  STOP_STALL_WAIT_MS = 5000,
  /* Waits wake on the signal fd, so a stop costs one early pass, and the
   * last pass may straddle the end of the stall. */
  STOP_EXTRA_KEEPALIVES = 2,
};

static time_t g_fake_time = FAKE_TIME_START;
static atomic_bool g_fail_pthread_create;

extern int __real_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                                 void* (*start_routine)(void*), void* arg);

int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                          void* (*start_routine)(void*), void* arg) {
  if (atomic_load_explicit(&g_fail_pthread_create, memory_order_relaxed)) {
    return EAGAIN;
  }
  return __real_pthread_create(thread, attr, start_routine, arg);
}

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec* req PCSC_FIDO_MAYBE_UNUSED,
                     struct timespec* rem PCSC_FIDO_MAYBE_UNUSED) {
  return 0;
}

extern int __real_clock_gettime(clockid_t clock_id, struct timespec* ts);

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* ts) {
  if (clock_id != CLOCK_MONOTONIC || ts == PCSC_FIDO_NULL) {
    return __real_clock_gettime(clock_id, ts);
  }
  g_fake_time++;
  ts->tv_sec = g_fake_time;
  ts->tv_nsec = 0;
  return 0;
}

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void exchange_setup(void) {
  g_fake_time = FAKE_TIME_START;
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
  mock_pcsc_reset();
  mock_pcsc_set_readers("Exchange Test Reader 00 00");
  pcsc_fido_bridge_reset();
  unsetenv("PCSC_FIDO_READER");
  unsetenv("PCSC_FIDO_READER");
}

typedef struct {
  int fd;
  /* Bytes the orchestrator wrote to the UHID side; every outbound frame is a
   * whole struct uhid_event, so bytes / sizeof(struct uhid_event) is the
   * number of keepalives (plus CHANNEL_BUSY replies, when a test sends one).
   * Written only by the drain thread; read after pthread_join. */
  size_t bytes;
  /* The first DRAIN_CAPTURE_EVENTS outbound events, for inspecting replies. */
  struct uhid_event captured[DRAIN_CAPTURE_EVENTS];
} socket_drain_arg_t;

static void* drain_socket_main(void* arg) {
  socket_drain_arg_t* ctx = (socket_drain_arg_t*)arg;
  const int fd = ctx->fd;
  uint8_t buf[TEST_CAP_4096];
  ssize_t got;
  while ((got = read(fd, buf, sizeof(buf))) > 0) {
    const size_t cap = sizeof(ctx->captured);
    if (ctx->bytes < cap) {
      const size_t room = cap - ctx->bytes;
      const size_t take = (size_t)got < room ? (size_t)got : room;
      (void)pcsc_fido_copy_bytes(ctx->captured, cap, ctx->bytes, buf, take);
    }
    ctx->bytes += (size_t)got;
  }
  return PCSC_FIDO_NULL;
}

/* CTAPHID error frames among the captured outbound events (keepalives are
 * KEEPALIVE frames, so they are not counted). */
static unsigned captured_error_frames(const socket_drain_arg_t* arg) {
  unsigned errors = 0u;
  size_t events = arg->bytes / sizeof(struct uhid_event);
  if (events > DRAIN_CAPTURE_EVENTS) {
    events = DRAIN_CAPTURE_EVENTS;
  }
  for (size_t i = 0u; i < events; i++) {
    if (arg->captured[i].u.input2.data[HID_CMD_OFFSET] ==
        (uint8_t)(HID_INIT_PACKET_FLAG | PCSC_FIDO_HID_CMD_ERROR)) {
      errors++;
    }
  }
  return errors;
}

static void start_socket_drain(int fd, pthread_t* thread,
                               socket_drain_arg_t* arg) {
  arg->fd = fd;
  arg->bytes = 0u;
  expect_true(
      pthread_create(thread, PCSC_FIDO_NULL, drain_socket_main, arg) == 0,
      "socket drain thread starts");
}

static void stop_socket_drain(int producer_fd, int drain_fd, pthread_t thread) {
  (void)close(producer_fd);
  (void)pthread_join(thread, PCSC_FIDO_NULL);
  (void)close(drain_fd);
}

/* Exact-length match on the private job struct: the bridge CAPDU/RAPDU and
 * chain-chunk scrubs are also larger than PENDING_MAX, so a size threshold
 * would pass even with the job guard removed. */
static void expect_job_scrubbed(const char* why) {
  expect_true(
      scrub_hook_calls_with_len(pcsc_fido_daemon_exchange_job_size()) == 1u,
      why);
  expect_true(scrub_hook_all_zero(), "exchange scrubs left regions zeroed");
}

static void exchange_getinfo_completes(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  unsigned keepalives = 0u;
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  scrub_hook_reset();
  expect_true(
      pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "exchange with keepalive succeeds");
  expect_true(response_len == GETINFO_RESPONSE_LEN, "response length");
  /* Join the drain first so drain_arg.bytes is final; it is the only
   * observer of how many keepalives the timing-dependent loop emitted. */
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(drain_arg.bytes % sizeof(struct uhid_event) == 0u,
              "orchestrator wrote whole UHID events only");
  keepalives = (unsigned)(drain_arg.bytes / sizeof(struct uhid_event));
  /* Job is unique-sized. CAPDU is unique-sized. RAPDU shares its length
   * with the SELECT output buffer and the APDU-chain chunk (SELECT +
   * command), so that count is combined.
   * UHID events: the loop runs keepalives+1 passes (the last sees done), each
   * scrubbing one drained-event buffer, and one more drain runs after the
   * worker is joined. Every keepalive adds one send_packet event and one HID
   * packet staging buffer. */
  expect_true(
      scrub_hook_calls_with_len(pcsc_fido_daemon_exchange_job_size()) == 1u,
      "job scrubbed once, exact struct length");
  expect_true(scrub_hook_calls_with_len(PCSC_FIDO_BRIDGE_MAX_APDU) == 1u,
              "bridge CAPDU is scrubbed once");
  expect_true(
      scrub_hook_calls_with_len(PCSC_FIDO_BRIDGE_MAX_RESPONSE) == TEST_LIT_4U,
      "RAPDU, SELECT response, and SELECT and command chain chunks");
  expect_true(scrub_hook_calls_with_len(sizeof(struct uhid_event)) ==
                  (TEST_LIT_2U * keepalives) + TEST_LIT_2U,
              "one drained event per loop pass, one after join, plus one per "
              "keepalive sent");
  expect_true(
      scrub_hook_calls_with_len(PCSC_FIDO_HID_PACKET_SIZE) == keepalives,
      "one HID packet staging buffer per keepalive sent");
  expect_true(scrub_hook_all_zero(), "every scrub left its region zeroed");
}

static void exchange_response_too_large_for_buffer(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[SMALL_RESPONSE_CAPACITY];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  const uint8_t mock_resp[] = {0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair small buffer");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "too-small caller buffer fails");
  expect_job_scrubbed("job scrubbed when the caller buffer is too small");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void write_uhid_output(int fd, const struct uhid_event* ev) {
  ssize_t wr = write(fd, ev, sizeof(*ev));
  (void)wr;
}

static void build_hid_packet(uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                             uint32_t cid, uint8_t cmd) {
  pcsc_fido_zero_bytes(packet, PCSC_FIDO_HID_PACKET_SIZE);
  packet[0] = (uint8_t)((cid >> UINT32_BYTE3_SHIFT) & BYTE_MASK);
  packet[1] = (uint8_t)((cid >> UINT32_BYTE2_SHIFT) & BYTE_MASK);
  packet[HID_CID_BYTE2_OFFSET] =
      (uint8_t)((cid >> UINT32_BYTE1_SHIFT) & BYTE_MASK);
  packet[HID_CID_BYTE3_OFFSET] = (uint8_t)(cid & BYTE_MASK);
  packet[HID_CMD_OFFSET] = (uint8_t)(HID_INIT_PACKET_FLAG | cmd);
}

static void queue_uhid_packet(int fd, const uint8_t packet[]) {
  struct uhid_event ev;
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(ev.u.output.data), 0u,
                             packet, PCSC_FIDO_HID_PACKET_SIZE);
  write_uhid_output(fd, &ev);
}

/* One-shot: the next pthread_join (the exchange worker's) queues this event on
 * the peer fd once the worker has finished, after the loop's last poll. */
static atomic_int g_after_join_fd = -1;
static struct uhid_event g_after_join_event;

extern int __real_pthread_join(pthread_t thread, void** retval);

int __wrap_pthread_join(pthread_t thread, void** retval) {
  const int rc = __real_pthread_join(thread, retval);
  const int fd =
      atomic_exchange_explicit(&g_after_join_fd, -1, memory_order_relaxed);
  if (fd >= 0) {
    write_uhid_output(fd, &g_after_join_event);
  }
  return rc;
}

static bool run_with_event_after_join(const struct uhid_event* ev, char* err,
                                      size_t err_cap) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  bool ok;
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair event after join");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  g_after_join_event = *ev;
  atomic_store_explicit(&g_after_join_fd, sv[1], memory_order_relaxed);
  ok = pcsc_fido_daemon_run_exchange_with_keepalive(
      sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
      response, sizeof(response), &response_len, err, err_cap);
  expect_true(
      atomic_load_explicit(&g_after_join_fd, memory_order_relaxed) == -1,
      "the event was queued after the worker was joined");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  return ok;
}

static void exchange_cancel_after_last_poll(void) {
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  char err[TEST_CAP_256];
  build_hid_packet(packet, TEST_CID, PCSC_FIDO_HID_CMD_CANCEL);
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(ev.u.output.data), 0u,
                             packet, sizeof(packet));
  expect_true(!run_with_event_after_join(&ev, err, sizeof(err)),
              "a CANCEL behind the card's success still cancels");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_CANCELLED) == 0,
              "a late CANCEL is reported as cancelled");
}

static void exchange_close_after_last_poll(void) {
  struct uhid_event ev;
  char err[TEST_CAP_256];
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_CLOSE;
  expect_true(!run_with_event_after_join(&ev, err, sizeof(err)),
              "a close behind the card's success still fails the exchange");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_CLIENT_CLOSED) == 0,
              "a late close is reported as a closed client");
}

static void exchange_cancelled_by_uhid_packet(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair cancel");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_hid_packet(packet, TEST_CID, PCSC_FIDO_HID_CMD_CANCEL);
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(packet), 0u, packet,
                             sizeof(packet));
  write_uhid_output(sv[1], &ev);
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "cancelled exchange fails");
  expect_true(strstr(err, "cancelled") != PCSC_FIDO_NULL,
              "cancelled error message");
  expect_job_scrubbed("job scrubbed on CANCEL");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void exchange_uhid_close_cancels(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair close");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_CLOSE;
  write_uhid_output(sv[1], &ev);
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "UHID close cancels exchange");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_CLIENT_CLOSED) == 0,
              "UHID close is reported as a closed client");
  expect_job_scrubbed("job scrubbed on UHID close");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(drain_arg.bytes == 0u, "no keepalive is sent to a closed client");
}

static void build_init_packet(uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                              uint32_t cid,
                              const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN],
                              uint8_t bcntl) {
  build_hid_packet(packet, cid, PCSC_FIDO_HID_CMD_INIT);
  packet[HID_BCNTL_OFFSET] = bcntl;
  (void)pcsc_fido_copy_bytes(packet, PCSC_FIDO_HID_PACKET_SIZE,
                             HID_INIT_DATA_OFFSET, nonce,
                             PCSC_FIDO_HID_INIT_NONCE_LEN);
}

static void exchange_init_on_active_channel_resyncs(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN] = {
      0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair resync");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_init_packet(packet, TEST_CID, nonce, PCSC_FIDO_HID_INIT_NONCE_LEN);
  queue_uhid_packet(sv[1], packet);
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "INIT on the busy channel abandons the exchange");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_RESYNC) == 0,
              "INIT on the busy channel is reported as a resync");
  expect_true(response_len == sizeof(nonce) &&
                  memcmp(response, nonce, sizeof(nonce)) == 0,
              "the resync hands back the INIT nonce, not the card's response");
  expect_job_scrubbed("job scrubbed on resync");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(drain_arg.bytes == 0u,
              "a resynced channel gets neither CHANNEL_BUSY nor keepalives");
}

static void exchange_malformed_init_is_busy(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN] = {0};
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair malformed INIT");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_init_packet(packet, TEST_CID, nonce, PCSC_FIDO_HID_INIT_NONCE_LEN - 1u);
  queue_uhid_packet(sv[1], packet);
  expect_true(
      pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "an INIT with a short nonce does not resync the channel");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(captured_error_frames(&drain_arg) == 1u,
              "an INIT with a short nonce gets CHANNEL_BUSY");
}

static void exchange_channel_busy_on_ping(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair busy");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_hid_packet(packet, TEST_CID, PCSC_FIDO_HID_CMD_PING);
  packet[HID_INIT_DATA_OFFSET] = 0x01u;
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(packet), 0u, packet,
                             sizeof(packet));
  write_uhid_output(sv[1], &ev);
  expect_true(
      pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "exchange survives channel busy ping");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(captured_error_frames(&drain_arg) == 1u,
              "a new request during the exchange gets one CHANNEL_BUSY");
}

static void exchange_drops_other_channel_cancel_and_continuation(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  exchange_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair silent frames");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  build_hid_packet(packet, OTHER_CHANNEL_CID, PCSC_FIDO_HID_CMD_CANCEL);
  queue_uhid_packet(sv[1], packet);
  build_hid_packet(packet, OTHER_CHANNEL_CID, 0u);
  packet[HID_CMD_OFFSET] = 0u; /* continuation frame, sequence 0 */
  queue_uhid_packet(sv[1], packet);
  expect_true(
      pcsc_fido_daemon_run_exchange_with_keepalive(
          sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "another channel's CANCEL does not cancel the exchange");
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(captured_error_frames(&drain_arg) == 0u,
              "CANCEL and continuation frames from another channel get no "
              "reply");
}

static void exchange_thread_start_failure(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  exchange_setup();
  atomic_store_explicit(&g_fail_pthread_create, true, memory_order_relaxed);
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          -1, TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "pthread_create failure rejected");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_EXCHANGE_THREAD) == 0,
              "thread start error message");
  expect_job_scrubbed("job scrubbed when the worker thread fails to start");
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
}

static void exchange_stop_requested_cancels(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  exchange_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup for stop test");
  pcsc_fido_daemon_test_request_stop();
  scrub_hook_reset();
  expect_true(
      !pcsc_fido_daemon_run_exchange_with_keepalive(
          -1, TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
          response, sizeof(response), &response_len, err, sizeof(err)),
      "stop request cancels exchange");
  expect_true(strstr(err, PCSC_FIDO_ERR_MSG_CANCELLED) != PCSC_FIDO_NULL,
              "stop cancel message");
  expect_job_scrubbed("job scrubbed when a stop request cancels the exchange");
  pcsc_fido_daemon_signals_shutdown();
}

static void* request_stop_during_transmit(void* arg PCSC_FIDO_MAYBE_UNUSED) {
  if (mock_pcsc_wait_for_transmit_waiting(STOP_STALL_WAIT_MS)) {
    pcsc_fido_daemon_test_request_stop();
  }
  return PCSC_FIDO_NULL;
}

/* SCardCancel cannot interrupt SCardTransmit, so after a stop the loop keeps
 * waiting for the worker; it must keep pacing itself while it does. */
static void exchange_stop_waits_without_spinning(void) {
  int sv[TEST_SOCKETPAIR_FDS];
  pthread_t drain_thread;
  pthread_t stop_thread;
  socket_drain_arg_t drain_arg;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  bool ok;
  size_t keepalives;
  exchange_setup();
  mock_pcsc_set_transmit_stall_ms(STOP_STALL_MS);
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup for stall test");
  expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair stop stall");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(pthread_create(&stop_thread, PCSC_FIDO_NULL,
                             request_stop_during_transmit, PCSC_FIDO_NULL) == 0,
              "stop thread starts");
  ok = pcsc_fido_daemon_run_exchange_with_keepalive(
      sv[0], TEST_CID, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
      response, sizeof(response), &response_len, err, sizeof(err));
  (void)pthread_join(stop_thread, PCSC_FIDO_NULL);
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(!ok, "stop during a stalled transmit fails the exchange");
  expect_true(strcmp(err, PCSC_FIDO_ERR_MSG_CANCELLED) == 0,
              "stop during a stalled transmit is reported as cancelled");
  expect_true(mock_pcsc_cancel_during_transmit(),
              "stop cancels the transmit in flight");
  keepalives = drain_arg.bytes / sizeof(struct uhid_event);
  expect_true(
      keepalives <= (STOP_STALL_MS / PCSC_FIDO_EXCHANGE_KEEPALIVE_INTERVAL_MS) +
                        STOP_EXTRA_KEEPALIVES,
      "keepalives stay paced at the interval after a stop");
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
}

int main(void) {
  exchange_getinfo_completes();
  exchange_response_too_large_for_buffer();
  exchange_cancelled_by_uhid_packet();
  exchange_uhid_close_cancels();
  exchange_cancel_after_last_poll();
  exchange_close_after_last_poll();
  exchange_init_on_active_channel_resyncs();
  exchange_malformed_init_is_busy();
  exchange_channel_busy_on_ping();
  exchange_drops_other_channel_cancel_and_continuation();
  exchange_thread_start_failure();
  exchange_stop_requested_cancels();
  exchange_stop_waits_without_spinning();
  return failures == 0 ? 0 : 1;
}
