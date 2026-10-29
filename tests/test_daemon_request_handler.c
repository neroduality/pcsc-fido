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
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/daemon_request_handler.h"
#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/exchange_orchestrator.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <errno.h>
#include <linux/uhid.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "pcsc_fido/apdu.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"
#include "scrub_hook.h"

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
  /* A kept session sends just the command; a reset one re-SELECTs first. */
  KEPT_SESSION_TRANSMITS = 1,
  RESET_SESSION_TRANSMITS = 2,
  /* After one overflow evicts slot 1, slot 2 is the next least-recent channel.
   */
  SESSION_OWNER_LRU_SLOT = 2,
  GET_ASSERTION_HEADER_LEN = 5,
  CLIENT_DATA_HASH_LEN = 32,
  GET_ASSERTION_LEN = GET_ASSERTION_HEADER_LEN + CLIENT_DATA_HASH_LEN,
  /* Within the bridge's response cap, one byte over what CTAPHID can frame. */
  UNFRAMEABLE_RESPONSE_LEN = PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1,
  SW_OK_HIGH = 0x90,
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

static pcsc_fido_daemon_channels_t g_channels;

static void bind_test_channel(pcsc_fido_daemon_request_context_t* ctx,
                              uint32_t cid) {
  pcsc_fido_daemon_channels_init(&g_channels);
  expect_true(
      pcsc_fido_daemon_channels_allocate(&g_channels, PCSC_FIDO_NULL) == cid,
      "first allocated channel matches the test CID");
  ctx->channels = &g_channels;
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
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
  mock_pcsc_reset();
  pcsc_fido_bridge_reset();
  pcsc_fido_rate_limit_reset();
}

static void init_valid(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  uint32_t cid = INIT_CMD_NFC;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair init");
  ctx.fd = sv[0];
  bind_test_channel(&ctx, cid);
  scrub_hook_reset();
  pcsc_fido_daemon_handle_hid_request(
      &ctx, U32_ALL_ONES, PCSC_FIDO_HID_CMD_INIT, nonce, sizeof(nonce));
  {
    struct uhid_event ev;
    expect_true(read_uhid_event(sv[1], &ev), "init response event");
    expect_true(ev.type == UHID_INPUT2, "init UHID_INPUT2");
  }
  expect_true(scrub_hook_calls_with_len(PCSC_FIDO_HID_INIT_RESP_LEN) == 1u,
              "INIT response staging buffer scrubbed");
  expect_true(scrub_hook_all_zero(), "INIT scrubs left regions zeroed");
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_WINK,
                                      PCSC_FIDO_NULL, 0u);
  {
    struct uhid_event ev;
    expect_true(
        read_uhid_event(sv[1], &ev) &&
            ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] ==
                (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_WINK),
        "WINK answered with an empty WINK response");
  }
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_LOCK,
                                      PCSC_FIDO_NULL, 0u);
  {
    struct uhid_event ev;
    expect_true(
        read_uhid_event(sv[1], &ev) &&
            ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] ==
                (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_ERROR) &&
            ev.u.input2.data[PCSC_FIDO_HID_OFF_INIT_DATA] ==
                PCSC_FIDO_DAEMON_ERR_INVALID_CMD,
        "unimplemented LOCK is rejected with ERR_INVALID_CMD");
  }
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
  scrub_hook_reset();
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
  /* The handler's assembled-response buffer is exactly PENDING_MAX bytes; the
   * exchange job scrub is larger and the HID packet / UHID event smaller. */
  expect_true(scrub_hook_calls_with_len(PCSC_FIDO_DAEMON_PENDING_MAX) == 1u,
              "handler response staging buffer scrubbed");
  expect_true(scrub_hook_all_zero(), "handler scrubs left regions zeroed");
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
  bind_test_channel(&ctx, cid);
  scrub_hook_reset();
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  stop_socket_drain(sv[0], sv[1], drain_thread);
  expect_true(scrub_hook_calls_with_len(PCSC_FIDO_DAEMON_PENDING_MAX) == 1u,
              "handler response buffer scrubbed on bridge failure");
  expect_true(
      scrub_hook_calls_with_len(pcsc_fido_daemon_exchange_job_size()) == 1u,
      "exchange job scrubbed on bridge failure (exact struct length)");
  expect_true(scrub_hook_all_zero(),
              "bridge-failure scrubs left regions zeroed");
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
  bind_test_channel(&ctx, cid);
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
  bind_test_channel(&ctx, cid);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  (void)pthread_join(inject_thread, PCSC_FIDO_NULL);
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

/* Sends INIT on `request_cid` and returns the channel ID from the reply, or 0
 * if the reply was an error. */
static uint32_t send_init(const pcsc_fido_daemon_request_context_t* ctx,
                          int peer_fd, uint32_t request_cid) {
  const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  struct uhid_event ev;
  pcsc_fido_daemon_handle_hid_request(ctx, request_cid, PCSC_FIDO_HID_CMD_INIT,
                                      nonce, sizeof(nonce));
  if (!read_uhid_event(peer_fd, &ev) ||
      ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] !=
          (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_INIT)) {
    return 0u;
  }
  expect_true(pcsc_fido_daemon_hid_packet_cid(ev.u.input2.data) == request_cid,
              "INIT reply is sent on the requesting channel");
  return pcsc_fido_daemon_hid_packet_cid(ev.u.input2.data +
                                         PCSC_FIDO_HID_OFF_INIT_DATA +
                                         PCSC_FIDO_HID_INIT_NONCE_LEN);
}

static bool reply_is_error(int peer_fd, uint32_t cid, uint8_t code) {
  struct uhid_event ev;
  return read_uhid_event(peer_fd, &ev) &&
         pcsc_fido_daemon_hid_packet_cid(ev.u.input2.data) == cid &&
         ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] ==
             (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_ERROR) &&
         ev.u.input2.data[PCSC_FIDO_HID_OFF_INIT_DATA] == code;
}

static void channel_ids_are_per_client(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t ping[] = {0xAAu};
  uint32_t cid_a;
  uint32_t cid_b;
  handler_setup();
  expect_true(uhid_pair(sv) == 0, "socketpair channels");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid_a = send_init(&ctx, sv[1], U32_ALL_ONES);
  cid_b = send_init(&ctx, sv[1], U32_ALL_ONES);
  expect_true(cid_a != 0u && cid_a != U32_ALL_ONES, "first channel is valid");
  expect_true(cid_b != 0u && cid_b != U32_ALL_ONES, "second channel is valid");
  expect_true(cid_a != cid_b, "each broadcast INIT allocates its own channel");
  expect_true(send_init(&ctx, sv[1], cid_a) == cid_a,
              "INIT on a live channel resynchronizes it and keeps its ID");
  expect_true(send_init(&ctx, sv[1], TEST_CID) == 0u &&
                  !pcsc_fido_daemon_channels_touch(&channels, TEST_CID),
              "INIT on an unknown channel does not allocate it");
  pcsc_fido_daemon_handle_hid_request(&ctx, TEST_CID, PCSC_FIDO_HID_CMD_PING,
                                      ping, sizeof(ping));
  expect_true(
      reply_is_error(sv[1], TEST_CID, PCSC_FIDO_DAEMON_ERR_INVALID_CHANNEL),
      "a request on an unknown channel gets ERR_INVALID_CHANNEL");
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_b, PCSC_FIDO_HID_CMD_PING, ping,
                                      sizeof(ping));
  {
    struct uhid_event ev;
    expect_true(
        read_uhid_event(sv[1], &ev) &&
            pcsc_fido_daemon_hid_packet_cid(ev.u.input2.data) == cid_b &&
            ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] ==
                (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_PING),
        "PING on the second channel is answered on that channel");
  }
  close(sv[0]);
  close(sv[1]);
}

static void channel_table_evicts_least_recently_used(void) {
  pcsc_fido_daemon_channels_t channels;
  uint32_t cids[PCSC_FIDO_DAEMON_CHANNEL_SLOTS];
  uint32_t extra;
  pcsc_fido_daemon_channels_init(&channels);
  for (unsigned i = 0u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    cids[i] = pcsc_fido_daemon_channels_allocate(&channels, PCSC_FIDO_NULL);
  }
  expect_true(pcsc_fido_daemon_channels_touch(&channels, cids[0]),
              "oldest channel is live before the table overflows");
  extra = pcsc_fido_daemon_channels_allocate(&channels, PCSC_FIDO_NULL);
  expect_true(pcsc_fido_daemon_channels_touch(&channels, extra),
              "a channel allocated into a full table is live");
  expect_true(pcsc_fido_daemon_channels_touch(&channels, cids[0]),
              "a recently used channel survives eviction");
  expect_true(!pcsc_fido_daemon_channels_touch(&channels, cids[1]),
              "the least recently used channel is evicted");
  channels.session_owner = cids[SESSION_OWNER_LRU_SLOT];
  channels.next_assertions_left = TEST_LIT_2U;
  {
    bool session_dropped = false;
    extra = pcsc_fido_daemon_channels_allocate(&channels, &session_dropped);
    expect_true(session_dropped && channels.session_owner == 0u &&
                    channels.next_assertions_left == 0u,
                "evicting the session owner clears its getNextAssertion quota");
    expect_true(pcsc_fido_daemon_channels_touch(&channels, extra),
                "the channel that replaced the session owner is live");
    expect_true(!pcsc_fido_daemon_channels_touch(&channels,
                                                 cids[SESSION_OWNER_LRU_SLOT]),
                "the session owner was the least recently used channel");
  }
  channels.next_cid = U32_ALL_ONES;
  extra = pcsc_fido_daemon_channels_allocate(&channels, PCSC_FIDO_NULL);
  expect_true(extra != U32_ALL_ONES && extra != 0u,
              "allocation skips the broadcast and zero channel IDs");
}

static void cancel_is_scoped_to_session_owner(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  uint32_t cid_a;
  uint32_t cid_b;
  unsigned before;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair cancel owner");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid_a = send_init(&ctx, sv[1], U32_ALL_ONES);
  cid_b = send_init(&ctx, sv[1], U32_ALL_ONES);
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_a, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  before = mock_pcsc_transmit_call_count();
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_b, PCSC_FIDO_HID_CMD_CANCEL,
                                      PCSC_FIDO_NULL, 0u);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_a, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  expect_true(
      mock_pcsc_transmit_call_count() - before == KEPT_SESSION_TRANSMITS,
      "another client's CANCEL keeps the PC/SC session");
  before = mock_pcsc_transmit_call_count();
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_a, PCSC_FIDO_HID_CMD_CANCEL,
                                      PCSC_FIDO_NULL, 0u);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_a, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  expect_true(
      mock_pcsc_transmit_call_count() - before == RESET_SESSION_TRANSMITS,
      "the session owner's CANCEL resets the PC/SC session");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void unframeable_response_gets_error(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  static uint8_t card_resp[UNFRAMEABLE_RESPONSE_LEN + PCSC_FIDO_SW_LEN];
  struct uhid_event ev;
  bool got_error = false;
  uint32_t cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  pcsc_fido_zero_bytes(card_resp, sizeof(card_resp));
  card_resp[UNFRAMEABLE_RESPONSE_LEN] = (uint8_t)SW_OK_HIGH;
  mock_pcsc_set_transmit_response(card_resp, sizeof(card_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair unframeable response");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  while (!got_error &&
         recv(sv[1], &ev, sizeof(ev), MSG_DONTWAIT) == (ssize_t)sizeof(ev)) {
    got_error =
        pcsc_fido_daemon_hid_packet_cid(ev.u.input2.data) == cid &&
        ev.u.input2.data[PCSC_FIDO_HID_OFF_CMD] ==
            (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_ERROR) &&
        ev.u.input2.data[PCSC_FIDO_HID_OFF_INIT_DATA] ==
            PCSC_FIDO_DAEMON_ERR_OTHER;
  }
  expect_true(got_error,
              "a card response too large to frame is answered with ERR_OTHER");
  close(sv[0]);
  close(sv[1]);
}

/* Card transmits one CBOR request took: 1 on a kept session, 2 (SELECT +
 * command) on a reset one. */
static unsigned cbor_transmits(const pcsc_fido_daemon_request_context_t* ctx,
                               uint32_t cid, const uint8_t* payload,
                               size_t payload_len) {
  const unsigned before = mock_pcsc_transmit_call_count();
  pcsc_fido_daemon_handle_hid_request(ctx, cid, PCSC_FIDO_HID_CMD_CBOR, payload,
                                      payload_len);
  return mock_pcsc_transmit_call_count() - before;
}

static void short_requests_get_invalid_len(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t short_msg[] = {0x00u, 0x01u, 0x00u};
  uint32_t cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  expect_true(uhid_pair(sv) == 0, "socketpair short requests");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  expect_true(cbor_transmits(&ctx, cid, PCSC_FIDO_NULL, 0u) == 0u,
              "an empty CBOR request never reaches the card");
  expect_true(reply_is_error(sv[1], cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN),
              "an empty CBOR request gets ERR_INVALID_LEN");
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_MSG,
                                      short_msg, sizeof(short_msg));
  expect_true(reply_is_error(sv[1], cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN),
              "a U2F MSG shorter than an APDU header gets ERR_INVALID_LEN");
  close(sv[0]);
  close(sv[1]);
}

/* getAssertion with a real (non-empty) clientDataHash, i.e. not a probe. */
static void build_get_assertion(uint8_t request[GET_ASSERTION_LEN]) {
  static const uint8_t GET_ASSERTION_HEADER[GET_ASSERTION_HEADER_LEN] = {
      0x02u, 0xA1u, 0x02u, 0x58u, 0x20u};
  (void)pcsc_fido_copy_bytes(request, GET_ASSERTION_LEN, 0u,
                             GET_ASSERTION_HEADER,
                             sizeof(GET_ASSERTION_HEADER));
  pcsc_fido_fill_bytes(request + GET_ASSERTION_HEADER_LEN, CLIENT_DATA_HASH_LEN,
                       (uint8_t)TEST_LIT_0XAAU);
}

static void rate_limit_keeps_owner(
    const pcsc_fido_daemon_request_context_t* ctx, uint32_t cid_a,
    uint32_t cid_b, const uint8_t* get_assertion, const uint8_t* get_next,
    size_t get_next_len, const uint8_t* get_info, size_t get_info_len,
    const uint8_t* three_credentials, size_t three_len) {
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  pcsc_fido_rate_limit_reset();
  mock_pcsc_set_transmit_response(three_credentials, three_len);
  (void)cbor_transmits(ctx, cid_a, get_assertion, GET_ASSERTION_LEN);
  expect_true(ctx->channels->next_assertions_left == TEST_LIT_2U,
              "the rate-limited sequence starts with two follow-ups");
  expect_true(cbor_transmits(ctx, cid_a, get_next, get_next_len) == 0u,
              "a rate-limited getNextAssertion never reaches the card");
  expect_true(ctx->channels->next_assertions_left == TEST_LIT_2U &&
                  ctx->channels->session_owner == cid_a,
              "a rate-limited exchange keeps the getNextAssertion quota");
  expect_true(cbor_transmits(ctx, cid_b, get_info, get_info_len) == 0u,
              "a refused command from another channel never reaches the card");
  expect_true(ctx->channels->next_assertions_left == TEST_LIT_2U &&
                  ctx->channels->session_owner == cid_a,
              "a refused command does not take the session or its quota");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
  pcsc_fido_rate_limit_reset();
  expect_true(cbor_transmits(ctx, cid_a, get_next, get_next_len) ==
                  KEPT_SESSION_TRANSMITS,
              "the kept quota still runs on the original session");

  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  pcsc_fido_rate_limit_reset();
  (void)cbor_transmits(ctx, cid_a, get_info, get_info_len);
  expect_true(ctx->channels->session_owner == cid_a,
              "the channel that reached the card owns the session");
  expect_true(cbor_transmits(ctx, cid_b, get_info, get_info_len) == 0u,
              "a refused command does not run");
  expect_true(ctx->channels->session_owner == cid_a,
              "a refused command does not become the session owner");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
  pcsc_fido_rate_limit_reset();
  expect_true(cbor_transmits(ctx, cid_a, get_info, get_info_len) ==
                  KEPT_SESSION_TRANSMITS,
              "the session owner still has the card after the refusal");
}

static void get_next_assertion_keeps_session(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  uint8_t get_assertion[GET_ASSERTION_LEN];
  const uint8_t get_next[] = {0x08u};
  const uint8_t get_info[] = {0x04u};
  /* OK, {numberOfCredentials (0x05): 3} */
  const uint8_t three_credentials[] = {0x00u, 0xA1u, 0x05u,
                                       0x03u, 0x90u, 0x00u};
  const uint8_t one_credential[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  uint32_t cid_a;
  uint32_t cid_b;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  build_get_assertion(get_assertion);
  expect_true(uhid_pair(sv) == 0, "socketpair getNextAssertion");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid_a = send_init(&ctx, sv[1], U32_ALL_ONES);
  cid_b = send_init(&ctx, sv[1], U32_ALL_ONES);
  start_socket_drain(sv[1], &drain_thread, &drain_arg);

  mock_pcsc_set_transmit_response(one_credential, sizeof(one_credential));
  (void)cbor_transmits(&ctx, cid_a, get_assertion, sizeof(get_assertion));
  expect_true(cbor_transmits(&ctx, cid_a, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "a single-credential getAssertion resets the session");

  mock_pcsc_set_transmit_response(three_credentials, sizeof(three_credentials));
  (void)cbor_transmits(&ctx, cid_a, get_assertion, sizeof(get_assertion));
  expect_true(channels.next_assertions_left == TEST_LIT_2U,
              "three credentials leave two getNextAssertion calls");
  expect_true(cbor_transmits(&ctx, cid_a, get_next, sizeof(get_next)) ==
                  KEPT_SESSION_TRANSMITS,
              "getNextAssertion runs on the getAssertion's session");
  expect_true(cbor_transmits(&ctx, cid_a, get_next, sizeof(get_next)) ==
                  KEPT_SESSION_TRANSMITS,
              "the last getNextAssertion runs on that session too");
  expect_true(
      channels.next_assertions_left == 0u && channels.session_owner == 0u,
      "the last getNextAssertion ends the operation");
  expect_true(cbor_transmits(&ctx, cid_a, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the session is reset after the last getNextAssertion");

  (void)cbor_transmits(&ctx, cid_a, get_assertion, sizeof(get_assertion));
  expect_true(cbor_transmits(&ctx, cid_a, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "another command abandons the sequence on a fresh session");
  expect_true(channels.next_assertions_left == 0u,
              "an abandoned sequence is forgotten");

  (void)cbor_transmits(&ctx, cid_a, get_assertion, sizeof(get_assertion));
  expect_true(cbor_transmits(&ctx, cid_b, get_next, sizeof(get_next)) ==
                  RESET_SESSION_TRANSMITS,
              "another client cannot continue the getNextAssertion sequence");

  mock_pcsc_set_transmit_response(three_credentials, sizeof(three_credentials));
  (void)cbor_transmits(&ctx, cid_a, get_assertion, sizeof(get_assertion));
  expect_true(channels.next_assertions_left == TEST_LIT_2U,
              "a fresh three-credential getAssertion re-arms the quota");
  mock_pcsc_set_transmit_fail(true);
  (void)cbor_transmits(&ctx, cid_a, get_next, sizeof(get_next));
  expect_true(
      channels.next_assertions_left == 0u && channels.session_owner == 0u,
      "a failed getNextAssertion drops the sequence");
  mock_pcsc_set_transmit_fail(false);
  mock_pcsc_set_transmit_response(one_credential, sizeof(one_credential));
  expect_true(cbor_transmits(&ctx, cid_a, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the next request after a failed exchange reconnects");

  rate_limit_keeps_owner(&ctx, cid_a, cid_b, get_assertion, get_next,
                         sizeof(get_next), get_info, sizeof(get_info),
                         three_credentials, sizeof(three_credentials));
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void evicting_session_owner_resets_card(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  uint8_t get_assertion[GET_ASSERTION_LEN];
  const uint8_t ping[] = {(uint8_t)TEST_LIT_0XAAU};
  const uint8_t three_credentials[] = {0x00u, 0xA1u, 0x05u,
                                       0x03u, 0x90u, 0x00u};
  const uint8_t get_info[] = {0x04u};
  const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint32_t cids[PCSC_FIDO_DAEMON_CHANNEL_SLOTS];
  uint32_t replacement = 0u;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  build_get_assertion(get_assertion);
  expect_true(uhid_pair(sv) == 0, "socketpair eviction reset");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  for (unsigned i = 0u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    cids[i] = send_init(&ctx, sv[1], U32_ALL_ONES);
    expect_true(cids[i] != 0u, "broadcast INIT allocates a channel");
  }
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  mock_pcsc_set_transmit_response(three_credentials, sizeof(three_credentials));
  (void)cbor_transmits(&ctx, cids[0], get_assertion, sizeof(get_assertion));
  for (unsigned i = 1u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    pcsc_fido_daemon_handle_hid_request(&ctx, cids[i], PCSC_FIDO_HID_CMD_PING,
                                        ping, sizeof(ping));
  }
  pcsc_fido_daemon_handle_hid_request(
      &ctx, U32_ALL_ONES, PCSC_FIDO_HID_CMD_INIT, nonce, sizeof(nonce));
  expect_true(!pcsc_fido_daemon_channels_touch(&channels, cids[0]),
              "the session owner was the channel evicted by the new INIT");
  expect_true(
      channels.session_owner == 0u && channels.next_assertions_left == 0u,
      "evicting the session owner drops its getNextAssertion sequence");
  for (unsigned i = 0u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    bool known = false;
    for (unsigned j = 1u; j < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; j++) {
      if (channels.cids[i] == cids[j]) {
        known = true;
      }
    }
    if (!known) {
      replacement = channels.cids[i];
    }
  }
  expect_true(cbor_transmits(&ctx, replacement, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the next request after eviction reconnects to the card");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void queue_uhid_event(int fd, const struct uhid_event* ev,
                             const char* what) {
  expect_true(write(fd, ev, sizeof(*ev)) == (ssize_t)sizeof(*ev), what);
}

static void uhid_close_during_exchange_releases_session(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  struct uhid_event ev;
  const uint8_t get_info[] = {0x04u};
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  uint32_t cid;
  uint32_t closed_cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair close during exchange");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_CLOSE;
  queue_uhid_event(sv[1], &ev, "queue UHID_CLOSE");
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  expect_true(channels.session_owner == 0u,
              "a closed client no longer owns the PC/SC session");
  (void)shutdown(sv[0], SHUT_WR);
  expect_true(!read_uhid_event(sv[1], &ev),
              "a closed client gets neither a response nor keepalives");
  close(sv[0]);
  close(sv[1]);
  expect_true(uhid_pair(sv) == 0, "socketpair after close");
  ctx.fd = sv[0];
  closed_cid = cid;
  expect_true(!pcsc_fido_daemon_channels_touch(&channels, closed_cid),
              "a closed client loses its channel ID");
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  expect_true(cid != 0u && cid != closed_cid,
              "the next client gets a new channel ID from INIT");
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(
      cbor_transmits(&ctx, closed_cid, get_info, sizeof(get_info)) == 0u,
      "the closed channel ID does not reach the card");
  expect_true(cbor_transmits(&ctx, cid, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the next client after a close starts on a fresh session");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void init_on_busy_channel_resyncs(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  struct uhid_event ev;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  const uint8_t nonce[PCSC_FIDO_HID_INIT_NONCE_LEN] = {
      0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};
  const uint8_t get_info[] = {0x04u};
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  const uint8_t* reply;
  uint32_t cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(uhid_pair(sv) == 0, "socketpair resync");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  expect_true(pcsc_fido_hid_encode_init_packet(cid, PCSC_FIDO_HID_CMD_INIT,
                                               nonce, sizeof(nonce), packet),
              "encode resync INIT");
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_OUTPUT;
  ev.u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  (void)pcsc_fido_copy_bytes(ev.u.output.data, sizeof(ev.u.output.data), 0u,
                             packet, sizeof(packet));
  queue_uhid_event(sv[1], &ev, "queue resync INIT");
  pcsc_fido_daemon_handle_hid_request(&ctx, cid, PCSC_FIDO_HID_CMD_CBOR,
                                      get_info, sizeof(get_info));
  expect_true(read_uhid_event(sv[1], &ev) && ev.type == UHID_INPUT2,
              "the resync is answered");
  reply = ev.u.input2.data;
  expect_true(
      pcsc_fido_daemon_hid_packet_cid(reply) == cid &&
          reply[PCSC_FIDO_HID_OFF_CMD] ==
              (uint8_t)(PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_INIT) &&
          memcmp(reply + PCSC_FIDO_HID_OFF_INIT_DATA, nonce, sizeof(nonce)) ==
              0 &&
          pcsc_fido_daemon_hid_packet_cid(reply + PCSC_FIDO_HID_OFF_INIT_DATA +
                                          PCSC_FIDO_HID_INIT_NONCE_LEN) == cid,
      "INIT on the busy channel is answered, keeping the channel ID");
  (void)shutdown(sv[0], SHUT_WR);
  expect_true(!read_uhid_event(sv[1], &ev),
              "the abandoned request itself gets no response");
  expect_true(channels.session_owner == 0u,
              "the resync releases the PC/SC session");
  close(sv[0]);
  close(sv[1]);
}

static void other_channel_starts_a_fresh_session(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  uint32_t cid_a;
  uint32_t cid_b;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  expect_true(uhid_pair(sv) == 0, "socketpair other channel");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid_a = send_init(&ctx, sv[1], U32_ALL_ONES);
  cid_b = send_init(&ctx, sv[1], U32_ALL_ONES);
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(cbor_transmits(&ctx, cid_a, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the first command opens a session");
  expect_true(channels.session_owner == cid_a,
              "the channel that opened the session owns it");
  expect_true(cbor_transmits(&ctx, cid_b, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "another channel starts on a fresh session");
  expect_true(channels.session_owner == cid_b,
              "the channel that ran the command owns the session");
  pcsc_fido_daemon_handle_hid_request(&ctx, cid_a, PCSC_FIDO_HID_CMD_CANCEL,
                                      PCSC_FIDO_NULL, 0u);
  expect_true(channels.session_owner == cid_b,
              "the previous owner's CANCEL does not take the session");
  expect_true(cbor_transmits(&ctx, cid_b, get_info, sizeof(get_info)) ==
                  KEPT_SESSION_TRANSMITS,
              "the previous owner's CANCEL leaves the card connected");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void credential_count_is_capped(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  uint8_t get_assertion[GET_ASSERTION_LEN];
  /* OK, map {numberOfCredentials (0x05): 100}. */
  const uint8_t over_cap[] = {0x00u, 0xA1u, 0x05u, 0x18u, 0x64u, 0x90u, 0x00u};
  /* OK, map {numberOfCredentials: 2^64-1}. */
  const uint8_t max_count[] = {0x00u, 0xA1u, 0x05u, 0x1Bu, 0xFFu, 0xFFu, 0xFFu,
                               0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x90u, 0x00u};
  uint32_t cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  build_get_assertion(get_assertion);
  expect_true(uhid_pair(sv) == 0, "socketpair credential cap");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  mock_pcsc_set_transmit_response(over_cap, sizeof(over_cap));
  (void)cbor_transmits(&ctx, cid, get_assertion, sizeof(get_assertion));
  expect_true(
      channels.next_assertions_left == PCSC_FIDO_DAEMON_MAX_NEXT_ASSERTIONS,
      "a credential count above the cap is stored as the cap");
  mock_pcsc_set_transmit_response(max_count, sizeof(max_count));
  (void)cbor_transmits(&ctx, cid, get_assertion, sizeof(get_assertion));
  expect_true(
      channels.next_assertions_left == PCSC_FIDO_DAEMON_MAX_NEXT_ASSERTIONS,
      "the largest CBOR credential count is stored as the cap");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void idle_session_is_dropped(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pthread_t drain_thread;
  socket_drain_arg_t drain_arg;
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  const uint8_t get_info[] = {0x04u};
  uint32_t cid;
  time_t frozen;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  expect_true(uhid_pair(sv) == 0, "socketpair idle session");
  pcsc_fido_daemon_channels_init(&channels);
  frozen = g_fake_time;
  expect_true(pcsc_fido_daemon_channels_poll_timeout_ms(&channels, 0) == 0 &&
                  g_fake_time == frozen,
              "no held session and a zero cap do not read the clock");
  expect_true(pcsc_fido_daemon_channels_poll_timeout_ms(
                  &channels, PCSC_FIDO_UHID_POLL_TIMEOUT_MS) ==
                      PCSC_FIDO_UHID_POLL_TIMEOUT_MS &&
                  g_fake_time == frozen,
              "no held session leaves the poll cap unchanged");
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  start_socket_drain(sv[1], &drain_thread, &drain_arg);
  expect_true(cbor_transmits(&ctx, cid, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "getInfo opens a session");
  expect_true(channels.session_owner == cid && channels.session_deadline != 0,
              "a kept session has an idle deadline");
  expect_true(!pcsc_fido_daemon_channels_expire_session(&channels),
              "the session is not idle yet");
  expect_true(pcsc_fido_daemon_channels_poll_timeout_ms(
                  &channels, PCSC_FIDO_UHID_POLL_TIMEOUT_MS) ==
                  PCSC_FIDO_UHID_POLL_TIMEOUT_MS,
              "a live session does not stretch the poll wait");
  g_fake_time = channels.session_deadline - 1;
  expect_true(pcsc_fido_daemon_channels_expire_session(&channels),
              "the idle deadline drops the session");
  pcsc_fido_bridge_reset();
  expect_true(channels.session_owner == 0u &&
                  channels.next_assertions_left == 0u &&
                  channels.session_deadline == 0,
              "an idle session forgets its owner and quota");
  expect_true(cbor_transmits(&ctx, cid, get_info, sizeof(get_info)) ==
                  RESET_SESSION_TRANSMITS,
              "the next command after idle reconnects to the card");
  stop_socket_drain(sv[0], sv[1], drain_thread);
}

static void discard_queued_events(int peer_fd) {
  struct uhid_event ev;
  ssize_t got;
  do {
    got = recv(peer_fd, &ev, sizeof(ev), MSG_DONTWAIT);
  } while (got == (ssize_t)sizeof(ev));
}

static void worker_start_failure_keeps_session(void) {
  int sv[SOCKET_PAIR_FD_COUNT];
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t ctx;
  uint8_t get_assertion[GET_ASSERTION_LEN];
  const uint8_t get_next[] = {0x08u};
  /* OK, {numberOfCredentials (0x05): 3} */
  const uint8_t three_credentials[] = {0x00u, 0xA1u, 0x05u,
                                       0x03u, 0x90u, 0x00u};
  uint32_t cid;
  handler_setup();
  mock_pcsc_set_readers("Handler Test Reader 00 00");
  build_get_assertion(get_assertion);
  expect_true(uhid_pair(sv) == 0, "socketpair worker start failure");
  pcsc_fido_daemon_channels_init(&channels);
  ctx.fd = sv[0];
  ctx.channels = &channels;
  cid = send_init(&ctx, sv[1], U32_ALL_ONES);
  mock_pcsc_set_transmit_response(three_credentials, sizeof(three_credentials));
  (void)cbor_transmits(&ctx, cid, get_assertion, sizeof(get_assertion));
  discard_queued_events(sv[1]);
  expect_true(channels.session_owner == cid &&
                  channels.next_assertions_left == TEST_LIT_2U,
              "the getAssertion leaves two getNextAssertion calls");
  atomic_store_explicit(&g_fail_pthread_create, true, memory_order_relaxed);
  expect_true(cbor_transmits(&ctx, cid, get_next, sizeof(get_next)) == 0u,
              "a worker that never starts does not reach the card");
  atomic_store_explicit(&g_fail_pthread_create, false, memory_order_relaxed);
  expect_true(reply_is_error(sv[1], cid, PCSC_FIDO_DAEMON_ERR_OTHER),
              "a worker that never starts is answered ERR_OTHER");
  expect_true(channels.session_owner == cid &&
                  channels.next_assertions_left == TEST_LIT_2U,
              "a worker that never starts keeps the owner and the quota");
  expect_true(cbor_transmits(&ctx, cid, get_next, sizeof(get_next)) ==
                  KEPT_SESSION_TRANSMITS,
              "the retried getNextAssertion runs on the kept session");
  close(sv[0]);
  close(sv[1]);
}

int main(void) {
  channel_ids_are_per_client();
  channel_table_evicts_least_recently_used();
  cancel_is_scoped_to_session_owner();
  unframeable_response_gets_error();
  short_requests_get_invalid_len();
  get_next_assertion_keeps_session();
  other_channel_starts_a_fresh_session();
  credential_count_is_capped();
  idle_session_is_dropped();
  worker_start_failure_keeps_session();
  evicting_session_owner_resets_card();
  uhid_close_during_exchange_releases_session();
  init_on_busy_channel_resyncs();
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
