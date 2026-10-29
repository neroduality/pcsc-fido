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

#include <errno.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_config.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/pcsc_bridge.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"
#include "scrub_hook.h"

enum {
  FAKE_UHID_FD = 121,
  FAKE_TIME_START = 1000000,
  NS_PER_MS = 1000000,
  READS_BEFORE_STOP = 3,
  ALWAYS_MODE_EAGAIN_READ = 1,
  ALWAYS_MODE_REPLY_OUTBOUND = 1,
  TEST_PING_PAYLOAD_BYTE = 0xBBu,
  HID_HDR_N = 0x4Eu,
  HID_HDR_F = 0x46u,
  HID_CID_BYTE_2_OFF = 2,
  HID_HDR_C = 0x43u,
  HID_CID_BYTE_3_OFF = 3,
  HID_CMD_OFF = 4,
  HID_INIT_PKT_FLAG = 0x80u,
  HID_BCNT_HI_OFF = 5,
  HID_BCNT_LO_OFF = 6,
  HID_DATA_OFF = 7,
  HID_DATA_NEXT_OFF = 8,
  UHID_LOOP_ASSIGNED_CID = 0x4E464301u,
  MULTI_FRAME_PING_LEN = 100u,
  BYTE_MASK = 0xFFu,
  SIGNAL_WAKE_POLL_TIMEOUT_MS = 100,
  /* SELECT plus the command, after the session was disconnected. */
  RESET_SESSION_TRANSMITS = 2,
};

static time_t g_fake_time = FAKE_TIME_START;
static int g_read_calls;
static int g_uhid_create_fail;
static int g_poll_eintr_once;
static int g_poll_fail_once;
static int g_poll_hup_once;
static int g_read_io_error_once;
static int g_read_short_once;
static int g_stop_after_reads = READS_BEFORE_STOP;
static unsigned g_uhid_create_count;
static uint8_t g_last_input_init_cmd;
static uint8_t g_last_input_init_data0;
static uint8_t g_ping_payload[] = {TEST_PING_PAYLOAD_BYTE};

extern int __real_poll(struct pollfd* fds, nfds_t nfds, int timeout);
extern ssize_t __real_read(int fd, void* buf, size_t count);
extern ssize_t __real_write(int fd, const void* buf, size_t count);

extern int __real_nanosleep(const struct timespec* req, struct timespec* rem);

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec* req PCSC_FIDO_MAYBE_UNUSED,
                     struct timespec* rem PCSC_FIDO_MAYBE_UNUSED) {
  return __real_nanosleep(
      &(const struct timespec){.tv_sec = 0, .tv_nsec = NS_PER_MS}, rem);
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

ssize_t __wrap_read(int fd, void* buf, size_t count) {
  struct uhid_event* ev;
  if (fd != FAKE_UHID_FD || buf == PCSC_FIDO_NULL ||
      count < sizeof(struct uhid_event)) {
    return __real_read(fd, buf, count);
  }
  if (g_read_io_error_once) {
    g_read_io_error_once = 0;
    errno = EIO;
    return -1;
  }
  if (g_read_short_once) {
    g_read_short_once = 0;
    return 1;
  }
  if (g_read_calls >= g_stop_after_reads) {
    pcsc_fido_daemon_test_request_stop();
    errno = EAGAIN;
    return -1;
  }
  ev = (struct uhid_event*)buf;
  pcsc_fido_zero_bytes(ev, sizeof(*ev));
  g_read_calls++;
  if (g_read_calls == 1) {
    ev->type = UHID_OUTPUT;
    ev->u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
    {
      uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
      pcsc_fido_zero_bytes(packet, sizeof(packet));
      packet[0] = HID_HDR_N;
      packet[1] = HID_HDR_F;
      packet[HID_CID_BYTE_2_OFF] = HID_HDR_C;
      packet[HID_CID_BYTE_3_OFF] = 0x01u;
      packet[HID_CMD_OFF] =
          (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_PING);
      packet[HID_DATA_OFF] = (uint8_t)sizeof(g_ping_payload);
      packet[HID_DATA_NEXT_OFF] = g_ping_payload[0];
      (void)pcsc_fido_copy_bytes(ev->u.output.data, sizeof(packet), 0u, packet,
                                 sizeof(packet));
    }
    return (ssize_t)sizeof(*ev);
  }
  ev->type = UHID_CLOSE;
  return (ssize_t)sizeof(*ev);
}

ssize_t __wrap_write(int fd, const void* buf, size_t count) {
  if (fd == FAKE_UHID_FD && buf != PCSC_FIDO_NULL &&
      count >= sizeof(struct uhid_event)) {
    const struct uhid_event* ev = (const struct uhid_event*)buf;
    if (ev->type == UHID_CREATE2) {
      g_uhid_create_count++;
      if (g_uhid_create_fail) {
        errno = EIO;
        return -1;
      }
    }
    if (ev->type == UHID_INPUT2 &&
        (ev->u.input2.data[HID_CMD_OFF] & HID_INIT_PKT_FLAG) != 0u) {
      g_last_input_init_cmd = ev->u.input2.data[HID_CMD_OFF];
      g_last_input_init_data0 = ev->u.input2.data[HID_DATA_OFF];
    }
    return (ssize_t)count;
  }
  return __real_write(fd, buf, count);
}

int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout) {
  nfds_t i;
  (void)timeout;
  if (g_poll_fail_once) {
    g_poll_fail_once = 0;
    errno = EIO;
    return -1;
  }
  if (g_poll_eintr_once) {
    g_poll_eintr_once = 0;
    errno = EINTR;
    return -1;
  }
  if (pcsc_fido_daemon_stop_requested()) {
    return 0;
  }
  if (fds == PCSC_FIDO_NULL || nfds == 0u) {
    return 0;
  }
  for (i = 0u; i < nfds; i++) {
    fds[i].revents = 0;
  }
  for (i = 0u; i < nfds; i++) {
    if (fds[i].fd == FAKE_UHID_FD) {
      if (g_poll_hup_once) {
        g_poll_hup_once = 0;
        fds[i].revents = POLLHUP;
      } else {
        fds[i].revents = POLLIN;
      }
      return 1;
    }
  }
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

static void reset_uhid_loop_state(void) {
  g_fake_time = FAKE_TIME_START;
  g_read_calls = 0;
  g_uhid_create_fail = 0;
  g_poll_eintr_once = 0;
  g_poll_fail_once = 0;
  g_poll_hup_once = 0;
  g_read_io_error_once = 0;
  g_read_short_once = 0;
  g_stop_after_reads = READS_BEFORE_STOP;
  g_uhid_create_count = 0;
  g_last_input_init_cmd = 0u;
  g_last_input_init_data0 = 0u;
  unsetenv("PCSC_FIDO_RATE_LIMIT");
  unsetenv("PCSC_FIDO_RATE_WINDOW_SEC");
  unsetenv("PCSC_FIDO_RATE_CTAPHID");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
  pcsc_fido_rate_limit_reset();
  pcsc_fido_bridge_reset();
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup");
}

static void build_ping_output(struct uhid_event* ev) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  pcsc_fido_zero_bytes(ev, sizeof(*ev));
  ev->type = UHID_OUTPUT;
  ev->u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  pcsc_fido_zero_bytes(packet, sizeof(packet));
  packet[0] = HID_HDR_N;
  packet[1] = HID_HDR_F;
  packet[HID_CID_BYTE_2_OFF] = HID_HDR_C;
  packet[HID_CID_BYTE_3_OFF] = 0x01u;
  packet[HID_CMD_OFF] = (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_PING);
  packet[HID_DATA_OFF] = (uint8_t)sizeof(g_ping_payload);
  packet[HID_DATA_NEXT_OFF] = g_ping_payload[0];
  (void)pcsc_fido_copy_bytes(ev->u.output.data, sizeof(packet), 0u, packet,
                             sizeof(packet));
}

static void handle_uhid_event_null_guards(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, PCSC_FIDO_NULL, &pending,
                                     &ctx);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, PCSC_FIDO_NULL, &ctx);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending,
                                     PCSC_FIDO_NULL);
}

static void handle_uhid_event_rate_limited(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  reset_uhid_loop_state();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "second CTAPHID frame blocked");
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  pcsc_fido_daemon_signals_shutdown();
}

static void handle_uhid_event_rate_limit_charges_requests_not_frames(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  reset_uhid_loop_state();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  build_ping_output(&ev);
  ev.u.output.data[HID_BCNT_LO_OFF] = (uint8_t)MULTI_FRAME_PING_LEN;
  pcsc_fido_fill_bytes(ev.u.output.data + HID_DATA_OFF,
                       PCSC_FIDO_HID_INIT_PAYLOAD_MAX, TEST_PING_PAYLOAD_BYTE);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  ev.u.output.data[HID_CMD_OFF] = 0u;
  pcsc_fido_fill_bytes(ev.u.output.data + PCSC_FIDO_HID_OFF_CONT_DATA,
                       PCSC_FIDO_HID_CONT_PAYLOAD_MAX, TEST_PING_PAYLOAD_BYTE);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(g_last_input_init_cmd ==
                  (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_PING),
              "continuation frame is not charged against the request budget");
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "the request consumed exactly one budget unit");
  pcsc_fido_daemon_signals_shutdown();
}

static void rate_limited_init_abandons_partial_request(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  reset_uhid_loop_state();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  build_ping_output(&ev);
  ev.u.output.data[HID_BCNT_LO_OFF] = (uint8_t)MULTI_FRAME_PING_LEN;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(pending.active, "the first frame opens a multi-frame request");
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(!pending.active,
              "a refused INIT abandons the channel's partial request");
  pcsc_fido_daemon_signals_shutdown();
}

static void rate_limited_cancel_gets_no_reply(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  unsigned before;
  reset_uhid_loop_state();
  /* Wider than the clock reads a session check adds, so those reads cannot
   * refill the one-request bucket before the following ping. */
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "1000000", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  mock_pcsc_reset();
  mock_pcsc_set_readers("UHID Loop Reader 00 00");
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  expect_true(pcsc_fido_bridge_exchange(PCSC_FIDO_NULL, PCSC_FIDO_HID_CMD_CBOR,
                                        get_info, sizeof(get_info), response,
                                        sizeof(response), &response_len, err,
                                        sizeof(err)),
              "bridge session primed before the request budget is spent");
  bind_test_channel(&ctx, cid);
  pcsc_fido_daemon_channels_hold_session(ctx.channels, cid);
  expect_true(ctx.channels->session_owner == cid,
              "the primed session has an owner");
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  g_last_input_init_cmd = 0u;
  ev.u.output.data[HID_CMD_OFF] =
      (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_CANCEL);
  ev.u.output.data[HID_BCNT_LO_OFF] = 0u;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(g_last_input_init_cmd == 0u,
              "a rate-limited CANCEL gets no CHANNEL_BUSY reply");
  expect_true(ctx.channels->session_owner == 0u,
              "the owner's CANCEL still clears the session");
  before = mock_pcsc_transmit_call_count();
  expect_true(pcsc_fido_bridge_exchange(PCSC_FIDO_NULL, PCSC_FIDO_HID_CMD_CBOR,
                                        get_info, sizeof(get_info), response,
                                        sizeof(response), &response_len, err,
                                        sizeof(err)),
              "the card accepts a command after the owner's CANCEL");
  expect_true(
      mock_pcsc_transmit_call_count() - before == RESET_SESSION_TRANSMITS,
      "the owner's CANCEL disconnected the card");
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(g_last_input_init_cmd ==
                      (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_ERROR) &&
                  g_last_input_init_data0 == PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY,
              "a rate-limited new request still gets CHANNEL_BUSY");
  pcsc_fido_daemon_signals_shutdown();
}

static void bridge_reset_keeps_rate_limit_budget(void) {
  reset_uhid_loop_state();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_rate_limit_allow_ctaphid(), "first request allowed");
  expect_true(pcsc_fido_rate_limit_allow_exchange(), "first exchange allowed");
  pcsc_fido_bridge_reset();
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(),
              "bridge reset does not refill the request budget");
  expect_true(!pcsc_fido_rate_limit_allow_exchange(),
              "bridge reset does not refill the exchange budget");
  pcsc_fido_daemon_signals_shutdown();
}

static void handle_uhid_event_assembly_error(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  reset_uhid_loop_state();
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  build_ping_output(&ev);
  ev.u.output.data[HID_CMD_OFF] =
      (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_CBOR);
  ev.u.output.data[HID_BCNT_HI_OFF] = BYTE_MASK;
  ev.u.output.data[HID_BCNT_LO_OFF] = BYTE_MASK;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  pcsc_fido_daemon_signals_shutdown();
}

static void handle_uhid_event_close_resets_bridge(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[TEST_CAP_128];
  size_t response_len = 0u;
  char err[TEST_CAP_256];
  reset_uhid_loop_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("UHID Loop Reader 00 00");
  pcsc_fido_zero_bytes(&pending, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(pcsc_fido_bridge_exchange(PCSC_FIDO_NULL, PCSC_FIDO_HID_CMD_CBOR,
                                        get_info, sizeof(get_info), response,
                                        sizeof(response), &response_len, err,
                                        sizeof(err)),
              "bridge session primed");
  pcsc_fido_zero_bytes(&ev, sizeof(ev));
  ev.type = UHID_CLOSE;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(!pcsc_fido_daemon_channels_touch(ctx.channels, cid),
              "UHID close drops the client's channel ID");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_null_returns_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(
      pcsc_fido_daemon_poll_uhid_event(PCSC_FIDO_NULL, &pending, &ctx) == -1,
      "null poll ctx rejected");
  expect_true(
      pcsc_fido_daemon_poll_uhid_event(&poll_ctx, PCSC_FIDO_NULL, &ctx) == -1,
      "null pending rejected");
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending,
                                               PCSC_FIDO_NULL) == -1,
              "null request ctx rejected");
}

static void poll_uhid_event_stop_requested(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  pcsc_fido_daemon_test_request_stop();
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == 1,
              "stop requested returns 1");
  pcsc_fido_daemon_signals_shutdown();
}

static void signal_request_wakes_poll_fd(void) {
  struct pollfd pfd;
  int signal_fd;
  reset_uhid_loop_state();
  pcsc_fido_daemon_signals_shutdown();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup for wake fd");
  signal_fd = pcsc_fido_daemon_signal_poll_fd();
  expect_true(signal_fd >= 0, "signal poll fd available");
  pcsc_fido_daemon_test_request_stop();
  pfd.fd = signal_fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  expect_true(__real_poll(&pfd, 1u, SIGNAL_WAKE_POLL_TIMEOUT_MS) == 1 &&
                  (pfd.revents & POLLIN) != 0,
              "stop request wakes signal poll fd");
  pcsc_fido_daemon_drain_signal_wake();
  pfd.revents = 0;
  expect_true(__real_poll(&pfd, 1u, 0) == 0, "signal wake fd drains");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_poll_eintr(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_poll_eintr_once = 1;
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == 0,
              "poll EINTR returns 0");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_poll_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_poll_fail_once = 1;
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == -1,
              "poll error returns -1");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_read_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_read_io_error_once = 1;
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  scrub_hook_reset();
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == -1,
              "read error returns -1");
  expect_true(scrub_hook_calls_with_len(sizeof(struct uhid_event)) == 1u,
              "inbound UHID event scrubbed on read error");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_hangup(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_poll_hup_once = 1;
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == -1,
              "UHID hangup returns -1");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_short_read(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = UHID_LOOP_ASSIGNED_CID;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = FAKE_UHID_FD,
      .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_read_short_once = 1;
  ctx.fd = FAKE_UHID_FD;
  pcsc_fido_daemon_pending_request_reset(&pending);
  bind_test_channel(&ctx, cid);
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == 0,
              "a short UHID read is retried");
  pcsc_fido_daemon_signals_shutdown();
}

static void run_always_mode_loop(void) {
  reset_uhid_loop_state();
  scrub_hook_reset();
  expect_true(pcsc_fido_daemon_run_always_mode(FAKE_UHID_FD) == 0,
              "always mode exits cleanly on stop");
  expect_true(g_uhid_create_count == 1u,
              "always mode creates virtual key once");
  /* Exact inbound+outbound mix: 3 successful reads (PING + 2 CLOSE) + the
   * EAGAIN that stops the loop, plus one send_packet scrub for the PING
   * reply. CREATE2/DESTROY do not use SCRUB_ON_EXIT. */
  expect_true(scrub_hook_calls_with_len(sizeof(struct uhid_event)) ==
                  (unsigned)READS_BEFORE_STOP +
                      (unsigned)ALWAYS_MODE_EAGAIN_READ +
                      (unsigned)ALWAYS_MODE_REPLY_OUTBOUND,
              "3 successful reads + EAGAIN inbound + 1 reply outbound");
  expect_true(
      g_last_input_init_cmd ==
              (uint8_t)(HID_INIT_PKT_FLAG | PCSC_FIDO_HID_CMD_ERROR) &&
          g_last_input_init_data0 == PCSC_FIDO_DAEMON_ERR_INVALID_CHANNEL,
      "PING before INIT is rejected with ERR_INVALID_CHANNEL");
  expect_true(scrub_hook_all_zero(), "loop scrubs left regions zeroed");
  pcsc_fido_daemon_signals_shutdown();
}

static void run_always_mode_create_failure(void) {
  reset_uhid_loop_state();
  g_uhid_create_fail = 1;
  expect_true(pcsc_fido_daemon_run_always_mode(FAKE_UHID_FD) == 1,
              "always mode UHID create failure exits 1");
  pcsc_fido_daemon_signals_shutdown();
}

static void run_always_mode_read_error(void) {
  reset_uhid_loop_state();
  g_read_io_error_once = 1;
  expect_true(pcsc_fido_daemon_run_always_mode(FAKE_UHID_FD) == 1,
              "always mode read error exits 1");
  pcsc_fido_daemon_signals_shutdown();
}

int main(void) {
  handle_uhid_event_null_guards();
  handle_uhid_event_rate_limited();
  handle_uhid_event_rate_limit_charges_requests_not_frames();
  rate_limited_init_abandons_partial_request();
  rate_limited_cancel_gets_no_reply();
  bridge_reset_keeps_rate_limit_budget();
  handle_uhid_event_assembly_error();
  handle_uhid_event_close_resets_bridge();
  poll_uhid_event_null_returns_error();
  poll_uhid_event_stop_requested();
  signal_request_wakes_poll_fd();
  poll_uhid_event_poll_eintr();
  poll_uhid_event_poll_error();
  poll_uhid_event_read_error();
  poll_uhid_event_hangup();
  poll_uhid_event_short_read();
  run_always_mode_loop();
  run_always_mode_create_failure();
  run_always_mode_read_error();
  return failures == 0 ? 0 : 1;
}
