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

enum {
  FAKE_UHID_FD = 121,
};

static time_t g_fake_time = 1000000;
static int g_read_calls;
static int g_uhid_create_fail;
static int g_poll_eintr_once;
static int g_poll_fail_once;
static int g_read_io_error_once;
static int g_stop_after_reads = 3;
static unsigned g_uhid_create_count;
static uint8_t g_ping_payload[] = {0xBBu};

extern int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
extern ssize_t __real_read(int fd, void *buf, size_t count);
extern ssize_t __real_write(int fd, const void *buf, size_t count);

extern int __real_nanosleep(const struct timespec *req, struct timespec *rem);

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec *req PCSC_FIDO_MAYBE_UNUSED,
                     // cppcheck-suppress constParameterPointer
                     struct timespec *rem PCSC_FIDO_MAYBE_UNUSED) {
  return __real_nanosleep(&(const struct timespec){.tv_sec = 0, .tv_nsec = 1000000L}, rem);
}

time_t __wrap_time(time_t *t) {
  g_fake_time++;
  if (t != nullptr) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

ssize_t __wrap_read(int fd, void *buf, size_t count) {
  struct uhid_event *ev;
  if (fd != FAKE_UHID_FD || buf == nullptr || count < sizeof(struct uhid_event)) {
    return __real_read(fd, buf, count);
  }
  if (g_read_io_error_once) {
    g_read_io_error_once = 0;
    errno = EIO;
    return -1;
  }
  if (g_read_calls >= g_stop_after_reads) {
    pcsc_fido_daemon_test_request_stop();
    errno = EAGAIN;
    return -1;
  }
  ev = (struct uhid_event *)buf;
  memset(ev, 0, sizeof(*ev));
  g_read_calls++;
  if (g_read_calls == 1) {
    ev->type = UHID_OUTPUT;
    ev->u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
    {
      uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
      memset(packet, 0, sizeof(packet));
      packet[0] = 0x4Eu;
      packet[1] = 0x46u;
      packet[2] = 0x43u;
      packet[3] = 0x01u;
      packet[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_PING);
      packet[7] = (uint8_t)sizeof(g_ping_payload);
      packet[8] = g_ping_payload[0];
      memcpy(ev->u.output.data, packet, sizeof(packet));
    }
    return (ssize_t)sizeof(*ev);
  }
  ev->type = UHID_CLOSE;
  return (ssize_t)sizeof(*ev);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
  if (fd == FAKE_UHID_FD && buf != nullptr && count >= sizeof(struct uhid_event)) {
    const struct uhid_event *ev = (const struct uhid_event *)buf;
    if (ev->type == UHID_CREATE2) {
      g_uhid_create_count++;
      if (g_uhid_create_fail) {
        errno = EIO;
        return -1;
      }
    }
    return (ssize_t)count;
  }
  return __real_write(fd, buf, count);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
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
  if (fds == nullptr || nfds == 0u) {
    return 0;
  }
  for (i = 0u; i < nfds; i++) {
    fds[i].revents = 0;
  }
  for (i = 0u; i < nfds; i++) {
    if (fds[i].fd == FAKE_UHID_FD) {
      fds[i].revents = POLLIN;
      return 1;
    }
  }
  return 0;
}

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void reset_uhid_loop_state(void) {
  g_fake_time = 1000000;
  g_read_calls = 0;
  g_uhid_create_fail = 0;
  g_poll_eintr_once = 0;
  g_poll_fail_once = 0;
  g_read_io_error_once = 0;
  g_stop_after_reads = 3;
  g_uhid_create_count = 0;
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

static void build_ping_output(struct uhid_event *ev) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  memset(ev, 0, sizeof(*ev));
  ev->type = UHID_OUTPUT;
  ev->u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
  memset(packet, 0, sizeof(packet));
  packet[0] = 0x4Eu;
  packet[1] = 0x46u;
  packet[2] = 0x43u;
  packet[3] = 0x01u;
  packet[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_PING);
  packet[7] = (uint8_t)sizeof(g_ping_payload);
  packet[8] = g_ping_payload[0];
  memcpy(ev->u.output.data, packet, sizeof(packet));
}

static void handle_uhid_event_null_guards(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  memset(&pending, 0, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, nullptr, &pending, &ctx);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, nullptr, &ctx);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, nullptr);
}

static void handle_uhid_event_rate_limited(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  reset_uhid_loop_state();
  setenv("PCSC_FIDO_RATE_WINDOW_SEC", "10", 1);
  setenv("PCSC_FIDO_RATE_CTAPHID", "1", 1);
  memset(&pending, 0, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  build_ping_output(&ev);
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  expect_true(!pcsc_fido_rate_limit_allow_ctaphid(), "second CTAPHID frame blocked");
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  pcsc_fido_daemon_signals_shutdown();
}

static void handle_uhid_event_assembly_error(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  reset_uhid_loop_state();
  memset(&pending, 0, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  build_ping_output(&ev);
  ev.u.output.data[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_CBOR);
  ev.u.output.data[5] = 0xFFu;
  ev.u.output.data[6] = 0xFFu;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  pcsc_fido_daemon_signals_shutdown();
}

static void handle_uhid_event_close_resets_bridge(void) {
  struct uhid_event ev;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  reset_uhid_loop_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("UHID Loop Reader 00 00");
  memset(&pending, 0, sizeof(pending));
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "bridge session primed");
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_CLOSE;
  pcsc_fido_daemon_handle_uhid_event(FAKE_UHID_FD, &ev, &pending, &ctx);
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_null_returns_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = FAKE_UHID_FD,
    .poll_timeout_ms = 0,
  };
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  expect_true(pcsc_fido_daemon_poll_uhid_event(nullptr, &pending, &ctx) == -1,
              "null poll ctx rejected");
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, nullptr, &ctx) == -1,
              "null pending rejected");
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, nullptr) == -1,
              "null request ctx rejected");
}

static void poll_uhid_event_stop_requested(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = FAKE_UHID_FD,
    .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
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
  expect_true(__real_poll(&pfd, 1u, 100) == 1 && (pfd.revents & POLLIN) != 0,
              "stop request wakes signal poll fd");
  pcsc_fido_daemon_drain_signal_wake();
  pfd.revents = 0;
  expect_true(__real_poll(&pfd, 1u, 0) == 0, "signal wake fd drains");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_poll_eintr(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = FAKE_UHID_FD,
    .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_poll_eintr_once = 1;
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == 0,
              "poll EINTR returns 0");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_poll_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = FAKE_UHID_FD,
    .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_poll_fail_once = 1;
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == -1,
              "poll error returns -1");
  pcsc_fido_daemon_signals_shutdown();
}

static void poll_uhid_event_read_error(void) {
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t ctx;
  uint32_t cid = 0x4E464301u;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = FAKE_UHID_FD,
    .poll_timeout_ms = 0,
  };
  reset_uhid_loop_state();
  g_read_io_error_once = 1;
  ctx.fd = FAKE_UHID_FD;
  ctx.assigned_cid = &cid;
  expect_true(pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx) == -1,
              "read error returns -1");
  pcsc_fido_daemon_signals_shutdown();
}

static void run_always_mode_loop(void) {
  reset_uhid_loop_state();
  expect_true(pcsc_fido_daemon_run_always_mode(FAKE_UHID_FD) == 0,
              "always mode exits cleanly on stop");
  expect_true(g_uhid_create_count == 1u, "always mode creates virtual key once");
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
  handle_uhid_event_assembly_error();
  handle_uhid_event_close_resets_bridge();
  poll_uhid_event_null_returns_error();
  poll_uhid_event_stop_requested();
  signal_request_wakes_poll_fd();
  poll_uhid_event_poll_eintr();
  poll_uhid_event_poll_error();
  poll_uhid_event_read_error();
  run_always_mode_loop();
  run_always_mode_create_failure();
  run_always_mode_read_error();
  return failures == 0 ? 0 : 1;
}
