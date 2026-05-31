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

#include "pcsc_fido/browser_daemon.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_signals.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
  FAKE_UHID_FD = 120,
};

static time_t g_fake_time = 1000000;
static int g_read_calls;
static int g_stop_after_reads = 3;
static int g_open_fail;
static int g_uhid_create_fail;
static int g_eintr_once;
static int g_short_read_once;
static int g_uhid_stop_once;
static int g_malformed_output_once;
static int g_poll_wrap_enabled;
static int g_poll_timeout_zero_once;
static int g_raise_after_timeout_once;
static int g_stop_after_close;
static int g_read_io_error_once;
static int g_request_stop_after_ping;
static unsigned g_uhid_create_count;
static unsigned g_uhid_destroy_count;
static uint8_t g_ping_payload[] = {0xAAu};

extern int __real_nanosleep(const struct timespec *req, struct timespec *rem);

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec *req PCSC_FIDO_MAYBE_UNUSED,
                     // cppcheck-suppress constParameterPointer
                     struct timespec *rem PCSC_FIDO_MAYBE_UNUSED) {
  const struct timespec yield = {.tv_sec = 0, .tv_nsec = 1000000L};
  (void)req;
  return __real_nanosleep(&yield, rem);
}

time_t __wrap_time(time_t *t) {
  g_fake_time++;
  if (t != nullptr) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

extern int __real_open(const char *pathname, int flags, ...);
extern ssize_t __real_read(int fd, void *buf, size_t count);
extern ssize_t __real_write(int fd, const void *buf, size_t count);
extern int __real_close(int fd);
extern int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int __wrap_open(const char *pathname, int flags, ...) {
  (void)flags;
  if (g_open_fail && pathname != nullptr && strcmp(pathname, "/dev/uhid") == 0) {
    errno = EACCES;
    return -1;
  }
  if (pathname != nullptr && strcmp(pathname, "/dev/uhid") == 0) {
    return FAKE_UHID_FD;
  }
  return __real_open(pathname, flags);
}

ssize_t __wrap_read(int fd, void *buf, size_t count) {
  struct uhid_event *ev;
  if (fd != FAKE_UHID_FD || buf == nullptr || count < sizeof(struct uhid_event)) {
    return __real_read(fd, buf, count);
  }
  if (g_eintr_once) {
    g_eintr_once = 0;
    errno = EINTR;
    return -1;
  }
  if (g_short_read_once) {
    g_short_read_once = 0;
    return 1;
  }
  if (g_read_calls >= g_stop_after_reads && g_read_io_error_once) {
    g_read_io_error_once = 0;
    errno = EIO;
    return -1;
  }
  if (g_read_calls >= g_stop_after_reads) {
    errno = EIO;
    return -1;
  }
  ev = (struct uhid_event *)buf;
  memset(ev, 0, sizeof(*ev));
  g_read_calls++;
  if (g_read_calls == 1) {
    ev->type = UHID_START;
    return (ssize_t)sizeof(*ev);
  }
  if (g_read_calls == 2) {
    uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
    ev->type = UHID_OUTPUT;
    ev->u.output.size = PCSC_FIDO_HID_PACKET_SIZE;
    memset(packet, 0, sizeof(packet));
    if (g_malformed_output_once) {
      g_malformed_output_once = 0;
      packet[0] = 0x4Eu;
      packet[1] = 0x46u;
      packet[2] = 0x43u;
      packet[3] = 0x01u;
      packet[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_CBOR);
      packet[5] = 0xFFu;
      packet[6] = 0xFFu;
    } else {
      packet[0] = 0x4Eu;
      packet[1] = 0x46u;
      packet[2] = 0x43u;
      packet[3] = 0x01u;
      packet[4] = (uint8_t)(0x80u | PCSC_FIDO_HID_CMD_PING);
      packet[7] = (uint8_t)sizeof(g_ping_payload);
      packet[8] = g_ping_payload[0];
    }
    memcpy(ev->u.output.data, packet, sizeof(packet));
    if (g_request_stop_after_ping) {
      g_request_stop_after_ping = 0;
      pcsc_fido_daemon_test_request_stop();
    }
    return (ssize_t)sizeof(*ev);
  }
  if (g_uhid_stop_once) {
    g_uhid_stop_once = 0;
    ev->type = UHID_STOP;
    return (ssize_t)sizeof(*ev);
  }
  ev->type = UHID_CLOSE;
  if (g_stop_after_close) {
    pcsc_fido_daemon_test_request_stop();
  }
  return (ssize_t)sizeof(*ev);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
  if (fd == FAKE_UHID_FD && buf != nullptr && count >= sizeof(struct uhid_event)) {
    const struct uhid_event *ev = (const struct uhid_event *)buf;
    if (ev->type == UHID_CREATE2) {
      g_uhid_create_count++;
    } else if (ev->type == UHID_DESTROY) {
      g_uhid_destroy_count++;
    }
    if (ev->type == UHID_CREATE2) {
      if (!g_uhid_create_fail) {
        return (ssize_t)count;
      }
      errno = EIO;
      return -1;
    }
    return (ssize_t)count;
  }
  return __real_write(fd, buf, count);
}

int __wrap_close(int fd) {
  if (fd == FAKE_UHID_FD) {
    return 0;
  }
  return __real_close(fd);
}

static void maybe_request_stop_once(int *flag) {
  if (flag != nullptr && *flag != 0) {
    *flag = 0;
    pcsc_fido_daemon_test_request_stop();
  }
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  nfds_t i;
  if (pcsc_fido_daemon_stop_requested()) {
    return 0;
  }
  if (fds == nullptr || nfds == 0u) {
    return __real_poll(fds, nfds, timeout);
  }
  for (i = 0u; i < nfds; i++) {
    fds[i].revents = 0;
  }
  if (timeout >= 0 && g_poll_timeout_zero_once) {
    int armed = 0;
    for (i = 0u; i < nfds; i++) {
      if (fds[i].fd == FAKE_UHID_FD) {
        armed = 1;
        break;
      }
    }
    if (armed) {
      g_poll_timeout_zero_once = 0;
      maybe_request_stop_once(&g_raise_after_timeout_once);
      return 0;
    }
  }
  if (!g_poll_wrap_enabled) {
    for (i = 0u; i < nfds; i++) {
      int signal_fd = pcsc_fido_daemon_signal_poll_fd();
      if (signal_fd >= 0 && fds[i].fd == signal_fd && (fds[i].events & POLLIN) != 0) {
        int rv = __real_poll(&fds[i], 1, 0);
        if (rv > 0 && (fds[i].revents & POLLIN) != 0) {
          return rv;
        }
      }
    }
    for (i = 0u; i < nfds; i++) {
      if (fds[i].fd == FAKE_UHID_FD) {
        fds[i].revents = POLLIN;
        return 1;
      }
    }
    if (timeout < 0) {
      timeout = 1000;
    }
    if (timeout > 10) {
      timeout = 10;
    }
    return __real_poll(fds, nfds, timeout);
  }
  if (timeout < 0) {
    int signal_fd = pcsc_fido_daemon_signal_poll_fd();
    for (i = 0u; i < nfds; i++) {
      if (signal_fd >= 0 && fds[i].fd == signal_fd) {
        continue;
      }
      fds[i].revents = POLLIN;
    }
    return (int)nfds;
  }
  maybe_request_stop_once(&g_raise_after_timeout_once);
  return 0;
}

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void reset_loop_test_state(void) {
  expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "always", 1) == 0, "set always mode");
  g_read_calls = 0;
  g_stop_after_reads = 4;
  g_open_fail = 0;
  g_uhid_create_fail = 0;
  g_eintr_once = 0;
  g_short_read_once = 0;
  g_uhid_stop_once = 0;
  g_malformed_output_once = 0;
  g_poll_wrap_enabled = 0;
  g_poll_timeout_zero_once = 0;
  g_raise_after_timeout_once = 0;
  g_stop_after_close = 1;
  g_read_io_error_once = 0;
  g_request_stop_after_ping = 0;
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  g_uhid_create_count = 0;
  g_uhid_destroy_count = 0;
}

static char g_argv0[] = "pcsc-fido";

static void daemon_main_loop_handles_ping_and_close(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "daemon loop exits cleanly");
}

static void daemon_main_with_fd_entry(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  expect_true(pcsc_fido_browser_daemon_main_with_fd(1, argv, FAKE_UHID_FD) == 0,
              "main_with_fd exits cleanly");
}

static void daemon_stop_request_stops_loop(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  g_stop_after_reads = 4;
  g_stop_after_close = 0;
  g_request_stop_after_ping = 1;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "daemon exits after stop request");
}

static void daemon_open_uhid_failure(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  reset_loop_test_state();
  g_open_fail = 1;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 1, "open failure exits 1");
}

static void daemon_uhid_create_failure(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  reset_loop_test_state();
  g_uhid_create_fail = 1;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 1, "UHID create failure exits 1");
}

static void daemon_read_eintr_and_short_read(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  g_eintr_once = 1;
  g_short_read_once = 1;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "EINTR and short read handled");
}

static void daemon_read_io_error_exits_nonzero(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  g_stop_after_close = 0;
  g_read_io_error_once = 1;
  g_stop_after_reads = 4;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 1, "read I/O error exits 1");
}

static void daemon_uhid_stop_resets_bridge(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  g_uhid_stop_once = 1;
  g_stop_after_reads = 5;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "UHID_STOP handled");
}

static void daemon_assembly_error(void) {
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  reset_loop_test_state();
  g_malformed_output_once = 1;
  g_stop_after_reads = 3;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "assembly error handled");
}

static void daemon_tap_arm_expires_virtual_key(void) {
  static const bool sequence[] = {false, true, true};
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  mock_pcsc_set_status_present_sequence(sequence, sizeof(sequence) / sizeof(sequence[0]));
  reset_loop_test_state();
  expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "tap-arm", 1) == 0, "set tap-arm mode");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "5", 1) == 0, "set short arm window");
  g_poll_timeout_zero_once = 1;
  g_raise_after_timeout_once = 1;
  expect_true(pcsc_fido_browser_daemon_main(1, argv) == 0, "tap-arm daemon exits cleanly");
  expect_true(g_uhid_create_count > 0u, "tap-arm creates virtual key after card wake");
  expect_true(g_uhid_destroy_count > 0u, "tap-arm destroys virtual key after expiry");
}

static void daemon_tap_arm_card_wake_arms_key(void) {
  static const bool sequence[] = {false, true, true};
  char *argv[] = {g_argv0, nullptr};
  mock_pcsc_reset();
  mock_pcsc_set_readers("Loop Test Reader 00 00");
  mock_pcsc_set_status_present_sequence(sequence, sizeof(sequence) / sizeof(sequence[0]));
  reset_loop_test_state();
  expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "tap-arm", 1) == 0, "set tap-arm mode");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "5", 1) == 0, "set short arm window");
  g_poll_timeout_zero_once = 1;
  g_raise_after_timeout_once = 1;
  expect_true(pcsc_fido_browser_daemon_main_with_fd(1, argv, FAKE_UHID_FD) == 0,
              "tap-arm card wake exits cleanly");
  expect_true(g_uhid_create_count > 0u, "tap-arm arms after card wake");
}

int main(void) {
  daemon_main_loop_handles_ping_and_close();
  daemon_main_with_fd_entry();
  daemon_stop_request_stops_loop();
  daemon_open_uhid_failure();
  daemon_uhid_create_failure();
  daemon_read_eintr_and_short_read();
  daemon_read_io_error_exits_nonzero();
  daemon_uhid_stop_resets_bridge();
  daemon_assembly_error();
  daemon_tap_arm_expires_virtual_key();
  daemon_tap_arm_card_wake_arms_key();
  return failures == 0 ? 0 : 1;
}
