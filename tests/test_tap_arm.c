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
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/tap_arm.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_log.h"

enum {
  FAKE_UHID_FD = 120,
  FAKE_TIME_START = 1000000,
  NS_PER_MS = 1000000,
  DEFAULT_READS_BEFORE_STOP = TEST_LIT_4,
  TEST_PING_PAYLOAD_BYTE = TEST_LIT_0XAAU,
  UHID_OUTPUT_READ_CALL = TEST_SOCKETPAIR_FDS,
  HID_HDR_N = 0x4Eu,
  HID_HDR_F = 0x46u,
  HID_CID_BYTE_2_OFF = TEST_SOCKETPAIR_FDS,
  HID_HDR_C = 0x43u,
  HID_CID_BYTE_3_OFF = TEST_LIT_3,
  HID_CMD_OFF = TEST_LIT_4,
  HID_INIT_PKT_FLAG = TEST_LIT_0X80U,
  HID_DATA_OFF = TEST_LIT_7,
  HID_DATA_NEXT_OFF = TEST_LIT_8,
  SECOND_ARM_CREATE_COUNT = TEST_LIT_2U,
  DORMANT_POLL_TIMEOUT_MS = 1000,
  POLL_TIMEOUT_CAP_MS = 10,
  LONG_ARM_WINDOW_SEC = TEST_LIT_5U,
  READS_THROUGH_UHID_CLOSE = TEST_LIT_3,
  READ_ERROR_ARM_WINDOW_SEC = 20u,
};

static time_t g_fake_time = FAKE_TIME_START;
static int g_read_calls;
static int g_stop_after_reads = DEFAULT_READS_BEFORE_STOP;
static int g_uhid_create_fail;
static int g_poll_fail_once;
static int g_poll_timeout_zero_once;
static int g_raise_after_timeout_once;
static int g_request_stop_after_arm;
static int g_request_stop_after_destroy;
static int g_request_stop_after_second_arm;
static int g_request_stop_on_dormant_timeout;
static int g_inject_stale_wake_after_destroy;
static int g_last_card_wake_fd = -1;
static int g_read_io_error_once;
static unsigned g_uhid_create_count;
static unsigned g_uhid_destroy_count;
static uint8_t g_ping_payload[] = {TEST_PING_PAYLOAD_BYTE};

extern int __real_poll(struct pollfd* fds, nfds_t nfds, int timeout);
extern int __real_nanosleep(const struct timespec* req, struct timespec* rem);

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec* req PCSC_FIDO_MAYBE_UNUSED,
                     struct timespec* rem PCSC_FIDO_MAYBE_UNUSED) {
  return __real_nanosleep(
      &(const struct timespec){.tv_sec = 0, .tv_nsec = NS_PER_MS}, rem);
}

time_t __wrap_time(time_t* t) {
  g_fake_time++;
  if (t != PCSC_FIDO_NULL) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

extern ssize_t __real_read(int fd, void* buf, size_t count);
extern ssize_t __real_write(int fd, const void* buf, size_t count);

static void maybe_request_stop_once(int* flag);

ssize_t __wrap_read(int fd, void* buf, size_t count) {
  struct uhid_event* ev;
  if (fd != FAKE_UHID_FD || buf == PCSC_FIDO_NULL ||
      count < sizeof(struct uhid_event)) {
    return __real_read(fd, buf, count);
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
  ev = (struct uhid_event*)buf;
  pcsc_fido_zero_bytes(ev, sizeof(*ev));
  g_read_calls++;
  if (g_read_calls == 1) {
    ev->type = UHID_START;
    return (ssize_t)sizeof(*ev);
  }
  if (g_read_calls == UHID_OUTPUT_READ_CALL) {
    uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
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
    if (g_request_stop_after_arm) {
      g_request_stop_after_arm = 0;
      pcsc_fido_daemon_test_request_stop();
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
      if (g_request_stop_after_second_arm &&
          g_uhid_create_count >= SECOND_ARM_CREATE_COUNT) {
        g_request_stop_after_second_arm = 0;
        pcsc_fido_daemon_test_request_stop();
      }
      if (g_uhid_create_fail) {
        errno = EIO;
        return -1;
      }
    } else if (ev->type == UHID_DESTROY) {
      g_uhid_destroy_count++;
      if (g_inject_stale_wake_after_destroy && g_last_card_wake_fd >= 0) {
        uint8_t byte = 1u;
        g_inject_stale_wake_after_destroy = 0;
        (void)__real_write(g_last_card_wake_fd, &byte, sizeof(byte));
      }
      maybe_request_stop_once(&g_request_stop_after_destroy);
    }
    return (ssize_t)count;
  }
  return __real_write(fd, buf, count);
}

static void maybe_request_stop_once(int* flag) {
  if (flag != PCSC_FIDO_NULL && *flag != 0) {
    *flag = 0;
    pcsc_fido_daemon_test_request_stop();
  }
}

int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout) {
  nfds_t i;
  int armed = 0;
  int signal_fd;
  if (pcsc_fido_daemon_stop_requested()) {
    return 0;
  }
  if (g_poll_fail_once) {
    g_poll_fail_once = 0;
    errno = EIO;
    return -1;
  }
  if (fds == PCSC_FIDO_NULL || nfds == 0u) {
    return __real_poll(fds, nfds, timeout);
  }
  for (i = 0u; i < nfds; i++) {
    fds[i].revents = 0;
  }
  signal_fd = pcsc_fido_daemon_signal_poll_fd();
  for (i = 0u; i < nfds; i++) {
    if (fds[i].fd == FAKE_UHID_FD) {
      armed = 1;
    } else if (signal_fd < 0 || fds[i].fd != signal_fd) {
      g_last_card_wake_fd = fds[i].fd;
    }
  }
  if (timeout >= 0 && g_poll_timeout_zero_once) {
    if (armed) {
      g_poll_timeout_zero_once = 0;
      maybe_request_stop_once(&g_raise_after_timeout_once);
      return 0;
    }
  }
  for (i = 0u; i < nfds; i++) {
    if (fds[i].fd == FAKE_UHID_FD) {
      fds[i].revents = POLLIN;
      return 1;
    }
  }
  if (timeout < 0) {
    timeout = DORMANT_POLL_TIMEOUT_MS;
  }
  if (timeout > POLL_TIMEOUT_CAP_MS) {
    timeout = POLL_TIMEOUT_CAP_MS;
  }
  {
    int rv = __real_poll(fds, nfds, timeout);
    if (!armed && rv == 0) {
      maybe_request_stop_once(&g_request_stop_on_dormant_timeout);
    }
    return rv;
  }
}

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static pcsc_fido_browser_config_t default_cfg(void) {
  pcsc_fido_browser_config_t cfg;
  cfg.virtual_key_mode = PCSC_FIDO_VIRTUAL_KEY_TAP_ARM;
  cfg.arm_sec = 1u;
  return cfg;
}

static void reset_tap_arm_test_state(void) {
  g_fake_time = FAKE_TIME_START;
  g_read_calls = 0;
  g_stop_after_reads = DEFAULT_READS_BEFORE_STOP;
  g_uhid_create_fail = 0;
  g_poll_fail_once = 0;
  g_poll_timeout_zero_once = 0;
  g_raise_after_timeout_once = 0;
  g_request_stop_after_arm = 0;
  g_request_stop_after_destroy = 0;
  g_request_stop_after_second_arm = 0;
  g_request_stop_on_dormant_timeout = 0;
  g_inject_stale_wake_after_destroy = 0;
  g_last_card_wake_fd = -1;
  g_read_io_error_once = 0;
  g_uhid_create_count = 0;
  g_uhid_destroy_count = 0;
  pcsc_fido_daemon_signals_shutdown();
  pcsc_fido_daemon_reset_stop_request();
  expect_true(pcsc_fido_daemon_signals_init(), "signal setup");
}

static void tap_arm_null_cfg_rejected(void) {
  reset_tap_arm_test_state();
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, PCSC_FIDO_NULL) == 1,
              "null cfg rejected");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_card_wake_arms_and_timeout_disarms(void) {
  static const bool CARD_WAKE_ARM_TIMEOUT_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  cfg.arm_sec = LONG_ARM_WINDOW_SEC;
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      CARD_WAKE_ARM_TIMEOUT_SEQUENCE,
      sizeof(CARD_WAKE_ARM_TIMEOUT_SEQUENCE) /
          sizeof(CARD_WAKE_ARM_TIMEOUT_SEQUENCE[0]));
  g_poll_timeout_zero_once = 1;
  g_raise_after_timeout_once = 1;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 0,
              "tap-arm exits cleanly");
  expect_true(g_uhid_create_count > 0u, "virtual key created after card wake");
  expect_true(g_uhid_destroy_count > 0u,
              "virtual key destroyed after arm timeout");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_uhid_create_failure(void) {
  static const bool UHID_CREATE_FAILURE_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      UHID_CREATE_FAILURE_SEQUENCE,
      sizeof(UHID_CREATE_FAILURE_SEQUENCE) /
          sizeof(UHID_CREATE_FAILURE_SEQUENCE[0]));
  g_uhid_create_fail = 1;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 1,
              "UHID create failure exits 1");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_poll_error_exits_nonzero(void) {
  static const bool POLL_ERROR_PRESENT_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      POLL_ERROR_PRESENT_SEQUENCE, sizeof(POLL_ERROR_PRESENT_SEQUENCE) /
                                       sizeof(POLL_ERROR_PRESENT_SEQUENCE[0]));
  g_poll_fail_once = 1;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 1,
              "poll error exits 1");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_uhid_event_while_armed(void) {
  static const bool UHID_EVENT_ARMED_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  cfg.arm_sec = LONG_ARM_WINDOW_SEC;
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      UHID_EVENT_ARMED_SEQUENCE,
      sizeof(UHID_EVENT_ARMED_SEQUENCE) / sizeof(UHID_EVENT_ARMED_SEQUENCE[0]));
  g_request_stop_after_arm = 1;
  g_stop_after_reads = READS_THROUGH_UHID_CLOSE;
  g_poll_timeout_zero_once = 0;
  g_raise_after_timeout_once = 0;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 0,
              "uhid event while armed handled");
  expect_true(g_uhid_create_count > 0u, "virtual key armed for uhid traffic");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_expired_window_rejects_ready_uhid(void) {
  static const bool EXPIRED_WINDOW_PRESENT_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      EXPIRED_WINDOW_PRESENT_SEQUENCE,
      sizeof(EXPIRED_WINDOW_PRESENT_SEQUENCE) /
          sizeof(EXPIRED_WINDOW_PRESENT_SEQUENCE[0]));
  g_request_stop_after_destroy = 1;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 0,
              "expired arm window exits cleanly");
  expect_true(g_uhid_create_count > 0u, "virtual key created before expiry");
  expect_true(g_uhid_destroy_count > 0u, "virtual key destroyed at expiry");
  expect_true(g_read_calls == 0,
              "expired arm window rejects ready UHID events");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_timeout_discards_stale_card_wake(void) {
  static const bool STALE_CARD_WAKE_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  cfg.arm_sec = LONG_ARM_WINDOW_SEC;
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      STALE_CARD_WAKE_SEQUENCE,
      sizeof(STALE_CARD_WAKE_SEQUENCE) / sizeof(STALE_CARD_WAKE_SEQUENCE[0]));
  g_poll_timeout_zero_once = 1;
  g_inject_stale_wake_after_destroy = 1;
  g_request_stop_after_second_arm = 1;
  g_request_stop_on_dormant_timeout = 1;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 0,
              "stale card wake after timeout exits cleanly");
  expect_true(g_uhid_create_count == 1u,
              "stale card wake does not re-arm virtual key");
  expect_true(g_uhid_destroy_count > 0u,
              "virtual key destroyed after stale wake test");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_uhid_read_error_exits_nonzero(void) {
  static const bool UHID_READ_ERROR_SEQUENCE[] = {false, true, true};
  pcsc_fido_browser_config_t cfg = default_cfg();
  cfg.arm_sec = READ_ERROR_ARM_WINDOW_SEC;
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      UHID_READ_ERROR_SEQUENCE,
      sizeof(UHID_READ_ERROR_SEQUENCE) / sizeof(UHID_READ_ERROR_SEQUENCE[0]));
  g_read_io_error_once = 1;
  g_stop_after_reads = READS_THROUGH_UHID_CLOSE;
  g_poll_timeout_zero_once = 0;
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 1,
              "uhid read error exits 1");
  pcsc_fido_daemon_signals_shutdown();
}

static void tap_arm_stop_request_exits_cleanly(void) {
  static const bool STOP_REQUEST_ABSENT_SEQUENCE[] = {false, false, false};
  pcsc_fido_browser_config_t cfg = default_cfg();
  reset_tap_arm_test_state();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Tap Arm Reader 00 00");
  mock_pcsc_set_status_present_sequence(
      STOP_REQUEST_ABSENT_SEQUENCE,
      sizeof(STOP_REQUEST_ABSENT_SEQUENCE) /
          sizeof(STOP_REQUEST_ABSENT_SEQUENCE[0]));
  pcsc_fido_daemon_test_request_stop();
  expect_true(pcsc_fido_tap_arm_run(FAKE_UHID_FD, &cfg) == 0,
              "stop request exits cleanly");
  pcsc_fido_daemon_signals_shutdown();
}

int main(void) {
  tap_arm_null_cfg_rejected();
  tap_arm_card_wake_arms_and_timeout_disarms();
  tap_arm_uhid_create_failure();
  tap_arm_poll_error_exits_nonzero();
  tap_arm_uhid_event_while_armed();
  tap_arm_expired_window_rejects_ready_uhid();
  tap_arm_timeout_discards_stale_card_wake();
  tap_arm_uhid_read_error_exits_nonzero();
  tap_arm_stop_request_exits_cleanly();
  return failures == 0 ? 0 : 1;
}
