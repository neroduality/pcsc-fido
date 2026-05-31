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

#include "pcsc_fido/card_monitor.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_util.h"
#include "pcsc_fido/tap_arm.h"
#include "pcsc_fido/uhid_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

enum {
#ifdef PCSC_FIDO_TESTING
  PCSC_FIDO_TAP_ARM_DORMANT_POLL_MS = 10,
#else
  PCSC_FIDO_TAP_ARM_DORMANT_POLL_MS = 1000,
#endif
};

typedef struct {
  int uhid_fd;
  int card_wake_pipe[2];
  pcsc_fido_card_monitor_t monitor;
  bool monitor_started;
  bool created;
  time_t deadline;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_request_context_t request_ctx;
  uint32_t assigned_cid;
} pcsc_fido_tap_arm_state_t;

static bool set_cloexec(int fd) {
  int flags;
  if (fd < 0) {
    return false;
  }
  flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void drain_wake_pipe(int fd) {
  uint8_t buf[32];
  for (;;) {
    ssize_t got = read(fd, buf, sizeof(buf));
    if (got > 0) {
      continue;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
}

static void card_present_wake(void *ctx) {
  int fd;
  uint8_t byte = 1u;
  if (ctx == nullptr) {
    return;
  }
  fd = *(int *)ctx;
  for (;;) {
    ssize_t wrote = write(fd, &byte, sizeof(byte));
    if (wrote == (ssize_t)sizeof(byte) || (wrote < 0 && errno == EAGAIN)) {
      return;
    }
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    perror("pcsc-fido card wake");
    return;
  }
}

static bool arm_virtual_key(pcsc_fido_tap_arm_state_t *state,
                            const pcsc_fido_browser_config_t *cfg) {
  if (state == nullptr || cfg == nullptr) {
    return false;
  }
  pcsc_fido_daemon_pending_request_reset(&state->pending);
  pcsc_fido_bridge_reset();
  if (!state->created && !pcsc_fido_daemon_create_uhid_device(state->uhid_fd)) {
    perror("UHID_CREATE2");
    return false;
  }
  state->created = true;
  state->deadline = pcsc_fido_add_seconds_saturating(time(nullptr), cfg->arm_sec);
  pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                "NFC key detected; virtual FIDO key armed for %u seconds. Keep the key on "
                "the reader while WebAuthn completes.",
                cfg->arm_sec);
  return true;
}

static void disarm_virtual_key(pcsc_fido_tap_arm_state_t *state) {
  if (state == nullptr || !state->created) {
    return;
  }
  pcsc_fido_daemon_destroy_uhid_device(state->uhid_fd);
  state->created = false;
  state->deadline = 0;
  pcsc_fido_daemon_pending_request_reset(&state->pending);
  pcsc_fido_bridge_reset();
  pcsc_fido_log(PCSC_FIDO_LOG_INFO, "virtual FIDO key arm window expired");
}

static bool restart_card_monitor(pcsc_fido_tap_arm_state_t *state) {
  if (state == nullptr) {
    return false;
  }
  if (state->monitor_started) {
    return true;
  }
  if (!pcsc_fido_card_monitor_start(&state->monitor, card_present_wake,
                                    &state->card_wake_pipe[1])) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "failed to restart PC/SC card monitor");
    return false;
  }
  state->monitor_started = true;
  return true;
}

static void tap_arm_on_timeout(pcsc_fido_tap_arm_state_t *state) {
  disarm_virtual_key(state);
  if (state != nullptr && state->card_wake_pipe[0] >= 0) {
    drain_wake_pipe(state->card_wake_pipe[0]);
  }
  (void)restart_card_monitor(state);
}

static bool arm_window_expired(const pcsc_fido_tap_arm_state_t *state, int *timeout_ms) {
  int remaining_ms;
  if (state == nullptr || !state->created) {
    if (timeout_ms != nullptr) {
      *timeout_ms = PCSC_FIDO_TAP_ARM_DORMANT_POLL_MS;
    }
    return false;
  }
  remaining_ms = pcsc_fido_timeout_until_ms(state->deadline);
  if (timeout_ms != nullptr) {
    *timeout_ms = remaining_ms;
  }
  return remaining_ms == 0;
}

static void close_card_wake_pipe(pcsc_fido_tap_arm_state_t *state) {
  if (state == nullptr) {
    return;
  }
  if (state->card_wake_pipe[0] >= 0) {
    close(state->card_wake_pipe[0]);
    state->card_wake_pipe[0] = -1;
  }
  if (state->card_wake_pipe[1] >= 0) {
    close(state->card_wake_pipe[1]);
    state->card_wake_pipe[1] = -1;
  }
}

static bool open_card_wake_pipe(pcsc_fido_tap_arm_state_t *state) {
  if (state == nullptr) {
    return false;
  }
  if (pipe(state->card_wake_pipe) != 0) {
    perror("pipe");
    return false;
  }
  if (!set_cloexec(state->card_wake_pipe[0]) || !set_cloexec(state->card_wake_pipe[1]) ||
      !set_nonblock(state->card_wake_pipe[0]) || !set_nonblock(state->card_wake_pipe[1])) {
    close_card_wake_pipe(state);
    return false;
  }
  return true;
}

int pcsc_fido_tap_arm_run(int uhid_fd, const pcsc_fido_browser_config_t *cfg) {
  pcsc_fido_tap_arm_state_t state;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx;
  int status = 0;
  if (cfg == nullptr) {
    return 1;
  }
  memset(&state, 0, sizeof(state));
  state.uhid_fd = uhid_fd;
  state.card_wake_pipe[0] = -1;
  state.card_wake_pipe[1] = -1;
  state.assigned_cid = 0x4E464301u;
  state.request_ctx.fd = uhid_fd;
  state.request_ctx.assigned_cid = &state.assigned_cid;
  pcsc_fido_daemon_pending_request_reset(&state.pending);
  if (!open_card_wake_pipe(&state)) {
    return 1;
  }
  if (!pcsc_fido_card_monitor_start(&state.monitor, card_present_wake, &state.card_wake_pipe[1])) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "failed to start PC/SC card monitor");
    close_card_wake_pipe(&state);
    return 1;
  }
  state.monitor_started = true;
  pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                "place the NFC key on the reader to arm the virtual FIDO key for %u seconds",
                cfg->arm_sec);
  poll_ctx.uhid_fd = uhid_fd;
  while (!pcsc_fido_daemon_stop_requested()) {
    struct pollfd fds[3];
    nfds_t nfds = 0;
    int signal_fd = pcsc_fido_daemon_signal_poll_fd();
    int poll_timeout_ms;
    int rv;
    if (arm_window_expired(&state, &poll_timeout_ms)) {
      tap_arm_on_timeout(&state);
      continue;
    }
    if (signal_fd >= 0) {
      fds[nfds].fd = signal_fd;
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      nfds++;
    }
    if (state.monitor_started) {
      fds[nfds].fd = state.card_wake_pipe[0];
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      nfds++;
    }
    if (state.created) {
      fds[nfds].fd = uhid_fd;
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      nfds++;
    }
    rv = poll(fds, nfds, poll_timeout_ms);
    if (rv < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("poll");
      status = 1;
      break;
    }
    if (pcsc_fido_daemon_stop_requested()) {
      break;
    }
    if (rv == 0) {
      if (pcsc_fido_daemon_stop_requested()) {
        break;
      }
      if (state.created) {
        tap_arm_on_timeout(&state);
      }
      continue;
    }
    if (arm_window_expired(&state, nullptr)) {
      tap_arm_on_timeout(&state);
      continue;
    }
    for (nfds_t i = 0u; i < nfds; i++) {
      if ((fds[i].revents & POLLIN) == 0) {
        continue;
      }
      if (signal_fd >= 0 && fds[i].fd == signal_fd) {
        pcsc_fido_daemon_drain_signal_wake();
        if (pcsc_fido_daemon_stop_requested()) {
          goto out;
        }
        continue;
      }
      if (fds[i].fd == state.card_wake_pipe[0]) {
        drain_wake_pipe(state.card_wake_pipe[0]);
        if (!state.monitor_started) {
          continue;
        }
        pcsc_fido_card_monitor_stop(&state.monitor);
        state.monitor_started = false;
        drain_wake_pipe(state.card_wake_pipe[0]);
        if (!arm_virtual_key(&state, cfg)) {
          status = 1;
          goto out;
        }
        break;
      }
      if (state.created && fds[i].fd == uhid_fd) {
        poll_ctx.poll_timeout_ms = 0;
        rv = pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &state.pending, &state.request_ctx);
        if (rv < 0) {
          status = 1;
          goto out;
        }
        if (rv > 0) {
          goto out;
        }
        break;
      }
    }
  }
out:
  if (state.monitor_started) {
    pcsc_fido_card_monitor_stop(&state.monitor);
  }
  if (state.created) {
    pcsc_fido_daemon_destroy_uhid_device(uhid_fd);
  }
  close_card_wake_pipe(&state);
  return status;
}
