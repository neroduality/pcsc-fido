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

#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"

#include <errno.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void pcsc_fido_daemon_handle_uhid_event(int fd, const struct uhid_event *ev,
                                        pcsc_fido_daemon_pending_request_t *pending,
                                        const pcsc_fido_daemon_request_context_t *request_ctx) {
  if (ev == nullptr || pending == nullptr || request_ctx == nullptr) {
    return;
  }
  if (ev->type == UHID_OUTPUT) {
    const uint8_t *data;
    if (pcsc_fido_daemon_output_packet_data(ev, &data)) {
      if (!pcsc_fido_rate_limit_allow_ctaphid()) {
        (void)pcsc_fido_daemon_send_hid_error(fd, pcsc_fido_daemon_hid_packet_cid(data),
                                              PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
      } else if (!pcsc_fido_daemon_request_assembler_feed(
                   fd, pending, data,
                   (pcsc_fido_daemon_request_handler_fn)pcsc_fido_daemon_handle_hid_request,
                   request_ctx)) {
        pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "internal request assembly error");
      }
    }
  } else if (ev->type == UHID_CLOSE || ev->type == UHID_STOP) {
    pcsc_fido_log(PCSC_FIDO_LOG_INFO, "UHID client closed; resetting PC/SC session");
    pcsc_fido_daemon_pending_request_reset(pending);
    pcsc_fido_bridge_reset();
  }
}

static int read_uhid_event(int fd, pcsc_fido_daemon_pending_request_t *pending,
                           const pcsc_fido_daemon_request_context_t *request_ctx) {
  struct uhid_event ev;
  ssize_t got = read(fd, &ev, sizeof(ev));
  if (got < 0) {
    if (errno == EINTR || errno == EAGAIN) {
      return 0;
    }
    perror("read /dev/uhid");
    return -1;
  }
  if (got != (ssize_t)sizeof(ev)) {
    return 0;
  }
  pcsc_fido_daemon_handle_uhid_event(fd, &ev, pending, request_ctx);
  return 0;
}

int pcsc_fido_daemon_poll_uhid_event(pcsc_fido_daemon_uhid_poll_ctx_t *ctx,
                                     pcsc_fido_daemon_pending_request_t *pending,
                                     const pcsc_fido_daemon_request_context_t *request_ctx) {
  struct pollfd fds[2];
  nfds_t nfds = 0;
  int signal_fd;
  int rv;
  if (ctx == nullptr || pending == nullptr || request_ctx == nullptr) {
    return -1;
  }
  if (pcsc_fido_daemon_stop_requested()) {
    return 1;
  }
  signal_fd = pcsc_fido_daemon_signal_poll_fd();
  if (signal_fd >= 0) {
    fds[nfds].fd = signal_fd;
    fds[nfds].events = POLLIN;
    fds[nfds].revents = 0;
    nfds++;
  }
  fds[nfds].fd = ctx->uhid_fd;
  fds[nfds].events = POLLIN;
  fds[nfds].revents = 0;
  nfds++;
  rv = poll(fds, nfds, ctx->poll_timeout_ms);
  if (rv < 0) {
    if (errno == EINTR) {
      return 0;
    }
    perror("poll");
    return -1;
  }
  if (rv == 0) {
    return 0;
  }
  if (signal_fd >= 0 && (fds[0].revents & POLLIN) != 0) {
    pcsc_fido_daemon_drain_signal_wake();
    if (pcsc_fido_daemon_stop_requested()) {
      return 1;
    }
  }
  if ((fds[nfds - 1u].revents & POLLIN) != 0) {
    return read_uhid_event(ctx->uhid_fd, pending, request_ctx);
  }
  return 0;
}

int pcsc_fido_daemon_run_always_mode(int uhid_fd) {
  uint32_t assigned_cid = 0x4E464301u;
  pcsc_fido_daemon_request_context_t request_ctx;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
    .uhid_fd = uhid_fd,
    .poll_timeout_ms = 1000,
  };
  int status = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  if (!pcsc_fido_daemon_create_uhid_device(uhid_fd)) {
    perror("UHID_CREATE2");
    return 1;
  }
  request_ctx.fd = uhid_fd;
  request_ctx.assigned_cid = &assigned_cid;
  pcsc_fido_log(PCSC_FIDO_LOG_INFO, "virtual FIDO HID bridge ready; tap NFC key on browser prompt");
  while (!pcsc_fido_daemon_stop_requested()) {
    int rv = pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &request_ctx);
    if (rv < 0) {
      status = 1;
      break;
    }
    if (rv > 0) {
      break;
    }
  }
  pcsc_fido_daemon_destroy_uhid_device(uhid_fd);
  return status;
}
