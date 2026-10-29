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

#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"
#include "pcsc_fido/mem_util.h"

#include <errno.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void pcsc_fido_daemon_expire_idle_state(
    int fd, pcsc_fido_daemon_pending_request_t* pending,
    pcsc_fido_daemon_channels_t* channels) {
  (void)pcsc_fido_daemon_pending_request_expire(fd, pending);
  if (pcsc_fido_daemon_channels_expire_session(channels)) {
    pcsc_fido_bridge_reset();
  }
}

int pcsc_fido_daemon_idle_poll_timeout_ms(
    const pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_channels_t* channels, int cap_ms) {
  cap_ms = pcsc_fido_daemon_pending_request_poll_timeout_ms(pending, cap_ms);
  return pcsc_fido_daemon_channels_poll_timeout_ms(channels, cap_ms);
}

/* Calling the handler through a cast to the assembler's `const void*`
 * signature is undefined behavior (and trips -fsanitize=function / CFI). */
static void dispatch_hid_request(const void* ctx, uint32_t request_cid,
                                 uint8_t cmd, const uint8_t* payload,
                                 size_t payload_len) {
  pcsc_fido_daemon_handle_hid_request(
      (const pcsc_fido_daemon_request_context_t*)ctx, request_cid, cmd, payload,
      payload_len);
}

void pcsc_fido_daemon_handle_uhid_event(
    int fd, const struct uhid_event* ev,
    pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_request_context_t* request_ctx) {
  if (ev == PCSC_FIDO_NULL || pending == PCSC_FIDO_NULL ||
      request_ctx == PCSC_FIDO_NULL) {
    return;
  }
  if (ev->type == UHID_OUTPUT) {
    const uint8_t* data;
    if (pcsc_fido_daemon_output_packet_data(ev, &data)) {
      /* Budget is per request: only INIT frames are charged, so a request
       * that needs continuation frames is never cut off mid-message.
       * CANCEL is not charged and is never dropped: it is how the session
       * owner disconnects the card, including after the budget is spent. */
      const uint32_t packet_cid = pcsc_fido_daemon_hid_packet_cid(data);
      const bool is_cancel =
          pcsc_fido_daemon_hid_is_cancel_packet(data, packet_cid);
      const bool is_init =
          (data[PCSC_FIDO_HID_OFF_CMD] & PCSC_FIDO_HID_TYPE_INIT) != 0u;
      if (is_init && !is_cancel && !pcsc_fido_rate_limit_allow_ctaphid()) {
        /* A new INIT abandons the channel's unfinished request even when it
         * is refused; otherwise the next request's continuation frames would
         * be appended to the old one. */
        if (pending->active && pending->cid == packet_cid) {
          pcsc_fido_daemon_pending_request_reset(pending);
        }
        if (pcsc_fido_daemon_hid_is_busy_answerable(data)) {
          (void)pcsc_fido_daemon_send_hid_error(
              fd, pcsc_fido_daemon_hid_packet_cid(data),
              PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
        }
      } else if (!pcsc_fido_daemon_request_assembler_feed(
                     fd, pending, data, dispatch_hid_request, request_ctx)) {
        pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "internal request assembly error");
      }
    }
  } else if (ev->type == UHID_CLOSE || ev->type == UHID_STOP) {
    pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                  "UHID client closed; resetting PC/SC session");
    pcsc_fido_daemon_pending_request_reset(pending);
    pcsc_fido_daemon_channels_drop_client(request_ctx->channels);
    pcsc_fido_bridge_reset();
  }
}

static int read_uhid_event(
    int fd, pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_request_context_t* request_ctx) {
  struct uhid_event ev;
  ssize_t got;
  /* The inbound UHID_OUTPUT event carries the raw CTAPHID request frame
   * (clientDataHash, encrypted-PIN / key-agreement material). Scope-exit scrub
   * mirrors the outbound UHID_INPUT2 scrub in uhid_transport.c. */
  PCSC_FIDO_SCRUB_ON_EXIT(&ev, sizeof(ev));
  got = read(fd, &ev, sizeof(ev));
  if (got < 0) {
    if (errno == EINTR || errno == EAGAIN) {
      return 0;
    }
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "%s: %s", "read /dev/uhid",
                  strerror(errno));
    return -1;
  }
  /* A short read is not a reason to exit: the next poll reads again.
   * POLLERR, POLLHUP, and POLLNVAL are what stop the loop. */
  if (got != (ssize_t)sizeof(ev)) {
    return 0;
  }
  pcsc_fido_daemon_handle_uhid_event(fd, &ev, pending, request_ctx);
  return 0;
}

int pcsc_fido_daemon_poll_uhid_event(
    const pcsc_fido_daemon_uhid_poll_ctx_t* ctx,
    pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_request_context_t* request_ctx) {
  struct pollfd fds[PCSC_FIDO_UHID_POLLFD_MAX];
  nfds_t nfds = 0;
  int signal_fd;
  int rv;
  if (ctx == PCSC_FIDO_NULL || pending == PCSC_FIDO_NULL ||
      request_ctx == PCSC_FIDO_NULL) {
    return -1;
  }
  if (pcsc_fido_daemon_stop_requested()) {
    return 1;
  }
  pcsc_fido_daemon_expire_idle_state(ctx->uhid_fd, pending,
                                     request_ctx->channels);
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
  rv = poll(fds, nfds,
            pcsc_fido_daemon_idle_poll_timeout_ms(
                pending, request_ctx->channels, ctx->poll_timeout_ms));
  if (rv < 0) {
    if (errno == EINTR) {
      return 0;
    }
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "%s: %s", "poll", strerror(errno));
    return -1;
  }
  if (rv == 0) {
    pcsc_fido_daemon_expire_idle_state(ctx->uhid_fd, pending,
                                       request_ctx->channels);
    return 0;
  }
  if (signal_fd >= 0 && (fds[0].revents & POLLIN) != 0) {
    pcsc_fido_daemon_drain_signal_wake();
    if (pcsc_fido_daemon_stop_requested()) {
      return 1;
    }
  }
  if ((fds[nfds - 1u].revents & POLLIN) != 0) {
    /* The packet may have arrived as the deadline elapsed. Check again
     * before handling it: a rate-limited frame never reaches the assembler,
     * which is the other place a stalled reassembly is expired. */
    pcsc_fido_daemon_expire_idle_state(ctx->uhid_fd, pending,
                                       request_ctx->channels);
    return read_uhid_event(ctx->uhid_fd, pending, request_ctx);
  }
  /* POLLERR, POLLHUP, or POLLNVAL with nothing to read would otherwise
   * make poll return immediately and spin, leaving the card connected. */
  for (nfds_t i = 0u; i < nfds; i++) {
    if ((fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "%s", "UHID poll: device closed");
      return -1;
    }
  }
  return 0;
}

int pcsc_fido_daemon_run_always_mode(int uhid_fd) {
  pcsc_fido_daemon_channels_t channels;
  pcsc_fido_daemon_request_context_t request_ctx;
  pcsc_fido_daemon_pending_request_t pending;
  pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {
      .uhid_fd = uhid_fd,
      .poll_timeout_ms = PCSC_FIDO_UHID_POLL_TIMEOUT_MS,
  };
  int status = 0;
  pcsc_fido_daemon_pending_request_reset(&pending);
  if (!pcsc_fido_daemon_create_uhid_device(uhid_fd)) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "%s: %s", "UHID_CREATE2",
                  strerror(errno));
    return 1;
  }
  request_ctx.fd = uhid_fd;
  pcsc_fido_daemon_channels_init(&channels);
  request_ctx.channels = &channels;
  pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                "virtual FIDO HID bridge ready; tap NFC key on browser prompt");
  while (!pcsc_fido_daemon_stop_requested()) {
    int rv =
        pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &request_ctx);
    if (rv < 0) {
      status = 1;
      break;
    }
    if (rv > 0) {
      break;
    }
  }
  pcsc_fido_daemon_pending_request_reset(&pending);
  pcsc_fido_daemon_channels_drop_client(&channels);
  pcsc_fido_bridge_reset();
  pcsc_fido_daemon_destroy_uhid_device(uhid_fd);
  return status;
}
