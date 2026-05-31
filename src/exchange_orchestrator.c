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

#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/exchange_orchestrator.h"

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"

#include <errno.h>
#include <linux/uhid.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  uint8_t cmd;
  const uint8_t *payload;
  size_t payload_len;
  uint8_t response[PCSC_FIDO_DAEMON_PENDING_MAX];
  size_t response_len;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  bool ok;
  bool done;
  pthread_mutex_t mutex;
} exchange_job_t;

static atomic_bool g_exchange_in_flight;

static bool drain_exchange_events(int fd, uint32_t active_cid) {
  bool cancel_seen = false;
  for (;;) {
    struct pollfd pfd;
    struct uhid_event ev;
    ssize_t got;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1u, 0) <= 0 || (pfd.revents & POLLIN) == 0) {
      return cancel_seen;
    }
    got = read(fd, &ev, sizeof(ev));
    if (got != (ssize_t)sizeof(ev)) {
      continue;
    }
    if (ev.type == UHID_CLOSE || ev.type == UHID_STOP) {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "UHID client closed during PC/SC exchange");
      pcsc_fido_bridge_cancel();
      cancel_seen = true;
      continue;
    }
    {
      const uint8_t *data;
      if (!pcsc_fido_daemon_output_packet_data(&ev, &data)) {
        continue;
      }
      if (pcsc_fido_daemon_hid_is_cancel_packet(data, active_cid)) {
        pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "CTAPHID CANCEL received during PC/SC exchange");
        pcsc_fido_bridge_cancel();
        cancel_seen = true;
      } else {
        (void)pcsc_fido_daemon_send_hid_error(fd, pcsc_fido_daemon_hid_packet_cid(data),
                                              PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
      }
    }
  }
}

static void *exchange_thread_main(void *arg) {
  exchange_job_t *job = (exchange_job_t *)arg;
  if (job == nullptr) {
    return nullptr;
  }
  bool ok = pcsc_fido_bridge_exchange(nullptr, job->cmd, job->payload, job->payload_len,
                                      job->response, sizeof(job->response), &job->response_len,
                                      job->err, sizeof(job->err));
  pthread_mutex_lock(&job->mutex);
  job->ok = ok;
  job->done = true;
  pthread_mutex_unlock(&job->mutex);
  return nullptr;
}

static void wait_keepalive_interval(void) {
  const int timeout_ms = PCSC_FIDO_EXCHANGE_KEEPALIVE_INTERVAL_MS;
  int signal_fd = pcsc_fido_daemon_signal_poll_fd();
  if (pcsc_fido_daemon_stop_requested()) {
    return;
  }
  if (signal_fd >= 0) {
    struct pollfd pfd = {
      .fd = signal_fd,
      .events = POLLIN,
      .revents = 0,
    };
    int rv;
    do {
      rv = poll(&pfd, 1u, timeout_ms);
    } while (rv < 0 && errno == EINTR && !pcsc_fido_daemon_stop_requested());
    if (rv > 0 && (pfd.revents & POLLIN) != 0) {
      pcsc_fido_daemon_drain_signal_wake();
    }
    return;
  }
  {
    struct timespec ts = {
      .tv_sec = 0,
      .tv_nsec = (long)timeout_ms * 1000000L,
    };
    (void)nanosleep(&ts, nullptr);
  }
}

bool pcsc_fido_daemon_run_exchange_with_keepalive(int fd, uint32_t cid, uint8_t cmd,
                                                  const uint8_t *payload, size_t payload_len,
                                                  uint8_t *response, size_t response_cap,
                                                  size_t *response_len, char *err, size_t err_cap) {
  exchange_job_t job;
  pthread_t thread;
  bool done = false;
  bool cancelled = false;
  bool ok;
  unsigned keepalive_count = 0u;
  bool expected_in_flight = false;
  if (response == nullptr || response_len == nullptr || err == nullptr || err_cap == 0u) {
    return false;
  }
  if (!atomic_compare_exchange_strong(&g_exchange_in_flight, &expected_in_flight, true)) {
    pcsc_fido_set_err(err, err_cap, "exchange already in progress");
    return false;
  }
  memset(&job, 0, sizeof(job));
  job.cmd = cmd;
  job.payload = payload;
  job.payload_len = payload_len;
  if (pthread_mutex_init(&job.mutex, nullptr) != 0) {
    atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
    pcsc_fido_set_err(err, err_cap, "failed to initialize PC/SC exchange mutex");
    return false;
  }
  if (pthread_create(&thread, nullptr, exchange_thread_main, &job) != 0) {
    pthread_mutex_destroy(&job.mutex);
    atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
    pcsc_fido_set_err(err, err_cap, "failed to start PC/SC exchange thread");
    return false;
  }
  while (!done) {
    wait_keepalive_interval();
    if (drain_exchange_events(fd, cid)) {
      cancelled = true;
    }
    if (pcsc_fido_daemon_stop_requested()) {
      pcsc_fido_log(PCSC_FIDO_LOG_INFO, "stop requested during PC/SC exchange");
      pcsc_fido_bridge_cancel();
      cancelled = true;
    }
    pthread_mutex_lock(&job.mutex);
    done = job.done;
    pthread_mutex_unlock(&job.mutex);
    if (!done) {
      (void)pcsc_fido_daemon_send_keepalive(fd, cid);
      keepalive_count++;
      if ((keepalive_count % 8u) == 0u) {
        pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "PC/SC exchange still running cmd=0x%02X elapsed~%us",
                      cmd, (unsigned)((keepalive_count * 3u) / 4u));
      }
    }
  }
  (void)pthread_join(thread, nullptr);
  ok = job.ok;
  if (cancelled) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED);
    ok = false;
  } else if (ok) {
    if (job.response_len > response_cap) {
      pcsc_fido_set_err(err, err_cap, "response buffer too small");
      ok = false;
    } else if (!pcsc_fido_copy_bytes(response, response_cap, 0u, job.response, job.response_len)) {
      pcsc_fido_set_err(err, err_cap, "response buffer too small");
      ok = false;
    } else {
      *response_len = job.response_len;
    }
  } else {
    pcsc_fido_set_err(err, err_cap, job.err[0] != '\0' ? job.err : "PC/SC bridge failed");
  }
  pthread_mutex_destroy(&job.mutex);
  pcsc_fido_secure_clear(&job, sizeof(job));
  atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
  return ok;
}
