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

#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/exchange_orchestrator.h"

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_util.h"
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
  const uint8_t* payload;
  size_t payload_len;
  uint8_t response[PCSC_FIDO_DAEMON_PENDING_MAX];
  size_t response_len;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  bool ok;
  bool done;
  pthread_mutex_t mutex;
  /* Main thread only: nonce of a CTAPHID_INIT that resyncs the channel. */
  uint8_t resync_nonce[PCSC_FIDO_HID_INIT_NONCE_LEN];
} exchange_job_t;

/* Why the response will not be delivered, weakest first; the strongest seen
 * wins (a resync answers the INIT instead, a closed client gets nothing). */
typedef enum {
  PCSC_FIDO_EXCHANGE_RUNNING = 0,
  PCSC_FIDO_EXCHANGE_CANCELLED,
  PCSC_FIDO_EXCHANGE_RESYNC,
  PCSC_FIDO_EXCHANGE_CLIENT_CLOSED,
} exchange_abort_t;

static atomic_bool g_exchange_in_flight;

#if defined(PCSC_FIDO_TESTING)
size_t pcsc_fido_daemon_exchange_job_size(void) {
  return sizeof(exchange_job_t);
}
#endif

/* One UHID event read while an exchange is in flight: close/stop, and CANCEL
 * or INIT (resync) on the active CID abort the exchange; any other new request
 * is answered CHANNEL_BUSY and other frames are dropped. */
static exchange_abort_t handle_drained_event(
    int fd, const struct uhid_event* ev, uint32_t active_cid,
    uint8_t resync_nonce[PCSC_FIDO_HID_INIT_NONCE_LEN]) {
  const uint8_t* data;
  if (ev->type == UHID_CLOSE || ev->type == UHID_STOP) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "UHID client closed during PC/SC exchange");
    return PCSC_FIDO_EXCHANGE_CLIENT_CLOSED;
  }
  if (!pcsc_fido_daemon_output_packet_data(ev, &data)) {
    return PCSC_FIDO_EXCHANGE_RUNNING;
  }
  if (pcsc_fido_daemon_hid_is_cancel_packet(data, active_cid)) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "CTAPHID CANCEL received during PC/SC exchange");
    return PCSC_FIDO_EXCHANGE_CANCELLED;
  }
  /* INIT on the busy channel abandons its transaction and resyncs it
   * (CTAP 2.3 §11.2.9.1.3); the INIT is answered once the worker is done. */
  if (pcsc_fido_daemon_hid_is_init_packet(data, active_cid)) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "CTAPHID INIT received during PC/SC exchange; resyncing");
    (void)pcsc_fido_copy_bytes(resync_nonce, PCSC_FIDO_HID_INIT_NONCE_LEN, 0u,
                               data + PCSC_FIDO_HID_OFF_INIT_DATA,
                               PCSC_FIDO_HID_INIT_NONCE_LEN);
    return PCSC_FIDO_EXCHANGE_RESYNC;
  }
  if (pcsc_fido_daemon_hid_is_busy_answerable(data)) {
    (void)pcsc_fido_daemon_send_hid_error(fd,
                                          pcsc_fido_daemon_hid_packet_cid(data),
                                          PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
  }
  return PCSC_FIDO_EXCHANGE_RUNNING;
}

/* Returns the strongest abort among the events drained. */
static exchange_abort_t drain_exchange_events(
    int fd, uint32_t active_cid,
    uint8_t resync_nonce[PCSC_FIDO_HID_INIT_NONCE_LEN]) {
  exchange_abort_t strongest = PCSC_FIDO_EXCHANGE_RUNNING;
  for (;;) {
    struct pollfd pfd;
    struct uhid_event ev;
    /* Frames drained here may be full CTAPHID requests from another channel
     * (answered CHANNEL_BUSY); scope-exit scrub at each iteration end. */
    PCSC_FIDO_SCRUB_ON_EXIT(&ev, sizeof(ev));
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1u, 0) < 0) {
      if (errno == EINTR) {
        continue;
      }
      return PCSC_FIDO_EXCHANGE_CLIENT_CLOSED;
    }
    if (pfd.revents == 0) {
      return strongest;
    }
    /* Read a last event if one is waiting, then a later pass sees the
     * hangup on its own and aborts. An empty or short read has consumed
     * the stream, so it cannot be parsed again. */
    if ((pfd.revents & POLLIN) != 0) {
      const ssize_t got = read(fd, &ev, sizeof(ev));
      if (got < 0) {
        if (errno == EINTR) {
          continue;
        }
        /* EAGAIN: poll raced with the read; the keepalive loop will drain
         * again. Any other error means the fd is unusable. */
        if (errno == EAGAIN) {
          return strongest;
        }
        return PCSC_FIDO_EXCHANGE_CLIENT_CLOSED;
      }
      if (got != (ssize_t)sizeof(ev)) {
        return PCSC_FIDO_EXCHANGE_CLIENT_CLOSED;
      }
    } else if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return PCSC_FIDO_EXCHANGE_CLIENT_CLOSED;
    } else {
      return strongest;
    }
    {
      const exchange_abort_t seen =
          handle_drained_event(fd, &ev, active_cid, resync_nonce);
      if (seen > strongest) {
        strongest = seen;
      }
    }
  }
}

static void* exchange_thread_main(void* arg) {
  exchange_job_t* job = (exchange_job_t*)arg;
  if (job == PCSC_FIDO_NULL) {
    return PCSC_FIDO_NULL;
  }
  bool ok = pcsc_fido_bridge_exchange(
      PCSC_FIDO_NULL, job->cmd, job->payload, job->payload_len, job->response,
      sizeof(job->response), &job->response_len, job->err, sizeof(job->err));
  pthread_mutex_lock(&job->mutex);
  job->ok = ok;
  job->done = true;
  pthread_mutex_unlock(&job->mutex);
  return PCSC_FIDO_NULL;
}

/* Waits the full interval even once a stop is requested: the worker can only
 * be joined when it finishes, so returning early would just spin the loop. */
static void wait_keepalive_interval(void) {
  const int timeout_ms = PCSC_FIDO_EXCHANGE_KEEPALIVE_INTERVAL_MS;
  int signal_fd = pcsc_fido_daemon_signal_poll_fd();
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
        .tv_nsec = (long)timeout_ms * PCSC_FIDO_UTIL_NS_PER_MS,
    };
    (void)nanosleep(&ts, PCSC_FIDO_NULL);
  }
}

bool pcsc_fido_daemon_run_exchange_with_keepalive(
    int fd, uint32_t cid, uint8_t cmd, const uint8_t* payload,
    size_t payload_len, uint8_t* response, size_t response_cap,
    size_t* response_len, char* err, size_t err_cap) {
  exchange_job_t job;
  /* job.response holds the full CTAP response until copied out; scope-exit
   * scrub (also covers the early-return paths before the thread starts). */
  PCSC_FIDO_SCRUB_ON_EXIT(&job, sizeof(job));
  pthread_t thread;
  bool done = false;
  exchange_abort_t aborted = PCSC_FIDO_EXCHANGE_RUNNING;
  bool stop_logged = false;
  bool ok;
  unsigned keepalive_count = 0u;
  bool expected_in_flight = false;
  if (response == PCSC_FIDO_NULL || response_len == PCSC_FIDO_NULL ||
      err == PCSC_FIDO_NULL || err_cap == 0u) {
    /* The handler may already have charged this call. Leaving the mark set
     * would make the next exchange free. */
    pcsc_fido_rate_limit_release_exchange_charge();
    return false;
  }
  if (!atomic_compare_exchange_strong(&g_exchange_in_flight,
                                      &expected_in_flight, true)) {
    pcsc_fido_rate_limit_release_exchange_charge();
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_EXCHANGE_IN_PROGRESS);
    return false;
  }
  pcsc_fido_zero_bytes(&job, sizeof(job));
  job.cmd = cmd;
  job.payload = payload;
  job.payload_len = payload_len;
  if (pthread_mutex_init(&job.mutex, PCSC_FIDO_NULL) != 0) {
    pcsc_fido_rate_limit_release_exchange_charge();
    atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_EXCHANGE_MUTEX);
    return false;
  }
  if (pthread_create(&thread, PCSC_FIDO_NULL, exchange_thread_main, &job) !=
      0) {
    pcsc_fido_rate_limit_release_exchange_charge();
    pthread_mutex_destroy(&job.mutex);
    atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_EXCHANGE_THREAD);
    return false;
  }
  while (!done) {
    exchange_abort_t drained;
    wait_keepalive_interval();
    drained = drain_exchange_events(fd, cid, job.resync_nonce);
    if (drained > aborted) {
      aborted = drained;
    }
    if (pcsc_fido_daemon_stop_requested()) {
      if (!stop_logged) {
        stop_logged = true;
        pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                      "stop requested during PC/SC exchange");
      }
      if (aborted < PCSC_FIDO_EXCHANGE_CANCELLED) {
        aborted = PCSC_FIDO_EXCHANGE_CANCELLED;
      }
    }
    /* Re-sent every interval: a cancel that lands before the worker clears
     * the flag at the start of its exchange would otherwise be lost. */
    if (aborted != PCSC_FIDO_EXCHANGE_RUNNING) {
      pcsc_fido_bridge_cancel();
    }
    pthread_mutex_lock(&job.mutex);
    done = job.done;
    pthread_mutex_unlock(&job.mutex);
    /* Close and resync have nobody left waiting on this request.
     * CANCEL still gets keepalives: SCardCancel does not interrupt
     * SCardTransmit, and the host drops the transaction if the interval
     * goes quiet before CTAP2_ERR_KEEPALIVE_CANCEL can be sent. */
    if (!done && aborted < PCSC_FIDO_EXCHANGE_RESYNC) {
      (void)pcsc_fido_daemon_send_keepalive(fd, cid);
      keepalive_count++;
      if ((keepalive_count % PCSC_FIDO_KEEPALIVE_LOG_EVERY) == 0u) {
        pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                      "PC/SC exchange still running cmd=0x%02X elapsed~%us",
                      cmd,
                      (keepalive_count * PCSC_FIDO_KEEPALIVE_ELAPSED_NUM) /
                          PCSC_FIDO_KEEPALIVE_ELAPSED_DEN);
      }
    }
  }
  (void)pthread_join(thread, PCSC_FIDO_NULL);
  /* CANCEL, INIT, or close can land after the last poll inside the loop
   * and before the worker is joined. Read that before copying a success. */
  {
    const exchange_abort_t drained =
        drain_exchange_events(fd, cid, job.resync_nonce);
    if (drained > aborted) {
      aborted = drained;
    }
  }
  ok = job.ok;
  if (aborted == PCSC_FIDO_EXCHANGE_CLIENT_CLOSED) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CLIENT_CLOSED);
    ok = false;
  } else if (aborted == PCSC_FIDO_EXCHANGE_RESYNC) {
    if (!pcsc_fido_copy_bytes(response, response_cap, 0u, job.resync_nonce,
                              sizeof(job.resync_nonce))) {
      pcsc_fido_set_err(err, err_cap, "response buffer too small");
    } else {
      *response_len = sizeof(job.resync_nonce);
      pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_RESYNC);
    }
    ok = false;
  } else if (aborted == PCSC_FIDO_EXCHANGE_CANCELLED) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED);
    ok = false;
  } else if (ok) {
    if (job.response_len > response_cap ||
        !pcsc_fido_copy_bytes(response, response_cap, 0u, job.response,
                              job.response_len)) {
      pcsc_fido_set_err(err, err_cap, "response buffer too small");
      ok = false;
    } else {
      *response_len = job.response_len;
    }
  } else {
    pcsc_fido_set_err(err, err_cap,
                      job.err[0] != '\0' ? job.err : "PC/SC bridge failed");
  }
  pthread_mutex_destroy(&job.mutex);
  atomic_store_explicit(&g_exchange_in_flight, false, memory_order_release);
  /* The worker adopted the precharge inside the bridge. Drop only this
   * thread's count; releasing here would steal a charge another thread
   * published while the worker ran. */
  pcsc_fido_rate_limit_detach_local_charge();
  return ok;
}
