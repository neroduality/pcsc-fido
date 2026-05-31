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

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/daemon_signals.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal stop flag requires lock-free atomic int");

static atomic_int g_stop;
static atomic_int g_signal_read_fd = -1;
static atomic_int g_signal_write_fd = -1;
static atomic_bool g_signals_installed;

static void close_fd_if_open(int fd) {
  if (fd >= 0) {
    (void)close(fd);
  }
}

static bool set_fd_flags(int fd) {
  int flags = fcntl(fd, F_GETFD);
  int status = fcntl(fd, F_GETFL);
  if (flags < 0 || status < 0) {
    return false;
  }
  if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
    return false;
  }
  if (fcntl(fd, F_SETFL, status | O_NONBLOCK) != 0) {
    return false;
  }
  return true;
}

static bool create_signal_pipe(int fds[2]) {
  if (pipe(fds) != 0) {
    return false;
  }
  if (!set_fd_flags(fds[0]) || !set_fd_flags(fds[1])) {
    close_fd_if_open(fds[0]);
    close_fd_if_open(fds[1]);
    fds[0] = -1;
    fds[1] = -1;
    return false;
  }
  return true;
}

static void block_term_signals(sigset_t *previous) {
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGINT);
  sigaddset(&block, SIGTERM);
  (void)sigprocmask(SIG_BLOCK, &block, previous);
}

static void on_signal(int signo PCSC_FIDO_MAYBE_UNUSED) {
  const int saved_errno = errno;
  const int write_fd = atomic_load_explicit(&g_signal_write_fd, memory_order_relaxed);
  const uint8_t wake = 1u;
  atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
  if (write_fd >= 0) {
    ssize_t wrote = write(write_fd, &wake, sizeof(wake));
    if (wrote < 0) {
      /* Best-effort wake; the stop flag is authoritative. */
    }
  }
  errno = saved_errno;
}

bool pcsc_fido_daemon_signals_init(void) {
  struct sigaction sa;
  sigset_t previous;
  int fds[2] = {-1, -1};

  if (atomic_load_explicit(&g_signals_installed, memory_order_acquire)) {
    return true;
  }
  block_term_signals(&previous);
  if (!create_signal_pipe(fds)) {
    (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
    return false;
  }
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  pcsc_fido_daemon_reset_stop_request();
  atomic_store_explicit(&g_signal_read_fd, fds[0], memory_order_release);
  atomic_store_explicit(&g_signal_write_fd, fds[1], memory_order_release);
  if (sigaction(SIGINT, &sa, nullptr) != 0 || sigaction(SIGTERM, &sa, nullptr) != 0) {
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGINT, &sa, nullptr);
    (void)sigaction(SIGTERM, &sa, nullptr);
    atomic_store_explicit(&g_signal_read_fd, -1, memory_order_release);
    atomic_store_explicit(&g_signal_write_fd, -1, memory_order_release);
    close_fd_if_open(fds[0]);
    close_fd_if_open(fds[1]);
    (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
    return false;
  }
  atomic_store_explicit(&g_signals_installed, true, memory_order_release);
  (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
  return true;
}

void pcsc_fido_daemon_signals_shutdown(void) {
  struct sigaction sa;
  sigset_t previous;
  int read_fd;
  int write_fd;

  if (!atomic_load_explicit(&g_signals_installed, memory_order_acquire)) {
    return;
  }
  block_term_signals(&previous);
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  (void)sigaction(SIGINT, &sa, nullptr);
  (void)sigaction(SIGTERM, &sa, nullptr);
  read_fd = atomic_exchange_explicit(&g_signal_read_fd, -1, memory_order_acq_rel);
  write_fd = atomic_exchange_explicit(&g_signal_write_fd, -1, memory_order_acq_rel);
  atomic_store_explicit(&g_signals_installed, false, memory_order_release);
  close_fd_if_open(read_fd);
  close_fd_if_open(write_fd);
  (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
}

int pcsc_fido_daemon_signal_poll_fd(void) {
  if (!atomic_load_explicit(&g_signals_installed, memory_order_acquire)) {
    return -1;
  }
  return atomic_load_explicit(&g_signal_read_fd, memory_order_acquire);
}

void pcsc_fido_daemon_drain_signal_wake(void) {
  uint8_t buf[64];
  int fd = pcsc_fido_daemon_signal_poll_fd();
  if (fd < 0) {
    return;
  }
  for (;;) {
    ssize_t got = read(fd, buf, sizeof(buf));
    if (got > 0) {
      continue;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    return;
  }
}

bool pcsc_fido_daemon_stop_requested(void) {
  return atomic_load_explicit(&g_stop, memory_order_relaxed) != 0;
}

void pcsc_fido_daemon_reset_stop_request(void) {
  atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
}

#if defined(PCSC_FIDO_TESTING)
void pcsc_fido_daemon_test_request_stop(void) {
  on_signal(SIGTERM);
}
#endif
