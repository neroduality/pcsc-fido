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

#pragma once

#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

/*
 * Test seams for `-Wl,--wrap=NAME`: the linker sends calls to NAME into
 * __wrap_NAME and resolves __real_NAME to the original, so both must keep
 * external linkage. Each test defines only the wrappers its link line names.
 */

int __real_clock_gettime(clockid_t clock_id, struct timespec* ts);
int __wrap_clock_gettime(clockid_t clock_id, struct timespec* ts);

int __real_nanosleep(const struct timespec* req, struct timespec* rem);
int __wrap_nanosleep(const struct timespec* req, struct timespec* rem);

time_t __wrap_time(time_t* t);

int __real_open(const char* pathname, int flags, ...);
int __wrap_open(const char* pathname, int flags, ...);
int __wrap___open_2(const char* pathname, int flags);

int __real_close(int fd);
int __wrap_close(int fd);

ssize_t __real_read(int fd, void* buf, size_t count);
ssize_t __wrap_read(int fd, void* buf, size_t count);
ssize_t __wrap___read_chk(int fd, void* buf, size_t nbytes, size_t buflen);

ssize_t __real_write(int fd, const void* buf, size_t count);
ssize_t __wrap_write(int fd, const void* buf, size_t count);

int __real_poll(struct pollfd* fds, nfds_t nfds, int timeout);
int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout);
int __wrap___poll_chk(struct pollfd* fds, nfds_t nfds, int timeout,
                      size_t fdslen);

int __real_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                          void* (*start_routine)(void*), void* arg);
int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                          void* (*start_routine)(void*), void* arg);

int __real_pthread_join(pthread_t thread, void** retval);
int __wrap_pthread_join(pthread_t thread, void** retval);

void __real_pcsc_fido_secure_clear(void* ptr, size_t len);
void __wrap_pcsc_fido_secure_clear(void* ptr, size_t len);
