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

/* Optimized builds define _FORTIFY_SOURCE, and glibc then compiles read() and
 * poll() to __read_chk / __poll_chk wherever it cannot prove the buffer size
 * at compile time (Clang far more often than GCC). Those calls bypass
 * -Wl,--wrap=read / --wrap=poll, so tests that wrap read or poll also link
 * this file with --wrap=__read_chk / --wrap=__poll_chk. Both spellings then
 * reach the test's own __wrap_read / __wrap_poll, after the same size checks
 * the _chk entry points make. */

#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>

extern ssize_t __wrap_read(int fd, void* buf, size_t count);
extern int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout);

ssize_t __wrap___read_chk(int fd, void* buf, size_t nbytes, size_t buflen) {
  if (nbytes > buflen) {
    abort();
  }
  return __wrap_read(fd, buf, nbytes);
}

int __wrap___poll_chk(struct pollfd* fds, nfds_t nfds, int timeout,
                      size_t fdslen) {
  if (fdslen / sizeof(*fds) < nfds) {
    abort();
  }
  return __wrap_poll(fds, nfds, timeout);
}
