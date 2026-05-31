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

#include <limits.h>
#include <stdint.h>
#include <time.h>

static inline time_t pcsc_fido_add_seconds_saturating(time_t base, unsigned seconds) {
  if (base > (time_t)(LONG_MAX - (long)seconds)) {
    return (time_t)LONG_MAX;
  }
  return base + (time_t)seconds;
}

static inline int pcsc_fido_timeout_until_ms(time_t deadline) {
  time_t now = time(nullptr);
  if (deadline <= now) {
    return 0;
  }
  if (deadline - now > (time_t)(INT32_MAX / 1000)) {
    return INT32_MAX;
  }
  return (int)((deadline - now) * 1000);
}

static inline void pcsc_fido_sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000L;
  ts.tv_nsec = (ms % 1000L) * 1000000L;
  (void)nanosleep(&ts, nullptr);
}
