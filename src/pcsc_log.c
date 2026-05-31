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

#include "pcsc_fido/pcsc_bridge_debug.h"
#include "pcsc_fido/pcsc_log.h"

#include <stdio.h>
#include <stdarg.h>

void pcsc_fido_log(pcsc_fido_log_level_t level, const char *fmt, ...) {
  va_list args;
  if (fmt == nullptr) {
    return;
  }
  if (level == PCSC_FIDO_LOG_DEBUG && !pcsc_fido_bridge_debug_enabled()) {
    return;
  }
  va_start(args, fmt);
  fputs("pcsc-fido: ", stderr);
  (void)vfprintf(stderr, fmt, args);
  fputc('\n', stderr);
  va_end(args);
}
