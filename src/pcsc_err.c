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

#include "pcsc_fido/pcsc_err.h"

#include "pcsc_fido/mem_util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char k_err_truncated[] = " (truncated)";

static void pcsc_fido_err_mark_truncated(char *err, size_t err_cap) {
  size_t mark_off = 0u;
  size_t mark_len;
  if (err == nullptr || err_cap == 0u) {
    return;
  }
  mark_len = sizeof(k_err_truncated) - 1u;
  if (err_cap <= mark_len + 1u) {
    err[0] = '\0';
    return;
  }
  if (!pcsc_fido_try_sub_size(err_cap, 1u, &mark_off) ||
      !pcsc_fido_try_sub_size(mark_off, mark_len, &mark_off)) {
    err[0] = '\0';
    return;
  }
  memcpy(err + mark_off, k_err_truncated, mark_len);
  err[err_cap - 1u] = '\0';
}

bool pcsc_fido_format_err(char *err, size_t err_cap, const char *fmt, ...) {
  va_list args;
  int written;
  if (err == nullptr || err_cap == 0u || fmt == nullptr) {
    return false;
  }
  va_start(args, fmt);
  written = vsnprintf(err, err_cap, fmt, args);
  va_end(args);
  if (written < 0) {
    err[0] = '\0';
    return false;
  }
  if ((size_t)written >= err_cap) {
    pcsc_fido_err_mark_truncated(err, err_cap);
    return false;
  }
  return true;
}

void pcsc_fido_set_err(char *err, size_t err_cap, const char *msg) {
  (void)pcsc_fido_format_err(err, err_cap, "%s", msg != nullptr ? msg : "unknown error");
}

void pcsc_fido_set_pcsc_err(char *err, size_t err_cap, const char *stage, long rv) {
  (void)pcsc_fido_format_err(err, err_cap, "%s: PC/SC 0x%08lx",
                             stage != nullptr ? stage : "unknown stage", (unsigned long)rv);
}
