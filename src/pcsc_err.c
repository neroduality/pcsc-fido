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

static const char ERR_TRUNCATED[] = " (truncated)";

static void pcsc_fido_err_mark_truncated(char* err, size_t err_cap) {
  size_t mark_off = 0u;
  size_t mark_len;
  if (err == PCSC_FIDO_NULL || err_cap == 0u) {
    return;
  }
  mark_len = sizeof(ERR_TRUNCATED) - 1u;
  if (err_cap <= mark_len + 1u) {
    err[0] = '\0';
    return;
  }
  if (!pcsc_fido_try_sub_size(err_cap, 1u, &mark_off) ||
      !pcsc_fido_try_sub_size(mark_off, mark_len, &mark_off)) {
    err[0] = '\0';
    return;
  }
  /* mark_off = err_cap - 1 - mark_len, so the literal's NUL lands exactly at
   * err[err_cap - 1]. Route the copy through the bounds-checked helper so the
   * span is re-validated even inside this wrapper file. */
  (void)pcsc_fido_copy_bytes(err, err_cap, mark_off, ERR_TRUNCATED,
                             sizeof(ERR_TRUNCATED));
}

static bool pcsc_fido_vformat_err(char* err, size_t err_cap, const char* fmt,
                                  va_list args) {
#ifndef __clang_analyzer__
  va_list args_copy;
  int written;
  va_copy(args_copy, args);
  /* Bounded printf wrapper: fmt is validated by the printf format attribute on
   * the public API; the libc call still requires a non-literal format. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
  written = vsnprintf(err, err_cap, fmt, args_copy);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  va_end(args_copy);
  if (written < 0) {
    err[0] = '\0';
    return false;
  }
  if ((size_t)written >= err_cap) {
    pcsc_fido_err_mark_truncated(err, err_cap);
    return false;
  }
  return true;
#else
  (void)fmt;
  (void)args;
  if (err == PCSC_FIDO_NULL || err_cap < 1u) {
    return false;
  }
  err[0] = '\0';
  return false;
#endif
}

bool pcsc_fido_format_err(char* err, size_t err_cap, const char* fmt, ...) {
#ifndef __clang_analyzer__
  va_list args;
  bool ok;
  if (err == PCSC_FIDO_NULL || err_cap == 0u || fmt == PCSC_FIDO_NULL) {
    return false;
  }
  va_start(args, fmt);
  ok = pcsc_fido_vformat_err(err, err_cap, fmt, args);
  va_end(args);
  return ok;
#else
  (void)fmt;
  (void)pcsc_fido_vformat_err;
  (void)pcsc_fido_err_mark_truncated;
  if (err == PCSC_FIDO_NULL || err_cap < 1u) {
    return false;
  }
  err[0] = '\0';
  return false;
#endif
}

void pcsc_fido_set_err(char* err, size_t err_cap, const char* msg) {
  (void)pcsc_fido_format_err(err, err_cap, "%s",
                             msg != PCSC_FIDO_NULL ? msg : "unknown error");
}

void pcsc_fido_set_pcsc_err(char* err, size_t err_cap, const char* stage,
                            long rv) {
  (void)pcsc_fido_format_err(err, err_cap, "%s: PC/SC 0x%08lx",
                             stage != PCSC_FIDO_NULL ? stage : "unknown stage",
                             (unsigned long)rv);
}
