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

#include "pcsc_fido/attrs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define PCSC_FIDO_HAVE_STDCKDINT 1
#endif
#endif

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_try_add_size(size_t a,
                                                              size_t b,
                                                              size_t* out) {
  if (out == PCSC_FIDO_NULL) {
    return false;
  }
#if defined(PCSC_FIDO_HAVE_STDCKDINT)
  /* C23 ckd_* returns true when overflow/underflow occurred. */
  return !ckd_add(out, a, b);
#else
  if (a > SIZE_MAX - b) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_try_sub_size(size_t a,
                                                              size_t b,
                                                              size_t* out) {
  if (out == PCSC_FIDO_NULL) {
    return false;
  }
#if defined(PCSC_FIDO_HAVE_STDCKDINT)
  return !ckd_sub(out, a, b);
#else
  if (b > a) {
    return false;
  }
  *out = a - b;
  return true;
#endif
}

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_try_add_u16(uint16_t a,
                                                             uint16_t b,
                                                             uint16_t* out) {
  if (out == PCSC_FIDO_NULL) {
    return false;
  }
#if defined(PCSC_FIDO_HAVE_STDCKDINT)
  return !ckd_add(out, a, b);
#else
  if ((unsigned)a > (unsigned)UINT16_MAX - (unsigned)b) {
    return false;
  }
  *out = (uint16_t)((unsigned)a + (unsigned)b);
  return true;
#endif
}

/*
 * Type-generic checked addition. Dispatches on the result pointer type so a
 * caller cannot accidentally truncate a wide accumulator into a narrow field:
 * the destination width is what is range-checked. Extend the association list
 * when a new integer width needs an overflow-safe accumulator.
 */
#define PCSC_FIDO_TRY_ADD(a, b, out)   \
  _Generic((out),                      \
      size_t*: pcsc_fido_try_add_size, \
      uint16_t*: pcsc_fido_try_add_u16)((a), (b), (out))

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_span_ok(
    size_t offset, size_t count, size_t cap) PCSC_FIDO_UNSEQUENCED {
  size_t end = 0u;
  return pcsc_fido_try_add_size(offset, count, &end) && end <= cap;
}

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_bounded_strlen(const char* s,
                                                                size_t cap,
                                                                size_t* len) {
  if (len == PCSC_FIDO_NULL) {
    return false;
  }
  /* Fail closed: never leave *len indeterminate for callers that mix the
   * result into offset math before checking the return value. */
  *len = 0u;
  if (s == PCSC_FIDO_NULL) {
    return false;
  }
  for (size_t i = 0u; i < cap; i++) {
    if (s[i] == '\0') {
      *len = i;
      return true;
    }
  }
  return false;
}

PCSC_FIDO_NODISCARD bool pcsc_fido_copy_bytes(void* dst, size_t dst_cap,
                                              size_t dst_off, const void* src,
                                              size_t src_len);

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_copy_cstr(char* dst,
                                                           size_t dst_cap,
                                                           const char* src) {
  size_t len = 0u;
  if (dst == PCSC_FIDO_NULL || dst_cap == 0u) {
    return false;
  }
  if (src == PCSC_FIDO_NULL) {
    dst[0] = '\0';
    return true;
  }
  if (!pcsc_fido_bounded_strlen(src, dst_cap, &len) || len + 1u > dst_cap) {
    return false;
  }
  if (len == 0u) {
    dst[0] = '\0';
    return true;
  }
  if (!pcsc_fido_copy_bytes(dst, dst_cap, 0u, src, len)) {
    return false;
  }
  dst[len] = '\0';
  return true;
}

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_copy_cstr_len(char* dst,
                                                               size_t dst_cap,
                                                               const char* src,
                                                               size_t src_len) {
  size_t required = 0u;
  if (dst == PCSC_FIDO_NULL || dst_cap == 0u) {
    return false;
  }
  if (src == PCSC_FIDO_NULL && src_len != 0u) {
    return false;
  }
  if (!pcsc_fido_try_add_size(src_len, 1u, &required) || required > dst_cap) {
    return false;
  }
  if (src_len == 0u) {
    dst[0] = '\0';
    return true;
  }
  if (!pcsc_fido_copy_bytes(dst, dst_cap, 0u, src, src_len)) {
    return false;
  }
  dst[src_len] = '\0';
  return true;
}

PCSC_FIDO_NODISCARD bool pcsc_fido_move_bytes(void* data, size_t* len,
                                              size_t offset, size_t count);

void pcsc_fido_zero_bytes(void* ptr, size_t len);
void pcsc_fido_fill_bytes(void* ptr, size_t len, uint8_t value);

/* Erase helper: C23 memset_explicit, else glibc/BSD explicit_bzero, else a
 * volatile byte loop. Out-of-line so the libc feature macro the second tier
 * needs stays confined to mem_util.c. Does not run on _exit/abort; see
 * PCSC_FIDO_SCRUB_ON_EXIT. */
void pcsc_fido_secure_clear(void* ptr, size_t len);

/* Scope-exit secure wipe. Declare after the buffer it guards; the wipe runs on
 * every exit from the enclosing scope (return, goto, fallthrough), so no
 * early-return path can skip it. Guards fire in reverse declaration order.
 * cleanup does not run on _exit/abort/fatal signals; the daemon refuses to
 * start if it cannot set PR_SET_DUMPABLE=0 and RLIMIT_CORE=0. */
typedef struct {
  void* ptr;
  size_t len;
} pcsc_fido_scrub_guard_t;

static inline void pcsc_fido_scrub_guard_fire(pcsc_fido_scrub_guard_t* guard) {
  if (guard != PCSC_FIDO_NULL && guard->ptr != PCSC_FIDO_NULL) {
    pcsc_fido_secure_clear(guard->ptr, guard->len);
  }
}

#define PCSC_FIDO_SCRUB_ON_EXIT(ptr, len)                                    \
  pcsc_fido_scrub_guard_t PCSC_FIDO_CONCAT(pcsc_fido_scrub_guard_, __LINE__) \
      PCSC_FIDO_CLEANUP(pcsc_fido_scrub_guard_fire)                          \
          PCSC_FIDO_MAYBE_UNUSED = {(ptr), (len)}
