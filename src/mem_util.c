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

#include "pcsc_fido/mem_util.h"

#include <stdint.h>
#include <string.h>

bool pcsc_fido_copy_bytes(void* dst, size_t dst_cap, size_t dst_off,
                          const void* src, size_t src_len) {
  if (dst == PCSC_FIDO_NULL || (src == PCSC_FIDO_NULL && src_len != 0u)) {
    return false;
  }
  if (!pcsc_fido_span_ok(dst_off, src_len, dst_cap)) {
    return false;
  }
  if (src_len == 0u) {
    return true;
  }
  /* memmove keeps the bounded-copy contract defined even when a caller passes
   * overlapping ranges; memcpy would be undefined behaviour there. */
  memmove((uint8_t*)dst + dst_off, src, src_len);
  return true;
}

bool pcsc_fido_move_bytes(void* data, size_t* len, size_t offset,
                          size_t count) {
  size_t tail = 0u;
  if (data == PCSC_FIDO_NULL || len == PCSC_FIDO_NULL) {
    return false;
  }
  if (!pcsc_fido_try_sub_size(*len, offset, &tail) || count > tail) {
    return false;
  }
  if (count == 0u) {
    return true;
  }
  if (tail > count) {
    memmove((uint8_t*)data + offset, (uint8_t*)data + offset + count,
            tail - count);
  }
  *len -= count;
  return true;
}

void pcsc_fido_zero_bytes(void* ptr, size_t len) {
  if (ptr == PCSC_FIDO_NULL || len == 0u) {
    return;
  }
  memset(ptr, 0, len);
}

void pcsc_fido_fill_bytes(void* ptr, size_t len, uint8_t value) {
  if (ptr == PCSC_FIDO_NULL || len == 0u) {
    return;
  }
  memset(ptr, (int)value, len);
}
