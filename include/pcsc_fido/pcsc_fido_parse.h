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
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
  PCSC_FIDO_PARSE_TEXT_MAX = PCSC_FIDO_ERR_MSG_MAX,
};

PCSC_FIDO_NODISCARD static inline bool pcsc_fido_parse_u32(const char* text,
                                                           uint32_t* out) {
  uint32_t value = 0u;
  size_t i = 0u;
  size_t len = 0u;
  if (out == PCSC_FIDO_NULL) {
    return false;
  }
  *out = 0u;
  if (text == PCSC_FIDO_NULL ||
      !pcsc_fido_bounded_strlen(text, PCSC_FIDO_PARSE_TEXT_MAX, &len) ||
      len == 0u) {
    return false;
  }
  for (i = 0u; i < len; i++) {
    uint8_t c = (uint8_t)text[i];
    uint32_t digit = 0u;
    if (c < (uint8_t)'0' || c > (uint8_t)'9') {
      return false;
    }
    digit = (uint32_t)(c - (uint8_t)'0');
    if (value > (UINT32_MAX - digit) / (uint32_t)PCSC_FIDO_DECIMAL_BASE) {
      return false;
    }
    value = (value * (uint32_t)PCSC_FIDO_DECIMAL_BASE) + digit;
  }
  *out = value;
  return true;
}
