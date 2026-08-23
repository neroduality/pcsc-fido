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

#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/mem_util.h"

#include <stdint.h>
#include <string.h>

static bool cbor_advance_off(size_t* off, size_t delta, size_t len) {
  size_t next;
  if (off == PCSC_FIDO_NULL || !pcsc_fido_try_add_size(*off, delta, &next) ||
      next > len) {
    return false;
  }
  *off = next;
  return true;
}

bool pcsc_fido_cbor_read_len(uint8_t additional, const uint8_t* data,
                             size_t len, size_t* off, size_t* value) {
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL ||
      value == PCSC_FIDO_NULL) {
    return false;
  }
  if (additional < PCSC_FIDO_CBOR_AI_UINT8) {
    *value = additional;
    return true;
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT8) {
    if (*off >= len) {
      return false;
    }
    *value = data[*off];
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT8_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT16) {
    if (!pcsc_fido_span_ok(*off, PCSC_FIDO_CBOR_AI_UINT16_LEN, len)) {
      return false;
    }
    *value =
        ((size_t)data[*off] << PCSC_FIDO_U16_HIGH_BYTE_SHIFT) | data[*off + 1u];
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT16_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT32) {
    if (!pcsc_fido_span_ok(*off, PCSC_FIDO_CBOR_AI_UINT32_LEN, len)) {
      return false;
    }
    *value = ((size_t)data[*off] << PCSC_FIDO_U64_SHIFT_BYTE3) |
             ((size_t)data[*off + 1u] << PCSC_FIDO_U32_SHIFT_BYTE2) |
             ((size_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_2]
              << PCSC_FIDO_U32_SHIFT_BYTE1) |
             data[*off + PCSC_FIDO_BE_BYTE_INDEX_3];
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT32_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT64) {
    uint64_t wide;
    if (!pcsc_fido_span_ok(*off, PCSC_FIDO_CBOR_AI_UINT64_LEN, len)) {
      return false;
    }
    wide = ((uint64_t)data[*off] << PCSC_FIDO_U64_SHIFT_BYTE7) |
           ((uint64_t)data[*off + 1u] << PCSC_FIDO_U64_SHIFT_BYTE6) |
           ((uint64_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_2]
            << PCSC_FIDO_U64_SHIFT_BYTE5) |
           ((uint64_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_3]
            << PCSC_FIDO_U64_SHIFT_BYTE4) |
           ((uint64_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_4]
            << PCSC_FIDO_U64_SHIFT_BYTE3) |
           ((uint64_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_5]
            << PCSC_FIDO_U32_SHIFT_BYTE2) |
           ((uint64_t)data[*off + PCSC_FIDO_BE_BYTE_INDEX_6]
            << PCSC_FIDO_U32_SHIFT_BYTE1) |
           data[*off + PCSC_FIDO_BE_BYTE_INDEX_7];
    if (wide > (uint64_t)SIZE_MAX) {
      return false;
    }
    *value = (size_t)wide;
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT64_LEN, len);
  }
  return false;
}

bool pcsc_fido_cbor_read_type_len(const uint8_t* data, size_t len, size_t* off,
                                  uint8_t major, size_t* value) {
  uint8_t hdr;
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL ||
      value == PCSC_FIDO_NULL) {
    return false;
  }
  if (*off >= len) {
    return false;
  }
  hdr = data[*off];
  (*off)++;
  if ((uint8_t)(hdr >> PCSC_FIDO_CBOR_MAJOR_TYPE_SHIFT) != major) {
    return false;
  }
  return pcsc_fido_cbor_read_len((uint8_t)(hdr & PCSC_FIDO_CBOR_AI_MASK), data,
                                 len, off, value);
}

bool pcsc_fido_cbor_read_uint_value(const uint8_t* data, size_t len,
                                    size_t* off, size_t* value) {
  return pcsc_fido_cbor_read_type_len(data, len, off, PCSC_FIDO_CBOR_MAJOR_UINT,
                                      value);
}

static bool cbor_skip_simple_major7(uint8_t additional, size_t len,
                                    size_t* off) {
  if (additional < PCSC_FIDO_CBOR_AI_UINT8) {
    return true;
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT8) {
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT8_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT16) {
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT16_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT32) {
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT32_LEN, len);
  }
  if (additional == PCSC_FIDO_CBOR_AI_UINT64) {
    return cbor_advance_off(off, PCSC_FIDO_CBOR_AI_UINT64_LEN, len);
  }
  return false;
}

static bool cbor_skip_item_depth(const uint8_t* data, size_t len, size_t* off,
                                 unsigned depth) {
  /* PCSC_FIDO_BOUNDED_RECURSION max depth: PCSC_FIDO_CBOR_MAX_NESTING */
  uint8_t hdr;
  uint8_t major;
  uint8_t additional;
  size_t value = 0u;
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL) {
    return false;
  }
  if (depth >= PCSC_FIDO_CBOR_MAX_NESTING) {
    return false;
  }
  if (*off >= len) {
    return false;
  }
  hdr = data[*off];
  (*off)++;
  major = (uint8_t)(hdr >> PCSC_FIDO_CBOR_MAJOR_TYPE_SHIFT);
  additional = (uint8_t)(hdr & PCSC_FIDO_CBOR_AI_MASK);
  switch (major) {
    case PCSC_FIDO_CBOR_MAJOR_UINT:
    case PCSC_FIDO_CBOR_MAJOR_NINT:
      return pcsc_fido_cbor_read_len(additional, data, len, off, &value);
    case PCSC_FIDO_CBOR_MAJOR_BYTES:
    case PCSC_FIDO_CBOR_MAJOR_TEXT:
      if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value) ||
          !pcsc_fido_span_ok(*off, value, len)) {
        return false;
      }
      return cbor_advance_off(off, value, len);
    case PCSC_FIDO_CBOR_MAJOR_ARRAY:
      if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value)) {
        return false;
      }
      for (size_t i = 0u; i < value; i++) {
        if (!cbor_skip_item_depth(data, len, off, depth + 1u)) {
          return false;
        }
      }
      return true;
    case PCSC_FIDO_CBOR_MAJOR_MAP:
      if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value)) {
        return false;
      }
      for (size_t i = 0u; i < value; i++) {
        /* One map entry: skip the key item, then the value item. */
        for (size_t kv = 0u; kv < PCSC_FIDO_CBOR_MAP_ITEMS_PER_ENTRY; kv++) {
          if (!cbor_skip_item_depth(data, len, off, depth + 1u)) {
            return false;
          }
        }
      }
      return true;
    case PCSC_FIDO_CBOR_MAJOR_TAG:
      return pcsc_fido_cbor_read_len(additional, data, len, off, &value) &&
             cbor_skip_item_depth(data, len, off, depth + 1u);
    case PCSC_FIDO_CBOR_MAJOR_SIMPLE:
      return cbor_skip_simple_major7(additional, len, off);
    default:
      PCSC_FIDO_UNREACHABLE();
  }
}

bool pcsc_fido_cbor_skip_item(const uint8_t* data, size_t len, size_t* off) {
  return cbor_skip_item_depth(data, len, off, 0u);
}

bool pcsc_fido_cbor_read_bool_value(const uint8_t* data, size_t len,
                                    size_t* off, bool* value) {
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL ||
      value == PCSC_FIDO_NULL || *off >= len) {
    return false;
  }
  if (data[*off] == PCSC_FIDO_CBOR_FALSE || data[*off] == PCSC_FIDO_CBOR_TRUE) {
    *value = data[*off] == PCSC_FIDO_CBOR_TRUE;
    (*off)++;
    return true;
  }
  return false;
}

bool pcsc_fido_cbor_read_text_key_matches(const uint8_t* data, size_t len,
                                          size_t* off, const char* key,
                                          bool* matches) {
  size_t key_len;
  if (key == PCSC_FIDO_NULL || !pcsc_fido_bounded_strlen(key, len, &key_len)) {
    return false;
  }
  return pcsc_fido_cbor_read_text_key_matches_len(data, len, off, key, key_len,
                                                  matches);
}

bool pcsc_fido_cbor_read_text_key_matches_len(const uint8_t* data, size_t len,
                                              size_t* off, const char* key,
                                              size_t expected_len,
                                              bool* matches) {
  size_t key_len = 0u;
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL ||
      key == PCSC_FIDO_NULL || matches == PCSC_FIDO_NULL ||
      !pcsc_fido_cbor_read_type_len(data, len, off, PCSC_FIDO_CBOR_MAJOR_TEXT,
                                    &key_len) ||
      !pcsc_fido_span_ok(*off, key_len, len)) {
    return false;
  }
  *matches =
      key_len == expected_len && memcmp(data + *off, key, expected_len) == 0;
  return cbor_advance_off(off, key_len, len);
}
