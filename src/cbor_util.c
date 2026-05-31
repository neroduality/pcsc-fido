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

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/mem_util.h"

#include <stdint.h>
#include <string.h>

enum {
  PCSC_FIDO_CBOR_MAX_NESTING = 32u,
};

static bool cbor_advance_off(size_t *off, size_t delta, size_t len) {
  size_t next;
  if (off == nullptr || !pcsc_fido_try_add_size(*off, delta, &next) || next > len) {
    return false;
  }
  *off = next;
  return true;
}

bool pcsc_fido_cbor_read_len(uint8_t additional, const uint8_t *data, size_t len, size_t *off,
                             size_t *value) {
  if (data == nullptr || off == nullptr || value == nullptr) {
    return false;
  }
  if (additional < 24u) {
    *value = additional;
    return true;
  }
  if (additional == 24u) {
    if (*off >= len) {
      return false;
    }
    *value = data[*off];
    return cbor_advance_off(off, 1u, len);
  }
  if (additional == 25u) {
    if (!pcsc_fido_span_ok(*off, 2u, len)) {
      return false;
    }
    *value = ((size_t)data[*off] << 8u) | data[*off + 1u];
    return cbor_advance_off(off, 2u, len);
  }
  if (additional == 26u) {
    if (!pcsc_fido_span_ok(*off, 4u, len)) {
      return false;
    }
    *value = ((size_t)data[*off] << 24u) | ((size_t)data[*off + 1u] << 16u) |
             ((size_t)data[*off + 2u] << 8u) | data[*off + 3u];
    return cbor_advance_off(off, 4u, len);
  }
  if (additional == 27u) {
    uint64_t wide;
    if (!pcsc_fido_span_ok(*off, 8u, len)) {
      return false;
    }
    wide = ((uint64_t)data[*off] << 56u) | ((uint64_t)data[*off + 1u] << 48u) |
           ((uint64_t)data[*off + 2u] << 40u) | ((uint64_t)data[*off + 3u] << 32u) |
           ((uint64_t)data[*off + 4u] << 24u) | ((uint64_t)data[*off + 5u] << 16u) |
           ((uint64_t)data[*off + 6u] << 8u) | data[*off + 7u];
    if (wide > (uint64_t)SIZE_MAX) {
      return false;
    }
    *value = (size_t)wide;
    return cbor_advance_off(off, 8u, len);
  }
  return false;
}

bool pcsc_fido_cbor_read_type_len(const uint8_t *data, size_t len, size_t *off, uint8_t major,
                                  size_t *value) {
  uint8_t hdr;
  if (data == nullptr || off == nullptr || value == nullptr) {
    return false;
  }
  if (*off >= len) {
    return false;
  }
  hdr = data[*off];
  (*off)++;
  if ((uint8_t)(hdr >> 5u) != major) {
    return false;
  }
  return pcsc_fido_cbor_read_len((uint8_t)(hdr & 0x1Fu), data, len, off, value);
}

bool pcsc_fido_cbor_read_uint_value(const uint8_t *data, size_t len, size_t *off, size_t *value) {
  return pcsc_fido_cbor_read_type_len(data, len, off, 0u, value);
}

static bool cbor_skip_simple_major7(uint8_t additional, size_t len, size_t *off) {
  if (additional < 24u) {
    return true;
  }
  if (additional == 24u) {
    return cbor_advance_off(off, 1u, len);
  }
  if (additional == 25u) {
    return cbor_advance_off(off, 2u, len);
  }
  if (additional == 26u) {
    return cbor_advance_off(off, 4u, len);
  }
  if (additional == 27u) {
    return cbor_advance_off(off, 8u, len);
  }
  return false;
}

static bool cbor_skip_item_depth(const uint8_t *data, size_t len, size_t *off, unsigned depth) {
  uint8_t hdr;
  uint8_t major;
  uint8_t additional;
  size_t value = 0u;
  if (data == nullptr || off == nullptr) {
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
  major = (uint8_t)(hdr >> 5u);
  additional = (uint8_t)(hdr & 0x1Fu);
  switch (major) {
  case 0u:
  case 1u:
    return pcsc_fido_cbor_read_len(additional, data, len, off, &value);
  case 2u:
  case 3u:
    if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value) ||
        !pcsc_fido_span_ok(*off, value, len)) {
      return false;
    }
    return cbor_advance_off(off, value, len);
  case 4u:
    if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value)) {
      return false;
    }
    for (size_t i = 0u; i < value; i++) {
      if (!cbor_skip_item_depth(data, len, off, depth + 1u)) {
        return false;
      }
    }
    return true;
  case 5u:
    if (!pcsc_fido_cbor_read_len(additional, data, len, off, &value)) {
      return false;
    }
    for (size_t i = 0u; i < value; i++) {
      if (!cbor_skip_item_depth(data, len, off, depth + 1u) ||
          !cbor_skip_item_depth(data, len, off, depth + 1u)) {
        return false;
      }
    }
    return true;
  case 6u:
    return pcsc_fido_cbor_read_len(additional, data, len, off, &value) &&
           cbor_skip_item_depth(data, len, off, depth + 1u);
  case 7u:
    return cbor_skip_simple_major7(additional, len, off);
  default:
    PCSC_FIDO_UNREACHABLE();
  }
}

bool pcsc_fido_cbor_skip_item(const uint8_t *data, size_t len, size_t *off) {
  return cbor_skip_item_depth(data, len, off, 0u);
}

bool pcsc_fido_cbor_read_bool_value(const uint8_t *data, size_t len, size_t *off, bool *value) {
  if (data == nullptr || off == nullptr || value == nullptr || *off >= len) {
    return false;
  }
  if (data[*off] == 0xF4u || data[*off] == 0xF5u) {
    *value = data[*off] == 0xF5u;
    (*off)++;
    return true;
  }
  return false;
}

bool pcsc_fido_cbor_read_text_key_matches(const uint8_t *data, size_t len, size_t *off,
                                          const char *key, bool *matches) {
  size_t key_len;
  if (key == nullptr || !pcsc_fido_bounded_strlen(key, len, &key_len)) {
    return false;
  }
  return pcsc_fido_cbor_read_text_key_matches_len(data, len, off, key, key_len, matches);
}

bool pcsc_fido_cbor_read_text_key_matches_len(const uint8_t *data, size_t len, size_t *off,
                                              const char *key, size_t expected_len, bool *matches) {
  size_t key_len = 0u;
  if (data == nullptr || off == nullptr || key == nullptr || matches == nullptr ||
      !pcsc_fido_cbor_read_type_len(data, len, off, 3u, &key_len) ||
      !pcsc_fido_span_ok(*off, key_len, len)) {
    return false;
  }
  *matches = key_len == expected_len && memcmp(data + *off, key, expected_len) == 0;
  return cbor_advance_off(off, key_len, len);
}
