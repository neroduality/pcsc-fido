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

#include <stddef.h>
#include <stdint.h>

static const char k_cbor_keys[][11] = {"up", "uv", "rk", "clientPin"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t off = 0u;
  size_t value = 0u;
  bool flag = false;
  bool matches = false;

  if (data == nullptr) {
    return 0;
  }

  off = 0u;
  (void)pcsc_fido_cbor_skip_item(data, size, &off);

  off = 0u;
  (void)pcsc_fido_cbor_read_uint_value(data, size, &off, &value);

  off = 0u;
  (void)pcsc_fido_cbor_read_bool_value(data, size, &off, &flag);

  for (size_t i = 0u; i < sizeof(k_cbor_keys) / sizeof(k_cbor_keys[0]); i++) {
    off = 0u;
    (void)pcsc_fido_cbor_read_text_key_matches(data, size, &off, k_cbor_keys[i], &matches);
  }

  if (size > 0u) {
    const uint8_t additional = (uint8_t)(data[0] & 0x1Fu);
    off = size > 1u ? 1u : 0u;
    (void)pcsc_fido_cbor_read_len(additional, data, size, &off, &value);
  }

  return 0;
}
