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

/* Spec prefixes for docs/spec-traceability.yaml: IMPL-POLICY RFC8949
 * (cite in-file as [IMPL-POLICY], [RFC8949]). */
enum {
  PCSC_FIDO_CBOR_AI_MASK = 0x1Fu,
  PCSC_FIDO_CBOR_MAJOR_TYPE_SHIFT = 5u,
  PCSC_FIDO_CBOR_AI_UINT8 = 24u,  /* [RFC8949] */
  PCSC_FIDO_CBOR_AI_UINT16 = 25u, /* [RFC8949] */
  PCSC_FIDO_CBOR_AI_UINT32 = 26u, /* [RFC8949] */
  PCSC_FIDO_CBOR_AI_UINT64 = 27u, /* [RFC8949] */
  PCSC_FIDO_CBOR_AI_UINT8_LEN = 1u,
  PCSC_FIDO_CBOR_AI_UINT16_LEN = 2u,
  PCSC_FIDO_CBOR_AI_UINT32_LEN = 4u,
  PCSC_FIDO_CBOR_AI_UINT64_LEN = 8u,
  PCSC_FIDO_CBOR_MAJOR_UINT = 0u,   /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_NINT = 1u,   /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_BYTES = 2u,  /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_TEXT = 3u,   /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_ARRAY = 4u,  /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_MAP = 5u,    /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_TAG = 6u,    /* [RFC8949] */
  PCSC_FIDO_CBOR_MAJOR_SIMPLE = 7u, /* [RFC8949] */
  PCSC_FIDO_CBOR_FALSE = 0xF4u,     /* [RFC8949] */
  PCSC_FIDO_CBOR_TRUE = 0xF5u,      /* [RFC8949] */
  PCSC_FIDO_CBOR_MAX_NESTING = 32u, /* [IMPL-POLICY] */
  PCSC_FIDO_CBOR_MAP_ITEMS_PER_ENTRY = 2u,
};

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_len(uint8_t additional,
                                                 const uint8_t* data,
                                                 size_t len, size_t* off,
                                                 size_t* value);

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_type_len(const uint8_t* data,
                                                      size_t len, size_t* off,
                                                      uint8_t major,
                                                      size_t* value);

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_uint_value(const uint8_t* data,
                                                        size_t len, size_t* off,
                                                        size_t* value);

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_skip_item(const uint8_t* data,
                                                  size_t len, size_t* off);

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_bool_value(const uint8_t* data,
                                                        size_t len, size_t* off,
                                                        bool* value);

PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_text_key_matches(
    const uint8_t* data, size_t len, size_t* off, const char* key,
    bool* matches);
PCSC_FIDO_NODISCARD bool pcsc_fido_cbor_read_text_key_matches_len(
    const uint8_t* data, size_t len, size_t* off, const char* key,
    size_t expected_len, bool* matches);
