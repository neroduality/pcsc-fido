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

#include "pcsc_fido/daemon_policy.h"

#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/mem_util.h"

#include <string.h>

// CTAP2 authenticatorGetAssertion request map key for clientDataHash (CTAP 2.1 §6.2).
enum {
  PCSC_FIDO_GET_ASSERTION_KEY_CLIENT_DATA_HASH = 0x02u,
};

// CBOR major types (RFC 8949 §3.1).
enum {
  PCSC_FIDO_CBOR_MAJOR_BYTE_STRING = 2u,
  PCSC_FIDO_CBOR_MAJOR_MAP = 5u,
};

const uint8_t PCSC_FIDO_EMPTY_CLIENT_DATA_HASH[32] = {
  0xE3u, 0xB0u, 0xC4u, 0x42u, 0x98u, 0xFCu, 0x1Cu, 0x14u, 0x9Au, 0xFBu, 0xF4u,
  0xC8u, 0x99u, 0x6Fu, 0xB9u, 0x24u, 0x27u, 0xAEu, 0x41u, 0xE4u, 0x64u, 0x9Bu,
  0x93u, 0x4Cu, 0xA4u, 0x95u, 0x99u, 0x1Bu, 0x78u, 0x52u, 0xB8u, 0x55u};

bool pcsc_fido_daemon_is_get_assertion(uint8_t hid_cmd, const uint8_t *payload,
                                       size_t payload_len) {
  return hid_cmd == PCSC_FIDO_HID_CMD_CBOR && payload != nullptr && payload_len > 0u &&
         payload[0] == 0x02u;
}

bool pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(const uint8_t *payload,
                                                               size_t payload_len) {
  size_t off = 1u;
  size_t pairs = 0u;
  if (payload == nullptr || payload_len == 0u || payload[0] != 0x02u) {
    return false;
  }
  // Structurally decode the getAssertion CBOR map and inspect only the
  // clientDataHash field (key 0x02) rather than scanning the whole payload, so
  // bytes inside a credential ID or other field can never trigger a false match.
  if (!pcsc_fido_cbor_read_type_len(payload, payload_len, &off, PCSC_FIDO_CBOR_MAJOR_MAP, &pairs)) {
    return false;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key = 0u;
    if (!pcsc_fido_cbor_read_uint_value(payload, payload_len, &off, &key)) {
      return false;
    }
    if (key == PCSC_FIDO_GET_ASSERTION_KEY_CLIENT_DATA_HASH) {
      size_t hash_len = 0u;
      if (!pcsc_fido_cbor_read_type_len(payload, payload_len, &off,
                                        PCSC_FIDO_CBOR_MAJOR_BYTE_STRING, &hash_len)) {
        return false;
      }
      return hash_len == sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH) &&
             pcsc_fido_span_ok(off, hash_len, payload_len) &&
             memcmp(payload + off, PCSC_FIDO_EMPTY_CLIENT_DATA_HASH, hash_len) == 0;
    }
    if (!pcsc_fido_cbor_skip_item(payload, payload_len, &off)) {
      return false;
    }
  }
  return false;
}

bool pcsc_fido_daemon_is_terminal_webauthn_request(uint8_t cmd, const uint8_t *payload,
                                                   size_t payload_len) {
  if (cmd != PCSC_FIDO_HID_CMD_CBOR || payload == nullptr || payload_len == 0u) {
    return false;
  }
  if (payload[0] == 0x01u) {
    return true;
  }
  return payload[0] == 0x02u &&
         !pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(payload, payload_len);
}
