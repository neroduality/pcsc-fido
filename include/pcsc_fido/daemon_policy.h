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

#include "pcsc_fido/ctaphid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Spec prefixes for docs/spec-traceability.yaml: CTAP2.3
 * (cite in-file as [CTAP2.3]). */
enum {
  PCSC_FIDO_CLIENT_DATA_HASH_LEN = 32u,                 /* [CTAP2.3] */
  PCSC_FIDO_GET_ASSERTION_KEY_CLIENT_DATA_HASH = 0x02u, /* [CTAP2.3] §6.2 */
};

// SHA-256 of the empty byte string. Browsers send this as the clientDataHash on
// silent capability/allow-list preflight getAssertions, so its presence marks a
// probe rather than a terminal login.
extern const uint8_t
    PCSC_FIDO_EMPTY_CLIENT_DATA_HASH[PCSC_FIDO_CLIENT_DATA_HASH_LEN];

PCSC_FIDO_STATIC_ASSERT(sizeof(PCSC_FIDO_EMPTY_CLIENT_DATA_HASH) ==
                            PCSC_FIDO_CLIENT_DATA_HASH_LEN,
                        "empty clientDataHash marker must be 32 bytes");

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_is_get_assertion(
    uint8_t hid_cmd, const uint8_t* payload, size_t payload_len);

// True only when the request is an authenticatorGetAssertion whose CBOR
// clientDataHash field (map key 0x02) equals SHA-256(""), i.e. a browser
// capability/allow-list probe rather than a terminal login.
PCSC_FIDO_NODISCARD bool
pcsc_fido_daemon_get_assertion_has_empty_client_data_hash(
    const uint8_t* payload, size_t payload_len);

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_is_terminal_webauthn_request(
    uint8_t cmd, const uint8_t* payload, size_t payload_len);
