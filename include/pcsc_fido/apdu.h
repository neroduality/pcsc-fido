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

enum {
  PCSC_FIDO_SW_OK_HI = 0x90u,
  PCSC_FIDO_SW_OK_LO = 0x00u,
  PCSC_FIDO_SW_WRONG_LENGTH_HI = 0x67u,
  PCSC_FIDO_SW_INS_NOT_SUPPORTED_HI = 0x6Du,
  PCSC_FIDO_SW_WRONG_PARAMS_HI = 0x6Au,
  PCSC_FIDO_SW_WRONG_PARAMS_LO = 0x86u,
  PCSC_FIDO_SW_FILE_NOT_FOUND_LO = 0x82u,
  PCSC_FIDO_CTAPHID_MSG = 0x03u,
  PCSC_FIDO_CTAPHID_CBOR = 0x10u,
  PCSC_FIDO_CTAP2_OK = 0x00u,
  PCSC_FIDO_SHORT_APDU_PAYLOAD_MAX = 255u,
  PCSC_FIDO_AID_LEN = 8u,
  PCSC_FIDO_SELECT_APDU_MAX = 5u + PCSC_FIDO_AID_LEN + 1u,
};

typedef enum {
  PCSC_FIDO_APDU_UNSUPPORTED = 0,
  PCSC_FIDO_APDU_SELECT,
  PCSC_FIDO_APDU_CTAP,
} pcsc_fido_apdu_kind_t;

typedef struct {
  pcsc_fido_apdu_kind_t kind;
  uint8_t hid_cmd;
  const uint8_t *payload PCSC_FIDO_COUNTED_BY(payload_len);
  size_t payload_len;
  uint8_t sw1;
  uint8_t sw2;
} pcsc_fido_apdu_t;

extern const uint8_t PCSC_FIDO_AID[PCSC_FIDO_AID_LEN];

PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_AID_LEN == 8u, "FIDO AID must be 8 bytes");

pcsc_fido_apdu_t pcsc_fido_parse_apdu(const uint8_t *apdu, size_t apdu_len) PCSC_FIDO_REPRODUCIBLE;
PCSC_FIDO_NODISCARD bool pcsc_fido_pack_select_fido_apdu(uint8_t *apdu, size_t apdu_cap,
                                                         size_t *apdu_len, bool add_le);
PCSC_FIDO_NODISCARD bool pcsc_fido_pack_ctap2_cbor_apdu(const uint8_t *payload, size_t payload_len,
                                                        uint8_t *apdu, size_t apdu_cap,
                                                        size_t *apdu_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_append_status(uint8_t *out, size_t out_cap, size_t body_len,
                                                 uint8_t sw1, uint8_t sw2, size_t *out_len);
