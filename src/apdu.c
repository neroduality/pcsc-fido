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

#include "pcsc_fido/apdu.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include "pcsc_fido/mem_util.h"

#include <string.h>

const uint8_t PCSC_FIDO_AID[PCSC_FIDO_AID_LEN] = {0xA0u, 0x00u, 0x00u, 0x06u,
                                                  0x47u, 0x2Fu, 0x00u, 0x01u};

static pcsc_fido_apdu_t unsupported(uint8_t sw1, uint8_t sw2) {
  pcsc_fido_apdu_t parsed;
  pcsc_fido_zero_bytes(&parsed, sizeof(parsed));
  parsed.kind = PCSC_FIDO_APDU_UNSUPPORTED;
  parsed.sw1 = sw1;
  parsed.sw2 = sw2;
  return parsed;
}

static bool is_select_fido(const uint8_t* apdu, size_t apdu_len) {
  if (apdu == PCSC_FIDO_NULL) {
    return false;
  }
  if (apdu_len != PCSC_FIDO_SELECT_APDU_LEN &&
      apdu_len != PCSC_FIDO_SELECT_APDU_LEN_WITH_LE) {
    return false;
  }
  return apdu[PCSC_FIDO_APDU_OFF_CLA] == PCSC_FIDO_APDU_CLA_ISO &&
         apdu[PCSC_FIDO_APDU_OFF_INS] == PCSC_FIDO_APDU_INS_SELECT &&
         apdu[PCSC_FIDO_APDU_OFF_P1] == PCSC_FIDO_APDU_P1_SELECT_BY_DF &&
         apdu[PCSC_FIDO_APDU_OFF_P2] == PCSC_FIDO_APDU_P2_DEFAULT &&
         apdu[PCSC_FIDO_APDU_OFF_LC] == sizeof(PCSC_FIDO_AID) &&
         memcmp(apdu + PCSC_FIDO_APDU_OFF_SHORT_DATA, PCSC_FIDO_AID,
                sizeof(PCSC_FIDO_AID)) == 0;
}

static bool parse_short_ctap(const uint8_t* apdu, size_t apdu_len,
                             pcsc_fido_apdu_t* parsed) {
  size_t lc = 0u;
  if (apdu == PCSC_FIDO_NULL || parsed == PCSC_FIDO_NULL ||
      apdu_len < PCSC_FIDO_APDU_SHORT_PREFIX_LEN) {
    return false;
  }
  lc = apdu[PCSC_FIDO_APDU_OFF_LC];
  if (lc == 0u || apdu_len != PCSC_FIDO_APDU_SHORT_PREFIX_LEN + lc + 1u) {
    return false;
  }
  parsed->kind = PCSC_FIDO_APDU_CTAP;
  parsed->hid_cmd = PCSC_FIDO_CTAPHID_CBOR;
  parsed->payload = apdu + PCSC_FIDO_APDU_OFF_SHORT_DATA;
  parsed->payload_len = lc;
  parsed->sw1 = PCSC_FIDO_SW_OK_HI;
  parsed->sw2 = PCSC_FIDO_SW_OK_LO;
  return true;
}

static bool parse_extended_ctap(const uint8_t* apdu, size_t apdu_len,
                                pcsc_fido_apdu_t* parsed) {
  size_t lc = 0u;
  if (apdu == PCSC_FIDO_NULL || parsed == PCSC_FIDO_NULL) {
    return false;
  }
  if (apdu_len < PCSC_FIDO_APDU_EXT_OVERHEAD ||
      apdu[PCSC_FIDO_APDU_OFF_EXT_LC0] != PCSC_FIDO_SW_OK_LO) {
    return false;
  }
  lc = ((size_t)apdu[PCSC_FIDO_APDU_OFF_EXT_LC1]
        << PCSC_FIDO_U16_HIGH_BYTE_SHIFT) |
       apdu[PCSC_FIDO_APDU_OFF_EXT_LC2];
  if (lc == 0u || apdu_len != PCSC_FIDO_APDU_EXT_PREFIX_LEN + lc +
                                  PCSC_FIDO_APDU_EXT_LE_LEN) {
    return false;
  }
  parsed->kind = PCSC_FIDO_APDU_CTAP;
  parsed->hid_cmd = PCSC_FIDO_CTAPHID_CBOR;
  parsed->payload = apdu + PCSC_FIDO_APDU_OFF_EXT_DATA;
  parsed->payload_len = lc;
  parsed->sw1 = PCSC_FIDO_SW_OK_HI;
  parsed->sw2 = PCSC_FIDO_SW_OK_LO;
  return true;
}

pcsc_fido_apdu_t pcsc_fido_parse_apdu(const uint8_t* apdu,
                                      size_t apdu_len) PCSC_FIDO_REPRODUCIBLE {
  pcsc_fido_apdu_t parsed;
  if (apdu == PCSC_FIDO_NULL || apdu_len < PCSC_FIDO_APDU_HEADER_LEN) {
    return unsupported(PCSC_FIDO_SW_WRONG_LENGTH_HI, PCSC_FIDO_SW_OK_LO);
  }
  if (is_select_fido(apdu, apdu_len)) {
    pcsc_fido_zero_bytes(&parsed, sizeof(parsed));
    parsed.kind = PCSC_FIDO_APDU_SELECT;
    parsed.sw1 = PCSC_FIDO_SW_OK_HI;
    parsed.sw2 = PCSC_FIDO_SW_OK_LO;
    return parsed;
  }
  if (apdu[PCSC_FIDO_APDU_OFF_CLA] == PCSC_FIDO_APDU_CLA_PROPRIETARY &&
      apdu[PCSC_FIDO_APDU_OFF_INS] == PCSC_FIDO_APDU_INS_CTAP &&
      apdu[PCSC_FIDO_APDU_OFF_P1] == PCSC_FIDO_APDU_P2_DEFAULT &&
      apdu[PCSC_FIDO_APDU_OFF_P2] == PCSC_FIDO_APDU_P2_DEFAULT) {
    pcsc_fido_zero_bytes(&parsed, sizeof(parsed));
    if (apdu_len >= PCSC_FIDO_APDU_SHORT_PREFIX_LEN &&
        parse_short_ctap(apdu, apdu_len, &parsed)) {
      return parsed;
    }
    if (apdu_len >= PCSC_FIDO_APDU_EXT_PREFIX_LEN &&
        parse_extended_ctap(apdu, apdu_len, &parsed)) {
      return parsed;
    }
    return unsupported(PCSC_FIDO_SW_WRONG_LENGTH_HI, PCSC_FIDO_SW_OK_LO);
  }
  return unsupported(PCSC_FIDO_SW_INS_NOT_SUPPORTED_HI, PCSC_FIDO_SW_OK_LO);
}

bool pcsc_fido_pack_select_fido_apdu(uint8_t* apdu, size_t apdu_cap,
                                     size_t* apdu_len, bool add_le) {
  size_t total_len = 0u;
  if (apdu == PCSC_FIDO_NULL || apdu_len == PCSC_FIDO_NULL ||
      !pcsc_fido_try_add_size(PCSC_FIDO_APDU_SHORT_PREFIX_LEN,
                              PCSC_FIDO_AID_LEN, &total_len) ||
      (add_le && !pcsc_fido_try_add_size(total_len, 1u, &total_len)) ||
      apdu_cap < total_len) {
    return false;
  }
  apdu[PCSC_FIDO_APDU_OFF_CLA] = PCSC_FIDO_APDU_CLA_ISO;
  apdu[PCSC_FIDO_APDU_OFF_INS] = PCSC_FIDO_APDU_INS_SELECT;
  apdu[PCSC_FIDO_APDU_OFF_P1] = PCSC_FIDO_APDU_P1_SELECT_BY_DF;
  apdu[PCSC_FIDO_APDU_OFF_P2] = PCSC_FIDO_APDU_P2_DEFAULT;
  apdu[PCSC_FIDO_APDU_OFF_LC] = (uint8_t)PCSC_FIDO_AID_LEN;
  if (!pcsc_fido_copy_bytes(apdu, apdu_cap, PCSC_FIDO_APDU_OFF_SHORT_DATA,
                            PCSC_FIDO_AID, PCSC_FIDO_AID_LEN)) {
    return false;
  }
  *apdu_len = PCSC_FIDO_APDU_SHORT_PREFIX_LEN + PCSC_FIDO_AID_LEN;
  if (add_le) {
    apdu[*apdu_len] = PCSC_FIDO_SW_OK_LO;
    (*apdu_len)++;
  }
  return true;
}

bool pcsc_fido_pack_ctap2_cbor_apdu(const uint8_t* payload, size_t payload_len,
                                    uint8_t* apdu, size_t apdu_cap,
                                    size_t* apdu_len) {
  size_t total_len;
  if (payload == PCSC_FIDO_NULL || apdu == PCSC_FIDO_NULL ||
      apdu_len == PCSC_FIDO_NULL) {
    return false;
  }
  if (payload_len <= PCSC_FIDO_SHORT_APDU_PAYLOAD_MAX) {
    if (!pcsc_fido_try_add_size(payload_len, PCSC_FIDO_APDU_SHORT_OVERHEAD,
                                &total_len) ||
        apdu_cap < total_len) {
      return false;
    }
    apdu[PCSC_FIDO_APDU_OFF_CLA] = PCSC_FIDO_APDU_CLA_PROPRIETARY;
    apdu[PCSC_FIDO_APDU_OFF_INS] = PCSC_FIDO_APDU_INS_CTAP;
    apdu[PCSC_FIDO_APDU_OFF_P1] = PCSC_FIDO_APDU_P2_DEFAULT;
    apdu[PCSC_FIDO_APDU_OFF_P2] = PCSC_FIDO_APDU_P2_DEFAULT;
    apdu[PCSC_FIDO_APDU_OFF_LC] = (uint8_t)payload_len;
    if (!pcsc_fido_copy_bytes(apdu, apdu_cap, PCSC_FIDO_APDU_OFF_SHORT_DATA,
                              payload, payload_len)) {
      return false;
    }
    apdu[PCSC_FIDO_APDU_OFF_SHORT_DATA + payload_len] = PCSC_FIDO_SW_OK_LO;
    *apdu_len = total_len;
    return true;
  }
  if (payload_len > PCSC_FIDO_CTAPHID_MAX_PAYLOAD ||
      !pcsc_fido_try_add_size(payload_len, PCSC_FIDO_APDU_EXT_OVERHEAD,
                              &total_len) ||
      apdu_cap < total_len) {
    return false;
  }
  apdu[PCSC_FIDO_APDU_OFF_CLA] = PCSC_FIDO_APDU_CLA_PROPRIETARY;
  apdu[PCSC_FIDO_APDU_OFF_INS] = PCSC_FIDO_APDU_INS_CTAP;
  apdu[PCSC_FIDO_APDU_OFF_P1] = PCSC_FIDO_APDU_P2_DEFAULT;
  apdu[PCSC_FIDO_APDU_OFF_P2] = PCSC_FIDO_APDU_P2_DEFAULT;
  apdu[PCSC_FIDO_APDU_OFF_EXT_LC0] = PCSC_FIDO_SW_OK_LO;
  apdu[PCSC_FIDO_APDU_OFF_EXT_LC1] =
      (uint8_t)((payload_len >> PCSC_FIDO_U16_HIGH_BYTE_SHIFT) &
                PCSC_FIDO_BYTE_MASK);
  apdu[PCSC_FIDO_APDU_OFF_EXT_LC2] =
      (uint8_t)(payload_len & PCSC_FIDO_BYTE_MASK);
  if (!pcsc_fido_copy_bytes(apdu, apdu_cap, PCSC_FIDO_APDU_OFF_EXT_DATA,
                            payload, payload_len)) {
    return false;
  }
  apdu[PCSC_FIDO_APDU_OFF_EXT_DATA + payload_len] = PCSC_FIDO_SW_OK_LO;
  apdu[PCSC_FIDO_APDU_OFF_EXT_DATA + payload_len + 1u] = PCSC_FIDO_SW_OK_LO;
  *apdu_len = total_len;
  return true;
}

bool pcsc_fido_append_status(uint8_t* out, size_t out_cap, size_t body_len,
                             uint8_t sw1, uint8_t sw2, size_t* out_len) {
  if (out == PCSC_FIDO_NULL || out_len == PCSC_FIDO_NULL ||
      !pcsc_fido_span_ok(body_len, PCSC_FIDO_SW_LEN, out_cap)) {
    return false;
  }
  out[body_len] = sw1;
  out[body_len + 1u] = sw2;
  *out_len = body_len + PCSC_FIDO_SW_LEN;
  return true;
}
