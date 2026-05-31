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

#include "pcsc_fido/mem_util.h"

#include <string.h>

const uint8_t PCSC_FIDO_AID[PCSC_FIDO_AID_LEN] = {0xA0u, 0x00u, 0x00u, 0x06u,
                                                  0x47u, 0x2Fu, 0x00u, 0x01u};

static pcsc_fido_apdu_t unsupported(uint8_t sw1, uint8_t sw2) {
  pcsc_fido_apdu_t parsed;
  memset(&parsed, 0, sizeof(parsed));
  parsed.kind = PCSC_FIDO_APDU_UNSUPPORTED;
  parsed.sw1 = sw1;
  parsed.sw2 = sw2;
  return parsed;
}

static bool is_select_fido(const uint8_t *apdu, size_t apdu_len) {
  if (apdu == nullptr) {
    return false;
  }
  if (apdu_len != 13u && apdu_len != 14u) {
    return false;
  }
  return apdu[0] == 0x00u && apdu[1] == 0xA4u && apdu[2] == 0x04u && apdu[3] == 0x00u &&
         apdu[4] == sizeof(PCSC_FIDO_AID) &&
         memcmp(apdu + 5u, PCSC_FIDO_AID, sizeof(PCSC_FIDO_AID)) == 0;
}

static bool parse_short_ctap(const uint8_t *apdu, size_t apdu_len, pcsc_fido_apdu_t *parsed) {
  size_t lc = 0u;
  if (apdu == nullptr || parsed == nullptr || apdu_len < 5u) {
    return false;
  }
  lc = apdu[4];
  if (lc == 0u || apdu_len != 5u + lc + 1u) {
    return false;
  }
  parsed->kind = PCSC_FIDO_APDU_CTAP;
  parsed->hid_cmd = PCSC_FIDO_CTAPHID_CBOR;
  parsed->payload = apdu + 5u;
  parsed->payload_len = lc;
  parsed->sw1 = PCSC_FIDO_SW_OK_HI;
  parsed->sw2 = PCSC_FIDO_SW_OK_LO;
  return true;
}

static bool parse_extended_ctap(const uint8_t *apdu, size_t apdu_len, pcsc_fido_apdu_t *parsed) {
  size_t lc = 0u;
  if (apdu == nullptr || parsed == nullptr) {
    return false;
  }
  if (apdu_len < 9u || apdu[4] != 0x00u) {
    return false;
  }
  lc = ((size_t)apdu[5] << 8u) | apdu[6];
  if (lc == 0u || apdu_len != 7u + lc + 2u) {
    return false;
  }
  parsed->kind = PCSC_FIDO_APDU_CTAP;
  parsed->hid_cmd = PCSC_FIDO_CTAPHID_CBOR;
  parsed->payload = apdu + 7u;
  parsed->payload_len = lc;
  parsed->sw1 = PCSC_FIDO_SW_OK_HI;
  parsed->sw2 = PCSC_FIDO_SW_OK_LO;
  return true;
}

pcsc_fido_apdu_t pcsc_fido_parse_apdu(const uint8_t *apdu, size_t apdu_len) PCSC_FIDO_REPRODUCIBLE {
  pcsc_fido_apdu_t parsed;
  if (apdu == nullptr || apdu_len < 4u) {
    return unsupported(PCSC_FIDO_SW_WRONG_LENGTH_HI, 0x00u);
  }
  if (is_select_fido(apdu, apdu_len)) {
    memset(&parsed, 0, sizeof(parsed));
    parsed.kind = PCSC_FIDO_APDU_SELECT;
    parsed.sw1 = PCSC_FIDO_SW_OK_HI;
    parsed.sw2 = PCSC_FIDO_SW_OK_LO;
    return parsed;
  }
  if (apdu[0] == 0x80u && apdu[1] == 0x10u && apdu[2] == 0x00u && apdu[3] == 0x00u) {
    memset(&parsed, 0, sizeof(parsed));
    if (apdu_len >= 5u && parse_short_ctap(apdu, apdu_len, &parsed)) {
      return parsed;
    }
    if (apdu_len >= 7u && parse_extended_ctap(apdu, apdu_len, &parsed)) {
      return parsed;
    }
    return unsupported(PCSC_FIDO_SW_WRONG_LENGTH_HI, 0x00u);
  }
  return unsupported(PCSC_FIDO_SW_INS_NOT_SUPPORTED_HI, 0x00u);
}

bool pcsc_fido_pack_select_fido_apdu(uint8_t *apdu, size_t apdu_cap, size_t *apdu_len,
                                     bool add_le) {
  size_t total_len = 0u;
  if (apdu == nullptr || apdu_len == nullptr ||
      !pcsc_fido_try_add_size(5u, PCSC_FIDO_AID_LEN, &total_len) ||
      (add_le && !pcsc_fido_try_add_size(total_len, 1u, &total_len)) || apdu_cap < total_len) {
    return false;
  }
  apdu[0] = 0x00u;
  apdu[1] = 0xA4u;
  apdu[2] = 0x04u;
  apdu[3] = 0x00u;
  apdu[4] = (uint8_t)PCSC_FIDO_AID_LEN;
  if (!pcsc_fido_copy_bytes(apdu, apdu_cap, 5u, PCSC_FIDO_AID, PCSC_FIDO_AID_LEN)) {
    return false;
  }
  *apdu_len = 5u + PCSC_FIDO_AID_LEN;
  if (add_le) {
    apdu[*apdu_len] = 0x00u;
    (*apdu_len)++;
  }
  return true;
}

bool pcsc_fido_pack_ctap2_cbor_apdu(const uint8_t *payload, size_t payload_len, uint8_t *apdu,
                                    size_t apdu_cap, size_t *apdu_len) {
  size_t total_len;
  if (payload == nullptr || apdu == nullptr || apdu_len == nullptr) {
    return false;
  }
  if (payload_len <= PCSC_FIDO_SHORT_APDU_PAYLOAD_MAX) {
    if (!pcsc_fido_try_add_size(payload_len, 6u, &total_len) || apdu_cap < total_len) {
      return false;
    }
    apdu[0] = 0x80u;
    apdu[1] = 0x10u;
    apdu[2] = 0x00u;
    apdu[3] = 0x00u;
    apdu[4] = (uint8_t)payload_len;
    if (!pcsc_fido_copy_bytes(apdu, apdu_cap, 5u, payload, payload_len)) {
      return false;
    }
    apdu[5u + payload_len] = 0x00u;
    *apdu_len = total_len;
    return true;
  }
  if (payload_len > PCSC_FIDO_CTAPHID_MAX_PAYLOAD ||
      !pcsc_fido_try_add_size(payload_len, 9u, &total_len) || apdu_cap < total_len) {
    return false;
  }
  apdu[0] = 0x80u;
  apdu[1] = 0x10u;
  apdu[2] = 0x00u;
  apdu[3] = 0x00u;
  apdu[4] = 0x00u;
  apdu[5] = (uint8_t)((payload_len >> 8u) & 0xFFu);
  apdu[6] = (uint8_t)(payload_len & 0xFFu);
  if (!pcsc_fido_copy_bytes(apdu, apdu_cap, 7u, payload, payload_len)) {
    return false;
  }
  apdu[7u + payload_len] = 0x00u;
  apdu[8u + payload_len] = 0x00u;
  *apdu_len = total_len;
  return true;
}

bool pcsc_fido_append_status(uint8_t *out, size_t out_cap, size_t body_len, uint8_t sw1,
                             uint8_t sw2, size_t *out_len) {
  if (out == nullptr || out_len == nullptr || !pcsc_fido_span_ok(body_len, 2u, out_cap)) {
    return false;
  }
  out[body_len] = sw1;
  out[body_len + 1u] = sw2;
  *out_len = body_len + 2u;
  return true;
}
