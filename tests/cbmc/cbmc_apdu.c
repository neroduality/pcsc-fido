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

#include "cbmc_cprover.h"
#include "pcsc_fido/apdu.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <stddef.h>
#include <stdint.h>

/* Memory safety and the length checks for every APDU that fits in the
 * bridge buffer, SELECT packing, status-word append at every body length,
 * and CBOR packing for every payload length up to
 * PCSC_FIDO_CBMC_APDU_PAYLOAD_MAX (both the short and the extended Lc
 * encodings) plus the rejection of every claimed length above the CTAPHID
 * cap. The packer's memcpy of a nondeterministic length is what bounds the
 * payload cap: 8192 symbolic bytes do not finish. */
#ifndef PCSC_FIDO_CBMC_APDU_PAYLOAD_MAX
#define PCSC_FIDO_CBMC_APDU_PAYLOAD_MAX 300u
#endif

int main(void) {
  uint8_t apdu[PCSC_FIDO_BRIDGE_MAX_APDU] PCSC_FIDO_CBMC_NONDET;
  const size_t apdu_len = PCSC_FIDO_CBMC_NONDET_SIZE();
  PCSC_FIDO_CBMC_ASSUME(apdu_len <= sizeof(apdu));

  const pcsc_fido_apdu_t parsed = pcsc_fido_parse_apdu(apdu, apdu_len);
  if (parsed.kind == PCSC_FIDO_APDU_CTAP && parsed.payload != PCSC_FIDO_NULL) {
    PCSC_FIDO_CBMC_ASSERT(PCSC_FIDO_CBMC_SAME_OBJECT(parsed.payload, apdu),
                          "CTAP payload aliases the input APDU");
    PCSC_FIDO_CBMC_ASSERT(parsed.payload_len <= apdu_len,
                          "CTAP payload length stays inside the input");
  }

  uint8_t select_out[PCSC_FIDO_SELECT_APDU_MAX];
  size_t select_len = 0u;
  const bool add_le = (apdu[0] & 1u) != 0u;
  const bool select_ok = pcsc_fido_pack_select_fido_apdu(
      select_out, sizeof(select_out), &select_len, add_le);
  PCSC_FIDO_CBMC_ASSERT(select_ok, "SELECT fits in the SELECT buffer");
  PCSC_FIDO_CBMC_ASSERT(select_len <= sizeof(select_out), "SELECT length");
  PCSC_FIDO_CBMC_ASSERT(
      select_len == (add_le ? PCSC_FIDO_SELECT_APDU_LEN_WITH_LE
                            : PCSC_FIDO_SELECT_APDU_LEN),
      "SELECT length matches the AID encoding");

  uint8_t payload[PCSC_FIDO_CBMC_APDU_PAYLOAD_MAX] PCSC_FIDO_CBMC_NONDET;
  const size_t payload_len = PCSC_FIDO_CBMC_NONDET_SIZE();
  PCSC_FIDO_CBMC_ASSUME(payload_len <= sizeof(payload));
  /* Sized to the proof cap, not PCSC_FIDO_BRIDGE_MAX_APDU: a symbolic-length
   * memmove into an 8 KiB destination is what makes the formula intractable,
   * and the packer's cap arithmetic is checked against sizeof(packed). */
  uint8_t packed[PCSC_FIDO_CBMC_APDU_PAYLOAD_MAX + PCSC_FIDO_APDU_EXT_OVERHEAD];
  size_t packed_len = 0u;
  const bool pack_ok = pcsc_fido_pack_ctap2_cbor_apdu(
      payload, payload_len, packed, sizeof(packed), &packed_len);
  PCSC_FIDO_CBMC_ASSERT(pack_ok,
                        "CTAPHID-capped payload fits in the bridge APDU");
  PCSC_FIDO_CBMC_ASSERT(packed_len <= sizeof(packed), "packed APDU length");
  {
    const size_t overhead = payload_len <= PCSC_FIDO_SHORT_APDU_PAYLOAD_MAX
                                ? PCSC_FIDO_APDU_SHORT_OVERHEAD
                                : PCSC_FIDO_APDU_EXT_OVERHEAD;
    PCSC_FIDO_CBMC_ASSERT(packed_len == payload_len + overhead,
                          "packed length is payload plus APDU overhead");
  }

  /* apdu_cap deliberately overstates sizeof(packed) by enough to hold one byte
   * past the CTAPHID cap, so only the cap check can reject; without it the
   * packer writes past packed and the bounds check fails. A real buffer that
   * size makes the formula intractable, as above. */
  const size_t wide_cap =
      PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 1u + PCSC_FIDO_APDU_EXT_OVERHEAD;
  const size_t claimed = PCSC_FIDO_CBMC_NONDET_SIZE();
  PCSC_FIDO_CBMC_ASSUME(claimed > PCSC_FIDO_CTAPHID_MAX_PAYLOAD);
  PCSC_FIDO_CBMC_ASSUME(claimed <= wide_cap - PCSC_FIDO_APDU_EXT_OVERHEAD);
  const bool rejected = pcsc_fido_pack_ctap2_cbor_apdu(payload, claimed, packed,
                                                       wide_cap, &packed_len);
  PCSC_FIDO_CBMC_ASSERT(!rejected, "payload above the CTAPHID cap is rejected");

  uint8_t response[PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE] PCSC_FIDO_CBMC_NONDET;
  const size_t body_len = PCSC_FIDO_CBMC_NONDET_SIZE();
  PCSC_FIDO_CBMC_ASSUME(body_len <= sizeof(response));
  size_t response_len = 0u;
  const bool status_ok = pcsc_fido_append_status(
      response, sizeof(response), body_len, PCSC_FIDO_SW_OK_HI,
      PCSC_FIDO_SW_OK_LO, &response_len);
  if (body_len <= sizeof(response) - PCSC_FIDO_SW_LEN) {
    PCSC_FIDO_CBMC_ASSERT(status_ok, "status word fits in the chain cap");
    PCSC_FIDO_CBMC_ASSERT(response_len == body_len + PCSC_FIDO_SW_LEN,
                          "status word appends two bytes");
  } else {
    PCSC_FIDO_CBMC_ASSERT(
        !status_ok, "status word that would pass the chain cap is rejected");
  }
  return 0;
}
