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

#include "pcsc_fido/apdu_chain.h"

#include "pcsc_fido/apdu.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"

#include <string.h>

unsigned pcsc_fido_apdu_status_word(const uint8_t* rapdu,
                                    size_t rapdu_len) PCSC_FIDO_REPRODUCIBLE {
  if (rapdu == PCSC_FIDO_NULL || rapdu_len < PCSC_FIDO_SW_LEN) {
    return 0u;
  }
  return ((unsigned)rapdu[rapdu_len - PCSC_FIDO_SW_LEN]
          << PCSC_FIDO_U16_HIGH_BYTE_SHIFT) |
         rapdu[rapdu_len - 1u];
}

bool pcsc_fido_apdu_append_response_body(uint8_t* out, size_t out_cap,
                                         size_t* out_len, const uint8_t* chunk,
                                         size_t chunk_len, char* err,
                                         size_t err_cap) {
  size_t body_len;
  if (out == PCSC_FIDO_NULL || out_len == PCSC_FIDO_NULL ||
      chunk == PCSC_FIDO_NULL || chunk_len < PCSC_FIDO_SW_LEN) {
    pcsc_fido_set_err(err, err_cap, "APDU response missing status word");
    return false;
  }
  body_len = chunk_len - PCSC_FIDO_SW_LEN;
  if (!pcsc_fido_span_ok(*out_len, body_len, out_cap)) {
    pcsc_fido_set_err(err, err_cap, "APDU chained response too large");
    return false;
  }
  if (!pcsc_fido_copy_bytes(out, out_cap, *out_len, chunk, body_len)) {
    pcsc_fido_set_err(err, err_cap, "APDU chained response too large");
    return false;
  }
  *out_len += body_len;
  return true;
}

static bool apdu_chain_cancelled(pcsc_fido_apdu_cancel_fn_t should_cancel,
                                 void* cancel_ctx) {
  return should_cancel != PCSC_FIDO_NULL && should_cancel(cancel_ctx);
}

bool pcsc_fido_apdu_transmit_chained_cancel(
    void* ctx, pcsc_fido_apdu_transmit_fn_t transmit,
    pcsc_fido_apdu_cancel_fn_t should_cancel, void* cancel_ctx,
    const uint8_t* capdu, size_t capdu_len, uint8_t* rapdu, size_t rapdu_cap,
    size_t* rapdu_len, char* err, size_t err_cap) {
  uint8_t chunk[PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE];
  size_t chunk_len = 0u;
  size_t out_len = 0u;
  uint8_t get_response[PCSC_FIDO_APDU_GET_RESPONSE_LEN] = {
      PCSC_FIDO_APDU_CLA_ISO, PCSC_FIDO_APDU_INS_GET_RESPONSE,
      PCSC_FIDO_APDU_P2_DEFAULT, PCSC_FIDO_APDU_P2_DEFAULT, PCSC_FIDO_SW_OK_LO};
  unsigned guard = 0u;
  unsigned max_get_response_chunks =
      (unsigned)(rapdu_cap / PCSC_FIDO_SHORT_APDU_PAYLOAD_MAX) +
      PCSC_FIDO_APDU_GET_RESPONSE_CHUNK_SLACK;
  bool ok = false;

  if (transmit == PCSC_FIDO_NULL || capdu == PCSC_FIDO_NULL ||
      rapdu == PCSC_FIDO_NULL || rapdu_len == PCSC_FIDO_NULL) {
    pcsc_fido_set_err(err, err_cap, "invalid chained APDU transmit arguments");
    goto done;
  }
  *rapdu_len = 0u;
  if (!transmit(ctx, capdu, capdu_len, chunk, sizeof(chunk), &chunk_len, err,
                err_cap)) {
    goto done;
  }

  while ((pcsc_fido_apdu_status_word(chunk, chunk_len) &
          PCSC_FIDO_APDU_SW_BYTES_AVAILABLE_MASK) ==
         PCSC_FIDO_APDU_SW_BYTES_AVAILABLE) {
    unsigned sw = pcsc_fido_apdu_status_word(chunk, chunk_len);
    if (apdu_chain_cancelled(should_cancel, cancel_ctx)) {
      pcsc_fido_set_err(err, err_cap, "PC/SC bridge cancelled");
      goto done;
    }
    if (!pcsc_fido_apdu_append_response_body(rapdu, rapdu_cap, &out_len, chunk,
                                             chunk_len, err, err_cap)) {
      goto done;
    }
    if (++guard > max_get_response_chunks) {
      pcsc_fido_set_err(err, err_cap, "too many APDU GET RESPONSE chunks");
      goto done;
    }
    get_response[PCSC_FIDO_APDU_GET_RESPONSE_LEN - 1u] =
        (uint8_t)(sw & PCSC_FIDO_APDU_SW_LE_MASK);
    if (!transmit(ctx, get_response, sizeof(get_response), chunk, sizeof(chunk),
                  &chunk_len, err, err_cap)) {
      goto done;
    }
    if (apdu_chain_cancelled(should_cancel, cancel_ctx)) {
      pcsc_fido_set_err(err, err_cap, "PC/SC bridge cancelled");
      goto done;
    }
  }

  if (chunk_len < PCSC_FIDO_SW_LEN) {
    pcsc_fido_set_err(err, err_cap, "APDU response missing status word");
    goto done;
  }
  if (!pcsc_fido_copy_bytes(rapdu, rapdu_cap, out_len, chunk, chunk_len)) {
    pcsc_fido_set_err(err, err_cap, "APDU chained response too large");
    goto done;
  }
  out_len += chunk_len;
  *rapdu_len = out_len;
  ok = true;

done:
  /* chunk accumulates raw card responses -- for CBOR exchanges the full CTAP2
   * response plaintext, including authenticatorClientPIN token / keyAgreement
   * material. Scrub it on every exit so it does not linger on the worker-thread
   * stack, matching the secure_clear invariant applied to capdu/rapdu/job. */
  pcsc_fido_secure_clear(chunk, sizeof(chunk));
  return ok;
}

bool pcsc_fido_apdu_transmit_chained(void* ctx,
                                     pcsc_fido_apdu_transmit_fn_t transmit,
                                     const uint8_t* capdu, size_t capdu_len,
                                     uint8_t* rapdu, size_t rapdu_cap,
                                     size_t* rapdu_len, char* err,
                                     size_t err_cap) {
  return pcsc_fido_apdu_transmit_chained_cancel(
      ctx, transmit, PCSC_FIDO_NULL, PCSC_FIDO_NULL, capdu, capdu_len, rapdu,
      rapdu_cap, rapdu_len, err, err_cap);
}
