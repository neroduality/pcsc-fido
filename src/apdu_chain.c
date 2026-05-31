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

#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_err.h"

#include <string.h>

unsigned pcsc_fido_apdu_status_word(const uint8_t *rapdu, size_t rapdu_len) PCSC_FIDO_REPRODUCIBLE {
  if (rapdu == nullptr || rapdu_len < 2u) {
    return 0u;
  }
  return ((unsigned)rapdu[rapdu_len - 2u] << 8u) | rapdu[rapdu_len - 1u];
}

bool pcsc_fido_apdu_append_response_body(uint8_t *out, size_t out_cap, size_t *out_len,
                                         const uint8_t *chunk, size_t chunk_len, char *err,
                                         size_t err_cap) {
  size_t body_len;
  if (out == nullptr || out_len == nullptr || chunk == nullptr || chunk_len < 2u) {
    pcsc_fido_set_err(err, err_cap, "APDU response missing status word");
    return false;
  }
  body_len = chunk_len - 2u;
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

static bool apdu_chain_cancelled(pcsc_fido_apdu_cancel_fn should_cancel, void *cancel_ctx) {
  return should_cancel != nullptr && should_cancel(cancel_ctx);
}

bool pcsc_fido_apdu_transmit_chained_cancel(void *ctx, pcsc_fido_apdu_transmit_fn transmit,
                                            pcsc_fido_apdu_cancel_fn should_cancel,
                                            void *cancel_ctx, const uint8_t *capdu,
                                            size_t capdu_len, uint8_t *rapdu, size_t rapdu_cap,
                                            size_t *rapdu_len, char *err, size_t err_cap) {
  uint8_t chunk[PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE];
  size_t chunk_len = 0u;
  size_t out_len = 0u;
  uint8_t get_response[5] = {0x00u, 0xC0u, 0x00u, 0x00u, 0x00u};
  unsigned guard = 0u;
  unsigned max_get_response_chunks = (unsigned)(rapdu_cap / 255u) + 2u;

  if (transmit == nullptr || capdu == nullptr || rapdu == nullptr || rapdu_len == nullptr) {
    pcsc_fido_set_err(err, err_cap, "invalid chained APDU transmit arguments");
    return false;
  }
  *rapdu_len = 0u;
  if (!transmit(ctx, capdu, capdu_len, chunk, sizeof(chunk), &chunk_len, err, err_cap)) {
    return false;
  }

  while ((pcsc_fido_apdu_status_word(chunk, chunk_len) & 0xFF00u) == 0x6100u) {
    unsigned sw = pcsc_fido_apdu_status_word(chunk, chunk_len);
    if (apdu_chain_cancelled(should_cancel, cancel_ctx)) {
      pcsc_fido_set_err(err, err_cap, "PC/SC bridge cancelled");
      return false;
    }
    if (!pcsc_fido_apdu_append_response_body(rapdu, rapdu_cap, &out_len, chunk, chunk_len, err,
                                             err_cap)) {
      return false;
    }
    if (++guard > max_get_response_chunks) {
      pcsc_fido_set_err(err, err_cap, "too many APDU GET RESPONSE chunks");
      return false;
    }
    get_response[4] = (uint8_t)(sw & 0x00FFu);
    if (!transmit(ctx, get_response, sizeof(get_response), chunk, sizeof(chunk), &chunk_len, err,
                  err_cap)) {
      return false;
    }
    if (apdu_chain_cancelled(should_cancel, cancel_ctx)) {
      pcsc_fido_set_err(err, err_cap, "PC/SC bridge cancelled");
      return false;
    }
  }

  if (chunk_len < 2u) {
    pcsc_fido_set_err(err, err_cap, "APDU response missing status word");
    return false;
  }
  if (!pcsc_fido_copy_bytes(rapdu, rapdu_cap, out_len, chunk, chunk_len)) {
    pcsc_fido_set_err(err, err_cap, "APDU chained response too large");
    return false;
  }
  out_len += chunk_len;
  *rapdu_len = out_len;
  return true;
}

bool pcsc_fido_apdu_transmit_chained(void *ctx, pcsc_fido_apdu_transmit_fn transmit,
                                     const uint8_t *capdu, size_t capdu_len, uint8_t *rapdu,
                                     size_t rapdu_cap, size_t *rapdu_len, char *err,
                                     size_t err_cap) {
  return pcsc_fido_apdu_transmit_chained_cancel(ctx, transmit, nullptr, nullptr, capdu, capdu_len,
                                                rapdu, rapdu_cap, rapdu_len, err, err_cap);
}
