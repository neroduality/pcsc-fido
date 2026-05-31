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

enum {
  PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE = PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 6u,
};

PCSC_FIDO_STATIC_ASSERT((unsigned)PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE >
                          (unsigned)PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
                        "chained APDU response cap must exceed CTAPHID payload cap");

typedef bool (*pcsc_fido_apdu_transmit_fn)(void *ctx, const uint8_t *capdu, size_t capdu_len,
                                           uint8_t *rapdu, size_t rapdu_cap, size_t *rapdu_len,
                                           char *err, size_t err_cap);
typedef bool (*pcsc_fido_apdu_cancel_fn)(void *ctx);

unsigned pcsc_fido_apdu_status_word(const uint8_t *rapdu, size_t rapdu_len) PCSC_FIDO_REPRODUCIBLE;

PCSC_FIDO_NODISCARD bool pcsc_fido_apdu_append_response_body(uint8_t *out, size_t out_cap,
                                                             size_t *out_len, const uint8_t *chunk,
                                                             size_t chunk_len, char *err,
                                                             size_t err_cap);

PCSC_FIDO_NODISCARD bool
pcsc_fido_apdu_transmit_chained(void *ctx, pcsc_fido_apdu_transmit_fn transmit,
                                const uint8_t *capdu, size_t capdu_len, uint8_t *rapdu,
                                size_t rapdu_cap, size_t *rapdu_len, char *err, size_t err_cap);

PCSC_FIDO_NODISCARD bool pcsc_fido_apdu_transmit_chained_cancel(
  void *ctx, pcsc_fido_apdu_transmit_fn transmit, pcsc_fido_apdu_cancel_fn should_cancel,
  void *cancel_ctx, const uint8_t *capdu, size_t capdu_len, uint8_t *rapdu, size_t rapdu_cap,
  size_t *rapdu_len, char *err, size_t err_cap);
