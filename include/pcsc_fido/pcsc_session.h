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
#include <winscard.h>

// Single-daemon PC/SC session state (one context, one card, one mutex).
// Internal to the bridge stack; not a general-purpose PC/SC client API.

typedef struct {
  SCARDHANDLE card;
  const SCARD_IO_REQUEST *send_pci;
  uint64_t generation;
} pcsc_fido_session_tx_t;

PCSC_FIDO_NODISCARD bool pcsc_fido_session_is_ready(void);
PCSC_FIDO_NODISCARD bool pcsc_fido_session_verify_ready(char *err, size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_session_snapshot_tx(pcsc_fido_session_tx_t *tx, char *err,
                                                       size_t err_cap);
PCSC_FIDO_NODISCARD bool
pcsc_fido_session_tx_is_current(const pcsc_fido_session_tx_t *tx) PCSC_FIDO_UNSEQUENCED;
PCSC_FIDO_NODISCARD SCARDCONTEXT pcsc_fido_session_snapshot_context(void);

void pcsc_fido_session_reset(void);
void pcsc_fido_session_cancel(void);
PCSC_FIDO_NODISCARD bool pcsc_fido_session_cancel_requested(void);
void pcsc_fido_session_clear_cancel(void);

PCSC_FIDO_NODISCARD bool pcsc_fido_session_ensure(const char *reader_needle, char *err,
                                                  size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_session_transmit_chained(const pcsc_fido_session_tx_t *tx,
                                                            const uint8_t *capdu, size_t capdu_len,
                                                            uint8_t *rapdu, size_t rapdu_cap,
                                                            size_t *rapdu_len, char *err,
                                                            size_t err_cap);
