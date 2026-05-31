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
#include <stdio.h>
#include <winscard.h>

typedef enum {
  PCSC_FIDO_READER_CTX_USER = 0,
  PCSC_FIDO_READER_CTX_DAEMON,
} pcsc_fido_reader_ctx_scope_t;

PCSC_FIDO_NODISCARD bool pcsc_fido_reader_establish_context(SCARDCONTEXT *ctx,
                                                            pcsc_fido_reader_ctx_scope_t scope,
                                                            char *err, size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_list(SCARDCONTEXT ctx, char *buf, DWORD *buf_len,
                                               char *err, size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_list_snapshot(SCARDCONTEXT ctx, char *buf, DWORD *buf_len,
                                                        char *err, size_t err_cap);
PCSC_FIDO_NODISCARD size_t pcsc_fido_reader_fill_status_states(const char *readers,
                                                               size_t readers_len,
                                                               SCARD_READERSTATE *states,
                                                               size_t states_cap);
PCSC_FIDO_NODISCARD const SCARD_IO_REQUEST *
pcsc_fido_reader_pci_for_protocol(DWORD active_protocol);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_confirm_card_present(SCARDCONTEXT ctx, const char *reader,
                                                               char *err, size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_probe_fido_card(SCARDCONTEXT ctx, const char *reader);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_select_and_wait(SCARDCONTEXT ctx,
                                                          const char *reader_needle, char *reader,
                                                          size_t reader_cap, char *err,
                                                          size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_print_list(FILE *out, char *err, size_t err_cap);
