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

typedef struct pcsc_fido_reader_state pcsc_fido_reader_state_t;

typedef enum {
  PCSC_FIDO_READER_PICK_OK = 0,
  PCSC_FIDO_READER_PICK_NO_MATCH,
  PCSC_FIDO_READER_PICK_AMBIGUOUS,
  PCSC_FIDO_READER_PICK_NAME_TOO_LONG,
} pcsc_fido_reader_pick_result_t;

PCSC_FIDO_NODISCARD bool pcsc_fido_reader_name_contains_ci(const char *reader, const char *needle);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_name_contains_ci_len(const char *reader,
                                                               size_t reader_len,
                                                               const char *needle,
                                                               size_t needle_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_name_is_contactless_slot(const char *reader);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_name_is_contactless_slot_len(const char *reader,
                                                                       size_t reader_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_name_is_sam_slot_len(const char *reader,
                                                               size_t reader_len);
PCSC_FIDO_NODISCARD bool
pcsc_fido_reader_status_has_card(uint32_t event_state) PCSC_FIDO_UNSEQUENCED;

PCSC_FIDO_NODISCARD bool pcsc_fido_reader_state_has_card(const pcsc_fido_reader_state_t *state);

const char *pcsc_fido_reader_env_needle(const char *needle);

typedef enum {
  PCSC_FIDO_READER_LIST_ENTRY_OK = 0,
  PCSC_FIDO_READER_LIST_ENTRY_END,
  PCSC_FIDO_READER_LIST_ENTRY_MALFORMED,
} pcsc_fido_reader_list_entry_result_t;

PCSC_FIDO_NODISCARD pcsc_fido_reader_list_entry_result_t pcsc_fido_reader_list_next(
  const char *readers, size_t readers_len, size_t *offset, const char **entry, size_t *entry_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_reader_list_is_valid(const char *readers, size_t readers_len);

pcsc_fido_reader_pick_result_t
pcsc_fido_pick_reader_from_list(const char *readers, size_t readers_len, const char *needle,
                                bool auto_select_contactless, char *reader, size_t reader_cap,
                                bool *auto_selected_contactless);
