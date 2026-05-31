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

#include "pcsc_fido/reader_select.h"

#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <winscard.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

bool pcsc_fido_reader_status_has_card(uint32_t event_state) {
  return (event_state & (uint32_t)SCARD_STATE_PRESENT) != 0u &&
         (event_state & (uint32_t)SCARD_STATE_MUTE) == 0u &&
         (event_state & (uint32_t)SCARD_STATE_INUSE) == 0u;
}

bool pcsc_fido_reader_state_has_card(const pcsc_fido_reader_state_t *state) {
  const SCARD_READERSTATE *reader_state = (const SCARD_READERSTATE *)state;
  return reader_state != nullptr &&
         pcsc_fido_reader_status_has_card((uint32_t)reader_state->dwEventState);
}

const char *pcsc_fido_reader_env_needle(const char *needle) {
  const char *env;
  if (needle != nullptr && needle[0] != '\0') {
    return needle;
  }
  env = getenv("PCSC_FIDO_READER");
  if (env != nullptr && env[0] != '\0') {
    return env;
  }
  return needle;
}

pcsc_fido_reader_list_entry_result_t pcsc_fido_reader_list_next(const char *readers,
                                                                size_t readers_len, size_t *offset,
                                                                const char **entry,
                                                                size_t *entry_len) {
  size_t name_len;
  if (readers == nullptr || offset == nullptr || entry == nullptr || entry_len == nullptr ||
      readers_len == 0u || *offset >= readers_len) {
    return PCSC_FIDO_READER_LIST_ENTRY_MALFORMED;
  }
  if (readers[*offset] == '\0') {
    return PCSC_FIDO_READER_LIST_ENTRY_END;
  }
  if (!pcsc_fido_bounded_strlen(readers + *offset, readers_len - *offset, &name_len)) {
    return PCSC_FIDO_READER_LIST_ENTRY_MALFORMED;
  }
  *entry = readers + *offset;
  *entry_len = name_len;
  *offset += name_len + 1u;
  return PCSC_FIDO_READER_LIST_ENTRY_OK;
}

bool pcsc_fido_reader_list_is_valid(const char *readers, size_t readers_len) {
  size_t off = 0u;
  if (readers == nullptr || readers_len == 0u) {
    return false;
  }
  while (off < readers_len) {
    pcsc_fido_reader_list_entry_result_t entry_result;
    const char *entry;
    size_t entry_len;
    if (readers[off] == '\0') {
      return true;
    }
    entry_result = pcsc_fido_reader_list_next(readers, readers_len, &off, &entry, &entry_len);
    if (entry_result == PCSC_FIDO_READER_LIST_ENTRY_END) {
      return true;
    }
    if (entry_result != PCSC_FIDO_READER_LIST_ENTRY_OK) {
      return false;
    }
    (void)entry;
    (void)entry_len;
  }
  return false;
}

bool pcsc_fido_reader_name_contains_ci_len(const char *reader, size_t reader_len,
                                           const char *needle, size_t needle_len) {
  if (reader == nullptr || needle == nullptr) {
    return false;
  }
  if (needle_len == 0u) {
    return true;
  }
  if (needle_len > reader_len) {
    return false;
  }
  for (size_t pos = 0u; pos + needle_len <= reader_len; pos++) {
    size_t i = 0u;
    while (i < needle_len &&
           tolower((unsigned char)reader[pos + i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == needle_len) {
      return true;
    }
  }
  return false;
}

bool pcsc_fido_reader_name_contains_ci(const char *reader, const char *needle) {
  size_t reader_len;
  size_t needle_len;
  if (!pcsc_fido_bounded_strlen(reader, PCSC_FIDO_READER_NAME_MAX, &reader_len) ||
      !pcsc_fido_bounded_strlen(needle, PCSC_FIDO_READER_NAME_MAX, &needle_len)) {
    return false;
  }
  return pcsc_fido_reader_name_contains_ci_len(reader, reader_len, needle, needle_len);
}

bool pcsc_fido_reader_name_is_sam_slot_len(const char *reader, size_t reader_len) {
  return pcsc_fido_reader_name_contains_ci_len(reader, reader_len, "sam", 3u);
}

bool pcsc_fido_reader_name_is_contactless_slot_len(const char *reader, size_t reader_len) {
  if (reader == nullptr || pcsc_fido_reader_name_is_sam_slot_len(reader, reader_len)) {
    return false;
  }
  return pcsc_fido_reader_name_contains_ci_len(reader, reader_len, "picc", 4u) ||
         pcsc_fido_reader_name_contains_ci_len(reader, reader_len, "nfc", 3u) ||
         pcsc_fido_reader_name_contains_ci_len(reader, reader_len, "contactless", 11u);
}

bool pcsc_fido_reader_name_is_contactless_slot(const char *reader) {
  size_t reader_len;
  if (!pcsc_fido_bounded_strlen(reader, PCSC_FIDO_READER_NAME_MAX, &reader_len)) {
    return false;
  }
  return pcsc_fido_reader_name_is_contactless_slot_len(reader, reader_len);
}

static bool copy_reader_name(char *dst, size_t dst_cap, const char *src, size_t src_len) {
  if (dst == nullptr || dst_cap == 0u) {
    return false;
  }
  if (src == nullptr) {
    dst[0] = '\0';
    return true;
  }
  return pcsc_fido_copy_cstr_len(dst, dst_cap, src, src_len);
}

pcsc_fido_reader_pick_result_t
pcsc_fido_pick_reader_from_list(const char *readers, size_t readers_len, const char *needle,
                                bool auto_select_contactless, char *reader, size_t reader_cap,
                                bool *auto_selected_contactless) {
  size_t matches = 0u;
  size_t contactless_matches = 0u;
  size_t non_sam_matches = 0u;
  char contactless_reader[PCSC_FIDO_READER_NAME_MAX];
  size_t contactless_reader_len = 0u;
  bool has_needle = needle != nullptr && needle[0] != '\0';
  size_t needle_len = 0u;

  if (auto_selected_contactless != nullptr) {
    *auto_selected_contactless = false;
  }
  if (reader != nullptr && reader_cap > 0u) {
    reader[0] = '\0';
  }
  if (readers == nullptr || readers_len == 0u || readers[0] == '\0') {
    return PCSC_FIDO_READER_PICK_NO_MATCH;
  }
  if (has_needle && !pcsc_fido_bounded_strlen(needle, PCSC_FIDO_READER_NAME_MAX, &needle_len)) {
    return PCSC_FIDO_READER_PICK_NO_MATCH;
  }

  contactless_reader[0] = '\0';
  for (size_t off = 0u;;) {
    const char *p;
    size_t p_len;
    pcsc_fido_reader_list_entry_result_t entry_result =
      pcsc_fido_reader_list_next(readers, readers_len, &off, &p, &p_len);
    if (entry_result == PCSC_FIDO_READER_LIST_ENTRY_END) {
      break;
    }
    if (entry_result == PCSC_FIDO_READER_LIST_ENTRY_MALFORMED) {
      return PCSC_FIDO_READER_PICK_NO_MATCH;
    }
    if (has_needle && !pcsc_fido_reader_name_contains_ci_len(p, p_len, needle, needle_len)) {
      continue;
    }
    if (matches == 0u) {
      if (!copy_reader_name(reader, reader_cap, p, p_len)) {
        return PCSC_FIDO_READER_PICK_NAME_TOO_LONG;
      }
    }
    matches++;
    if (!has_needle && !pcsc_fido_reader_name_is_sam_slot_len(p, p_len)) {
      non_sam_matches++;
    }
    if (!has_needle && auto_select_contactless &&
        pcsc_fido_reader_name_is_contactless_slot_len(p, p_len)) {
      if (contactless_matches == 0u) {
        if (!copy_reader_name(contactless_reader, sizeof(contactless_reader), p, p_len)) {
          return PCSC_FIDO_READER_PICK_NAME_TOO_LONG;
        }
        contactless_reader_len = p_len;
      }
      contactless_matches++;
    }
  }

  if (matches == 1u) {
    return PCSC_FIDO_READER_PICK_OK;
  }
  if (!has_needle && auto_select_contactless && contactless_matches == 1u &&
      non_sam_matches == 1u) {
    if (!copy_reader_name(reader, reader_cap, contactless_reader, contactless_reader_len)) {
      return PCSC_FIDO_READER_PICK_NAME_TOO_LONG;
    }
    if (auto_selected_contactless != nullptr) {
      *auto_selected_contactless = true;
    }
    return PCSC_FIDO_READER_PICK_OK;
  }
  return matches == 0u ? PCSC_FIDO_READER_PICK_NO_MATCH : PCSC_FIDO_READER_PICK_AMBIGUOUS;
}
