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
#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_debug.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_fido_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  PCSC_FIDO_DEBUG_HEX_DUMP_MAX = 220u,
  PCSC_FIDO_DEBUG_CTAP_STATUS_OK_LEN = 4u,
  PCSC_FIDO_DEBUG_CTAP_STATUS_AND_SW_LEN = 3u,
  PCSC_FIDO_DEBUG_AUTHDATA_RP_ID_HASH_LEN = 32u,
  PCSC_FIDO_DEBUG_AUTHDATA_FLAGS_OFF = PCSC_FIDO_DEBUG_AUTHDATA_RP_ID_HASH_LEN,
  PCSC_FIDO_DEBUG_AUTHDATA_SIGN_COUNT_OFF =
      PCSC_FIDO_DEBUG_AUTHDATA_FLAGS_OFF + 1u,
  PCSC_FIDO_DEBUG_AUTHDATA_SIGN_COUNT_LEN = 4u,
  PCSC_FIDO_DEBUG_AUTHDATA_MIN_LEN = PCSC_FIDO_DEBUG_AUTHDATA_SIGN_COUNT_OFF +
                                     PCSC_FIDO_DEBUG_AUTHDATA_SIGN_COUNT_LEN,
  PCSC_FIDO_DEBUG_AUTHDATA_SCAN_SLACK = 2u,
  PCSC_FIDO_DEBUG_CBOR_MAJOR_MASK = 0xE0u,
  PCSC_FIDO_DEBUG_CBOR_BYTES_SHORT = 0x40u,
  PCSC_FIDO_DEBUG_CBOR_BYTES_UINT8 = 0x58u,
  PCSC_FIDO_DEBUG_CBOR_BYTES_UINT16 = 0x59u,
  PCSC_FIDO_DEBUG_GET_ASSERTION_AUTH_DATA_KEY = 0x02u,
  PCSC_FIDO_DEBUG_MAKE_CRED_ATTESTATION_KEY = 2u,
  PCSC_FIDO_DEBUG_AUTHDATA_KEY_LEN = 8u,
  PCSC_FIDO_DEBUG_OPTIONS_KEY_LEN = 2u,
  PCSC_FIDO_DEBUG_MAKE_CRED_OPTIONS_KEY = 7u,
  PCSC_FIDO_DEBUG_MAKE_CRED_PIN_UV_KEY = 8u,
  PCSC_FIDO_DEBUG_GET_ASSERT_OPTIONS_KEY = 5u,
  PCSC_FIDO_DEBUG_GET_ASSERT_PIN_UV_KEY = 6u,
  PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UP = 0x01u,
  PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UV = 0x04u,
  PCSC_FIDO_DEBUG_AUTHDATA_FLAG_AT = 0x40u,
  PCSC_FIDO_DEBUG_SIGN_COUNT_B0 = 0u,
  PCSC_FIDO_DEBUG_SIGN_COUNT_B1 = 1u,
  PCSC_FIDO_DEBUG_SIGN_COUNT_B2 = 2u,
  PCSC_FIDO_DEBUG_SIGN_COUNT_B3 = 3u,
  PCSC_FIDO_DEBUG_CBOR_HDR_TYPE_LEN = 2u,
  PCSC_FIDO_DEBUG_CBOR_HDR_UINT8_LEN = 3u,
  PCSC_FIDO_DEBUG_CBOR_HDR_UINT16_LEN = 4u,
  PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT8 = 2u,
  PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT16_HI = 2u,
  PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT16_LO = 3u,
};

bool pcsc_fido_bridge_debug_enabled(void) {
#if defined(NDEBUG)
  return false;
#else
  const char* v = getenv("PCSC_FIDO_DEBUG");
  if (v == PCSC_FIDO_NULL || v[0] == '\0') {
    return false;
  }
  return strcmp(v, "0") != 0;
#endif
}

void pcsc_fido_bridge_log_apdu_response_hex(const char* label,
                                            const uint8_t* rapdu,
                                            size_t rapdu_len) {
  bool truncated = rapdu_len > PCSC_FIDO_DEBUG_HEX_DUMP_MAX;
  size_t n = truncated ? PCSC_FIDO_DEBUG_HEX_DUMP_MAX : rapdu_len;
  if (!pcsc_fido_bridge_debug_enabled() || label == PCSC_FIDO_NULL) {
    return;
  }
  pcsc_fido_io_printf(stderr, "pcsc-fido: %s hex=", label);
  for (size_t i = 0u; i < n; i++) {
    pcsc_fido_io_printf(stderr, "%02X", rapdu[i]);
  }
  if (truncated) {
    pcsc_fido_io_printf(stderr, "...");
  }
  pcsc_fido_io_printf(stderr, "\n");
}

void pcsc_fido_bridge_log_get_assertion_summary(const uint8_t* rapdu,
                                                size_t rapdu_len) {
  const uint8_t* cbor;
  size_t cbor_len;
  if (!pcsc_fido_bridge_debug_enabled() || rapdu == PCSC_FIDO_NULL ||
      !pcsc_fido_span_ok(0u, PCSC_FIDO_DEBUG_CTAP_STATUS_OK_LEN, rapdu_len) ||
      !pcsc_fido_span_ok(1u, PCSC_FIDO_DEBUG_CTAP_STATUS_AND_SW_LEN,
                         rapdu_len) ||
      rapdu[0] != PCSC_FIDO_CTAP2_OK) {
    return;
  }
  cbor = rapdu + 1u;
  cbor_len = rapdu_len - PCSC_FIDO_DEBUG_CTAP_STATUS_AND_SW_LEN;
  for (size_t i = 0u; i + PCSC_FIDO_DEBUG_AUTHDATA_FLAGS_OFF +
                          PCSC_FIDO_DEBUG_AUTHDATA_SCAN_SLACK <
                      cbor_len;
       i++) {
    size_t auth_off = 0u;
    size_t auth_len = 0u;
    if (cbor[i] != PCSC_FIDO_DEBUG_GET_ASSERTION_AUTH_DATA_KEY) {
      continue;
    }
    if ((cbor[i + 1u] & PCSC_FIDO_DEBUG_CBOR_MAJOR_MASK) ==
        PCSC_FIDO_DEBUG_CBOR_BYTES_SHORT) {
      auth_len = cbor[i + 1u] & PCSC_FIDO_CBOR_AI_MASK;
      auth_off = i + PCSC_FIDO_DEBUG_CBOR_HDR_TYPE_LEN;
    } else if (cbor[i + 1u] == PCSC_FIDO_DEBUG_CBOR_BYTES_UINT8 &&
               i + PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT8 < cbor_len) {
      auth_len = cbor[i + PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT8];
      auth_off = i + PCSC_FIDO_DEBUG_CBOR_HDR_UINT8_LEN;
    } else if (cbor[i + 1u] == PCSC_FIDO_DEBUG_CBOR_BYTES_UINT16 &&
               i + PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT16_LO < cbor_len) {
      auth_len = ((size_t)cbor[i + PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT16_HI]
                  << PCSC_FIDO_U16_HIGH_BYTE_SHIFT) |
                 cbor[i + PCSC_FIDO_DEBUG_CBOR_LEN_OFF_UINT16_LO];
      auth_off = i + PCSC_FIDO_DEBUG_CBOR_HDR_UINT16_LEN;
    }
    if (auth_len >= PCSC_FIDO_DEBUG_AUTHDATA_MIN_LEN &&
        auth_off + auth_len <= cbor_len) {
      uint8_t flags = cbor[auth_off + PCSC_FIDO_DEBUG_AUTHDATA_FLAGS_OFF];
      pcsc_fido_io_printf(
          stderr, "pcsc-fido: getAssertion authData flags=0x%02X up=%u uv=%u\n",
          flags, (unsigned)((flags & PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UP) != 0u),
          (unsigned)((flags & PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UV) != 0u));
      return;
    }
  }
}

static bool read_ctap_options_summary(const uint8_t* data, size_t len,
                                      size_t* off, bool* has_up, bool* up,
                                      bool* has_uv, bool* uv) {
  size_t pairs = 0u;
  if (data == PCSC_FIDO_NULL || off == PCSC_FIDO_NULL ||
      has_up == PCSC_FIDO_NULL || up == PCSC_FIDO_NULL ||
      has_uv == PCSC_FIDO_NULL || uv == PCSC_FIDO_NULL) {
    return false;
  }
  if (!pcsc_fido_cbor_read_type_len(data, len, off, PCSC_FIDO_CBOR_MAJOR_MAP,
                                    &pairs)) {
    return false;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key_len = 0u;
    bool key_is_up = false;
    bool key_is_uv = false;
    if (!pcsc_fido_cbor_read_type_len(data, len, off, PCSC_FIDO_CBOR_MAJOR_TEXT,
                                      &key_len) ||
        key_len > len - *off) {
      return false;
    }
    key_is_up = key_len == PCSC_FIDO_DEBUG_OPTIONS_KEY_LEN &&
                data[*off] == 'u' && data[*off + 1u] == 'p';
    key_is_uv = key_len == PCSC_FIDO_DEBUG_OPTIONS_KEY_LEN &&
                data[*off] == 'u' && data[*off + 1u] == 'v';
    *off += key_len;
    if (key_is_up) {
      *has_up = pcsc_fido_cbor_read_bool_value(data, len, off, up);
      if (!*has_up) {
        return false;
      }
    } else if (key_is_uv) {
      *has_uv = pcsc_fido_cbor_read_bool_value(data, len, off, uv);
      if (!*has_uv) {
        return false;
      }
    } else if (!pcsc_fido_cbor_skip_item(data, len, off)) {
      return false;
    }
  }
  return true;
}

static const char* ctap2_command_name(uint8_t ctap_cmd) {
  switch (ctap_cmd) {
    case PCSC_FIDO_CTAP2_CMD_MAKE_CREDENTIAL:
      return "makeCredential";
    case PCSC_FIDO_CTAP2_CMD_GET_ASSERTION:
      return "getAssertion";
    case PCSC_FIDO_CTAP2_CMD_GET_INFO:
      return "getInfo";
    case PCSC_FIDO_CTAP2_CMD_CLIENT_PIN:
      return "clientPIN";
    case PCSC_FIDO_CTAP2_CMD_SELECTION:
      return "selection";
    default:
      return "other";
  }
}

static const char* option_bool_label(bool present, bool value) {
  if (!present) {
    return "absent";
  }
  if (value) {
    return "true";
  }
  return "false";
}

void pcsc_fido_bridge_log_ctap2_request_summary(uint8_t hid_cmd,
                                                const uint8_t* payload,
                                                size_t payload_len) {
  size_t off = 1u;
  size_t pairs = 0u;
  uint8_t ctap_cmd;
  size_t options_key;
  size_t pin_key;
  bool has_up = false;
  bool has_uv = false;
  bool up = false;
  bool uv = false;
  bool has_pin_uv_auth_param = false;

  if (!pcsc_fido_bridge_debug_enabled() || hid_cmd != PCSC_FIDO_HID_CMD_CBOR ||
      payload == PCSC_FIDO_NULL || payload_len < 1u) {
    return;
  }
  ctap_cmd = payload[0];
  if (ctap_cmd != PCSC_FIDO_CTAP2_CMD_MAKE_CREDENTIAL &&
      ctap_cmd != PCSC_FIDO_CTAP2_CMD_GET_ASSERTION) {
    pcsc_fido_io_printf(stderr,
                        "pcsc-fido: CTAP2 request %s(0x%02X) payload=%zu\n",
                        ctap2_command_name(ctap_cmd), ctap_cmd, payload_len);
    return;
  }

  if (ctap_cmd == PCSC_FIDO_CTAP2_CMD_MAKE_CREDENTIAL) {
    options_key = PCSC_FIDO_DEBUG_MAKE_CRED_OPTIONS_KEY;
    pin_key = PCSC_FIDO_DEBUG_MAKE_CRED_PIN_UV_KEY;
  } else {
    options_key = PCSC_FIDO_DEBUG_GET_ASSERT_OPTIONS_KEY;
    pin_key = PCSC_FIDO_DEBUG_GET_ASSERT_PIN_UV_KEY;
  }
  if (!pcsc_fido_cbor_read_type_len(payload, payload_len, &off,
                                    PCSC_FIDO_CBOR_MAJOR_MAP, &pairs)) {
    pcsc_fido_io_printf(
        stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-map\n",
        ctap2_command_name(ctap_cmd), payload_len);
    return;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key = 0u;
    if (!pcsc_fido_cbor_read_uint_value(payload, payload_len, &off, &key)) {
      pcsc_fido_io_printf(
          stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-key\n",
          ctap2_command_name(ctap_cmd), payload_len);
      return;
    }
    if (key == options_key) {
      if (!read_ctap_options_summary(payload, payload_len, &off, &has_up, &up,
                                     &has_uv, &uv)) {
        pcsc_fido_io_printf(
            stderr,
            "pcsc-fido: CTAP2 request %s payload=%zu malformed-options\n",
            ctap2_command_name(ctap_cmd), payload_len);
        return;
      }
    } else {
      if (key == pin_key) {
        has_pin_uv_auth_param = true;
      }
      if (!pcsc_fido_cbor_skip_item(payload, payload_len, &off)) {
        pcsc_fido_io_printf(
            stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-value\n",
            ctap2_command_name(ctap_cmd), payload_len);
        return;
      }
    }
  }
  pcsc_fido_io_printf(
      stderr,
      "pcsc-fido: CTAP2 request %s payload=%zu options.up=%s options.uv=%s "
      "pinUvAuthParam=%u\n",
      ctap2_command_name(ctap_cmd), payload_len, option_bool_label(has_up, up),
      option_bool_label(has_uv, uv), (unsigned)has_pin_uv_auth_param);
}

void pcsc_fido_bridge_log_make_credential_summary(const uint8_t* rapdu,
                                                  size_t rapdu_len) {
  /* Debug-only CBOR walk of a makeCredential response.
   * Find attestation authData and log flags (up/uv/at)
   * plus signCount when present. */
  const uint8_t* cbor;
  size_t cbor_len;
  size_t off = 0u;
  size_t pairs = 0u;
  if (!pcsc_fido_bridge_debug_enabled() || rapdu == PCSC_FIDO_NULL ||
      !pcsc_fido_span_ok(0u, PCSC_FIDO_DEBUG_CTAP_STATUS_OK_LEN, rapdu_len) ||
      !pcsc_fido_span_ok(1u, PCSC_FIDO_DEBUG_CTAP_STATUS_AND_SW_LEN,
                         rapdu_len) ||
      rapdu[0] != PCSC_FIDO_CTAP2_OK) {
    return;
  }
  cbor = rapdu + 1u;
  cbor_len = rapdu_len - PCSC_FIDO_DEBUG_CTAP_STATUS_AND_SW_LEN;
  if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off,
                                    PCSC_FIDO_CBOR_MAJOR_MAP, &pairs)) {
    pcsc_fido_io_printf(
        stderr, "pcsc-fido: makeCredential response malformed top-level map\n");
    return;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key = 0u;
    if (!pcsc_fido_cbor_read_uint_value(cbor, cbor_len, &off, &key)) {
      pcsc_fido_io_printf(
          stderr,
          "pcsc-fido: makeCredential response malformed top-level key\n");
      return;
    }
    if (key != PCSC_FIDO_DEBUG_MAKE_CRED_ATTESTATION_KEY) {
      if (!pcsc_fido_cbor_skip_item(cbor, cbor_len, &off)) {
        pcsc_fido_io_printf(
            stderr,
            "pcsc-fido: makeCredential response malformed top-level value\n");
        return;
      }
      continue;
    }
    {
      size_t att_pairs = 0u;
      if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off,
                                        PCSC_FIDO_CBOR_MAJOR_MAP, &att_pairs)) {
        pcsc_fido_io_printf(
            stderr, "pcsc-fido: makeCredential attestation object malformed\n");
        return;
      }
      for (size_t j = 0u; j < att_pairs; j++) {
        bool key_is_auth_data = false;
        if (!pcsc_fido_cbor_read_text_key_matches_len(
                cbor, cbor_len, &off, "authData",
                PCSC_FIDO_DEBUG_AUTHDATA_KEY_LEN, &key_is_auth_data)) {
          pcsc_fido_io_printf(
              stderr,
              "pcsc-fido: makeCredential attestation object malformed key\n");
          return;
        }
        if (key_is_auth_data) {
          size_t auth_len = 0u;
          if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off,
                                            PCSC_FIDO_CBOR_MAJOR_BYTES,
                                            &auth_len) ||
              auth_len > cbor_len - off) {
            pcsc_fido_io_printf(
                stderr, "pcsc-fido: makeCredential authData malformed\n");
            return;
          }
          if (auth_len >= PCSC_FIDO_DEBUG_AUTHDATA_MIN_LEN) {
            const uint8_t* auth = cbor + off;
            uint8_t flags = auth[PCSC_FIDO_DEBUG_AUTHDATA_FLAGS_OFF];
            const uint8_t* sc = auth + PCSC_FIDO_DEBUG_AUTHDATA_SIGN_COUNT_OFF;
            unsigned sign_count = ((unsigned)sc[PCSC_FIDO_DEBUG_SIGN_COUNT_B0]
                                   << PCSC_FIDO_U32_SHIFT_BYTE3) |
                                  ((unsigned)sc[PCSC_FIDO_DEBUG_SIGN_COUNT_B1]
                                   << PCSC_FIDO_U32_SHIFT_BYTE2) |
                                  ((unsigned)sc[PCSC_FIDO_DEBUG_SIGN_COUNT_B2]
                                   << PCSC_FIDO_U32_SHIFT_BYTE1) |
                                  (unsigned)sc[PCSC_FIDO_DEBUG_SIGN_COUNT_B3];
            pcsc_fido_io_printf(
                stderr,
                "pcsc-fido: makeCredential authData flags=0x%02X up=%u "
                "uv=%u at=%u "
                "signCount=%u\n",
                flags,
                (unsigned)((flags & PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UP) != 0u),
                (unsigned)((flags & PCSC_FIDO_DEBUG_AUTHDATA_FLAG_UV) != 0u),
                (unsigned)((flags & PCSC_FIDO_DEBUG_AUTHDATA_FLAG_AT) != 0u),
                sign_count);
          }
          return;
        }
        if (!pcsc_fido_cbor_skip_item(cbor, cbor_len, &off)) {
          pcsc_fido_io_printf(
              stderr,
              "pcsc-fido: makeCredential attestation object malformed value\n");
          return;
        }
      }
    }
    return;
  }
  pcsc_fido_io_printf(
      stderr, "pcsc-fido: makeCredential response has no attestation object\n");
}
