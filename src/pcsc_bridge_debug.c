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

#define _POSIX_C_SOURCE 200809L

#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/pcsc_bridge_debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool pcsc_fido_bridge_debug_enabled(void) {
#if defined(NDEBUG)
  return false;
#else
  const char *v = getenv("PCSC_FIDO_DEBUG");
  if (v == nullptr || v[0] == '\0') {
    return false;
  }
  return strcmp(v, "0") != 0;
#endif
}

void pcsc_fido_bridge_log_apdu_response_hex(const char *label, const uint8_t *rapdu,
                                            size_t rapdu_len) {
  bool truncated = rapdu_len > 220u;
  size_t n = truncated ? 220u : rapdu_len;
  if (!pcsc_fido_bridge_debug_enabled() || label == nullptr) {
    return;
  }
  fprintf(stderr, "pcsc-fido: %s hex=", label);
  for (size_t i = 0u; i < n; i++) {
    fprintf(stderr, "%02X", rapdu[i]);
  }
  if (truncated) {
    fprintf(stderr, "...");
  }
  fprintf(stderr, "\n");
}

void pcsc_fido_bridge_log_get_assertion_summary(const uint8_t *rapdu, size_t rapdu_len) {
  const uint8_t *cbor;
  size_t cbor_len;
  if (!pcsc_fido_bridge_debug_enabled() || rapdu == nullptr || rapdu_len < 4u ||
      rapdu[0] != 0x00u) {
    return;
  }
  cbor = rapdu + 1u;
  cbor_len = rapdu_len - 3u;
  for (size_t i = 0u; i + 34u < cbor_len; i++) {
    size_t auth_off = 0u;
    size_t auth_len = 0u;
    if (cbor[i] != 0x02u) {
      continue;
    }
    if ((cbor[i + 1u] & 0xE0u) == 0x40u) {
      auth_len = cbor[i + 1u] & 0x1Fu;
      auth_off = i + 2u;
    } else if (cbor[i + 1u] == 0x58u && i + 2u < cbor_len) {
      auth_len = cbor[i + 2u];
      auth_off = i + 3u;
    } else if (cbor[i + 1u] == 0x59u && i + 3u < cbor_len) {
      auth_len = ((size_t)cbor[i + 2u] << 8u) | cbor[i + 3u];
      auth_off = i + 4u;
    }
    if (auth_len >= 37u && auth_off + auth_len <= cbor_len) {
      uint8_t flags = cbor[auth_off + 32u];
      fprintf(stderr, "pcsc-fido: getAssertion authData flags=0x%02X up=%u uv=%u\n", flags,
              (unsigned)((flags & 0x01u) != 0u), (unsigned)((flags & 0x04u) != 0u));
      return;
    }
  }
}

static bool read_ctap_options_summary(const uint8_t *data, size_t len, size_t *off, bool *has_up,
                                      bool *up, bool *has_uv, bool *uv) {
  size_t pairs = 0u;
  if (data == nullptr || off == nullptr || has_up == nullptr || up == nullptr ||
      has_uv == nullptr || uv == nullptr) {
    return false;
  }
  if (!pcsc_fido_cbor_read_type_len(data, len, off, 5u, &pairs)) {
    return false;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key_len = 0u;
    bool key_is_up = false;
    bool key_is_uv = false;
    if (!pcsc_fido_cbor_read_type_len(data, len, off, 3u, &key_len) || key_len > len - *off) {
      return false;
    }
    key_is_up = key_len == 2u && data[*off] == 'u' && data[*off + 1u] == 'p';
    key_is_uv = key_len == 2u && data[*off] == 'u' && data[*off + 1u] == 'v';
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

static const char *ctap2_command_name(uint8_t ctap_cmd) {
  switch (ctap_cmd) {
  case 0x01u:
    return "makeCredential";
  case 0x02u:
    return "getAssertion";
  case 0x04u:
    return "getInfo";
  case 0x06u:
    return "clientPIN";
  case 0x0Au:
    return "selection";
  default:
    return "other";
  }
}

void pcsc_fido_bridge_log_ctap2_request_summary(uint8_t hid_cmd, const uint8_t *payload,
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
      payload == nullptr || payload_len == 0u) {
    return;
  }
  ctap_cmd = payload[0];
  if (ctap_cmd != 0x01u && ctap_cmd != 0x02u) {
    fprintf(stderr, "pcsc-fido: CTAP2 request %s(0x%02X) payload=%zu\n",
            ctap2_command_name(ctap_cmd), ctap_cmd, payload_len);
    return;
  }

  options_key = ctap_cmd == 0x01u ? 7u : 5u;
  pin_key = ctap_cmd == 0x01u ? 8u : 6u;
  if (!pcsc_fido_cbor_read_type_len(payload, payload_len, &off, 5u, &pairs)) {
    fprintf(stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-map\n",
            ctap2_command_name(ctap_cmd), payload_len);
    return;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key = 0u;
    if (!pcsc_fido_cbor_read_uint_value(payload, payload_len, &off, &key)) {
      fprintf(stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-key\n",
              ctap2_command_name(ctap_cmd), payload_len);
      return;
    }
    if (key == options_key) {
      if (!read_ctap_options_summary(payload, payload_len, &off, &has_up, &up, &has_uv, &uv)) {
        fprintf(stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-options\n",
                ctap2_command_name(ctap_cmd), payload_len);
        return;
      }
    } else {
      if (key == pin_key) {
        has_pin_uv_auth_param = true;
      }
      if (!pcsc_fido_cbor_skip_item(payload, payload_len, &off)) {
        fprintf(stderr, "pcsc-fido: CTAP2 request %s payload=%zu malformed-value\n",
                ctap2_command_name(ctap_cmd), payload_len);
        return;
      }
    }
  }
  fprintf(stderr,
          "pcsc-fido: CTAP2 request %s payload=%zu options.up=%s options.uv=%s "
          "pinUvAuthParam=%u\n",
          ctap2_command_name(ctap_cmd), payload_len, has_up ? (up ? "true" : "false") : "absent",
          has_uv ? (uv ? "true" : "false") : "absent", (unsigned)has_pin_uv_auth_param);
}

void pcsc_fido_bridge_log_make_credential_summary(const uint8_t *rapdu, size_t rapdu_len) {
  const uint8_t *cbor;
  size_t cbor_len;
  size_t off = 0u;
  size_t pairs = 0u;
  if (!pcsc_fido_bridge_debug_enabled() || rapdu == nullptr || rapdu_len < 4u ||
      rapdu[0] != 0x00u) {
    return;
  }
  cbor = rapdu + 1u;
  cbor_len = rapdu_len - 3u;
  if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off, 5u, &pairs)) {
    fprintf(stderr, "pcsc-fido: makeCredential response malformed top-level map\n");
    return;
  }
  for (size_t i = 0u; i < pairs; i++) {
    size_t key = 0u;
    if (!pcsc_fido_cbor_read_uint_value(cbor, cbor_len, &off, &key)) {
      fprintf(stderr, "pcsc-fido: makeCredential response malformed top-level key\n");
      return;
    }
    if (key != 2u) {
      if (!pcsc_fido_cbor_skip_item(cbor, cbor_len, &off)) {
        fprintf(stderr, "pcsc-fido: makeCredential response malformed top-level value\n");
        return;
      }
      continue;
    }
    {
      size_t att_pairs = 0u;
      if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off, 5u, &att_pairs)) {
        fprintf(stderr, "pcsc-fido: makeCredential attestation object malformed\n");
        return;
      }
      for (size_t j = 0u; j < att_pairs; j++) {
        bool key_is_auth_data = false;
        if (!pcsc_fido_cbor_read_text_key_matches_len(cbor, cbor_len, &off, "authData", 8u,
                                                      &key_is_auth_data)) {
          fprintf(stderr, "pcsc-fido: makeCredential attestation object malformed key\n");
          return;
        }
        if (key_is_auth_data) {
          size_t auth_len = 0u;
          if (!pcsc_fido_cbor_read_type_len(cbor, cbor_len, &off, 2u, &auth_len) ||
              auth_len > cbor_len - off) {
            fprintf(stderr, "pcsc-fido: makeCredential authData malformed\n");
            return;
          }
          if (auth_len >= 37u) {
            uint8_t flags = cbor[off + 32u];
            unsigned sign_count = ((unsigned)cbor[off + 33u] << 24u) |
                                  ((unsigned)cbor[off + 34u] << 16u) |
                                  ((unsigned)cbor[off + 35u] << 8u) | (unsigned)cbor[off + 36u];
            fprintf(stderr,
                    "pcsc-fido: makeCredential authData flags=0x%02X up=%u uv=%u at=%u "
                    "signCount=%u\n",
                    flags, (unsigned)((flags & 0x01u) != 0u), (unsigned)((flags & 0x04u) != 0u),
                    (unsigned)((flags & 0x40u) != 0u), sign_count);
          }
          return;
        }
        if (!pcsc_fido_cbor_skip_item(cbor, cbor_len, &off)) {
          fprintf(stderr, "pcsc-fido: makeCredential attestation object malformed value\n");
          return;
        }
      }
    }
    return;
  }
  fprintf(stderr, "pcsc-fido: makeCredential response has no attestation object\n");
}
