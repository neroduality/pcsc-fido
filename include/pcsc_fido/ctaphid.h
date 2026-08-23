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

/* Spec prefixes for docs/spec-traceability.yaml: IMPL-POLICY CTAPHID
 * (cite in-file as [IMPL-POLICY], [CTAPHID]). */
#define PCSC_FIDO_HID_BROADCAST_CID 0xFFFFFFFFu /* [CTAPHID] §11.2.1 */

enum {
  PCSC_FIDO_HID_PACKET_SIZE = 64u, /* [CTAPHID] §11.2.3 */
  PCSC_FIDO_HID_CID_LEN = 4u,
  PCSC_FIDO_HID_OFF_CID_B0 = 0u,
  PCSC_FIDO_HID_OFF_CID_B1 = 1u,
  PCSC_FIDO_HID_OFF_CID_B2 = 2u,
  PCSC_FIDO_HID_OFF_CID_B3 = 3u,
  PCSC_FIDO_HID_OFF_CMD = 4u,
  PCSC_FIDO_HID_OFF_BCNTH = 5u,
  PCSC_FIDO_HID_OFF_BCNTL = 6u,
  PCSC_FIDO_HID_OFF_INIT_DATA = 7u,
  PCSC_FIDO_HID_OFF_CONT_DATA = 5u,
  PCSC_FIDO_HID_INIT_HEADER_LEN = 7u,
  PCSC_FIDO_HID_CONT_HEADER_LEN = 5u,
  PCSC_FIDO_HID_TYPE_INIT = 0x80u, /* [CTAPHID] §11.2.3 */
  PCSC_FIDO_HID_CMD_MASK = 0x7Fu,
  PCSC_FIDO_HID_SEQ_MAX = 0x7Fu,
  PCSC_FIDO_HID_CONT_SEQ_COUNT = 0x80u,
  PCSC_FIDO_HID_INIT_PAYLOAD_MAX = 57u, /* [CTAPHID] */
  PCSC_FIDO_HID_CONT_PAYLOAD_MAX = 59u, /* [CTAPHID] */
  PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD =
      PCSC_FIDO_HID_INIT_PAYLOAD_MAX +
      (PCSC_FIDO_HID_CONT_SEQ_COUNT * PCSC_FIDO_HID_CONT_PAYLOAD_MAX),
  PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD_EXACT = 7609u, /* [CTAPHID] */
  /* Keep APDU buffers slightly above the CTAPHID framing maximum for card-side
     slack. Implementation policy (non-normative). */
  PCSC_FIDO_CTAPHID_MAX_PAYLOAD = 8192u, /* [IMPL-POLICY] */
  PCSC_FIDO_HID_CMD_INIT = 0x06u,        /* [CTAPHID] §11.2.9.1.3 */
  PCSC_FIDO_HID_CMD_PING = 0x01u,        /* [CTAPHID] §11.2.9.1.4 */
  PCSC_FIDO_HID_CMD_MSG = 0x03u,         /* [CTAPHID] §11.2.9.1.1 */
  PCSC_FIDO_HID_CMD_LOCK = 0x04u,        /* [CTAPHID] §11.2.9.2.2 */
  PCSC_FIDO_HID_CMD_WINK = 0x08u,        /* [CTAPHID] §11.2.9.2.1 */
  PCSC_FIDO_HID_CMD_CBOR = 0x10u,        /* [CTAPHID] §11.2.9.1.2 */
  PCSC_FIDO_HID_CMD_CANCEL = 0x11u,      /* [CTAPHID] §11.2.9.1.5 */
  PCSC_FIDO_HID_CMD_KEEPALIVE = 0x3Bu,   /* [CTAPHID] §11.2.9.1.7 */
  PCSC_FIDO_HID_CMD_ERROR = 0x3Fu,       /* [CTAPHID] §11.2.9.1.6 */
  PCSC_FIDO_HID_INIT_NONCE_LEN = 8u,     /* [CTAPHID] */
  PCSC_FIDO_HID_INIT_RESP_MIN_LEN = 17u,
  PCSC_FIDO_HID_INIT_RESP_CID_OFF = 15u,
  PCSC_FIDO_HID_INIT_RESP_LEN = 17u,
  PCSC_FIDO_HID_INIT_RESP_CID_LEN = 4u,
  PCSC_FIDO_HID_INIT_RESP_INFO_LEN = 5u,
  PCSC_FIDO_HID_INIT_RESP_PROTOCOL_VERSION = 2u, /* [CTAPHID] */
  PCSC_FIDO_HID_INIT_RESP_MAJOR = 0u,
  PCSC_FIDO_HID_INIT_RESP_MINOR = 1u,
  PCSC_FIDO_HID_INIT_RESP_BUILD = 0u,
  PCSC_FIDO_HID_INIT_RESP_INFO_OFF_PROTOCOL = 0u,
  PCSC_FIDO_HID_INIT_RESP_INFO_OFF_MAJOR = 1u,
  PCSC_FIDO_HID_INIT_RESP_INFO_OFF_MINOR = 2u,
  PCSC_FIDO_HID_INIT_RESP_INFO_OFF_BUILD = 3u,
  PCSC_FIDO_HID_INIT_RESP_INFO_OFF_CAPABILITIES = 4u,
  /* "NFC\x01" -- stable demo CID assigned after CTAPHID INIT. */
  PCSC_FIDO_DEFAULT_ASSIGNED_CID = 0x4E464301u,
};

PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_HID_INIT_PAYLOAD_MAX ==
                            PCSC_FIDO_HID_PACKET_SIZE -
                                PCSC_FIDO_HID_INIT_HEADER_LEN,
                        "CTAPHID init payload must fit init packet body");
PCSC_FIDO_STATIC_ASSERT(
    PCSC_FIDO_HID_CONT_PAYLOAD_MAX ==
        PCSC_FIDO_HID_PACKET_SIZE - PCSC_FIDO_HID_CONT_HEADER_LEN,
    "CTAPHID continuation payload must fit continuation packet body");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD ==
                            PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD_EXACT,
                        "CTAPHID seq range must frame exactly 7609 bytes");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD <=
                            PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
                        "framed CTAPHID payload must fit internal buffers");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_HID_INIT_RESP_LEN ==
                            PCSC_FIDO_HID_INIT_NONCE_LEN +
                                PCSC_FIDO_HID_INIT_RESP_CID_LEN +
                                PCSC_FIDO_HID_INIT_RESP_INFO_LEN,
                        "CTAPHID INIT response is nonce + CID + device info");

typedef int (*pcsc_fido_hid_write_fn_t)(void* ctx, const uint8_t* packet,
                                        size_t packet_len);
typedef int (*pcsc_fido_hid_read_fn_t)(void* ctx, uint8_t* packet,
                                       size_t packet_len, int timeout_ms);

typedef struct {
  void* ctx;
  pcsc_fido_hid_write_fn_t write_packet;
  pcsc_fido_hid_read_fn_t read_packet;
} pcsc_fido_hid_io_t;

PCSC_FIDO_NODISCARD bool pcsc_fido_hid_encode_init_packet(
    uint32_t cid, uint8_t cmd, const uint8_t* payload, size_t payload_len,
    uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]);
PCSC_FIDO_NODISCARD bool pcsc_fido_hid_encode_cont_packet(
    uint32_t cid, uint8_t seq, const uint8_t* payload, size_t payload_len,
    uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]);
PCSC_FIDO_NODISCARD bool pcsc_fido_hid_decode_init_header(
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t* cid,
    uint8_t* cmd, size_t* payload_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_hid_exchange(
    pcsc_fido_hid_io_t* io, uint8_t hid_cmd, const uint8_t* payload,
    size_t payload_len, uint8_t* response, size_t response_cap,
    size_t* response_len, int timeout_ms);
