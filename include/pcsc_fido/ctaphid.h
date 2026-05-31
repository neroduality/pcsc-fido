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

#define PCSC_FIDO_HID_BROADCAST_CID UINT32_C(0xFFFFFFFF)

enum {
  PCSC_FIDO_HID_PACKET_SIZE = 64u,
  PCSC_FIDO_HID_INIT_PAYLOAD_MAX = 57u,
  PCSC_FIDO_HID_CONT_PAYLOAD_MAX = 59u,
  PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD =
    PCSC_FIDO_HID_INIT_PAYLOAD_MAX + (0x80u * PCSC_FIDO_HID_CONT_PAYLOAD_MAX),
  /* Keep APDU buffers slightly above the CTAPHID framing maximum for card-side slack. */
  PCSC_FIDO_CTAPHID_MAX_PAYLOAD = 8192u,
  PCSC_FIDO_HID_CMD_INIT = 0x06u,
  PCSC_FIDO_HID_CMD_PING = 0x01u,
  PCSC_FIDO_HID_CMD_MSG = 0x03u,
  PCSC_FIDO_HID_CMD_LOCK = 0x04u,
  PCSC_FIDO_HID_CMD_WINK = 0x08u,
  PCSC_FIDO_HID_CMD_CBOR = 0x10u,
  PCSC_FIDO_HID_CMD_CANCEL = 0x11u,
  PCSC_FIDO_HID_CMD_KEEPALIVE = 0x3Bu,
  PCSC_FIDO_HID_CMD_ERROR = 0x3Fu,
};

PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_HID_INIT_PAYLOAD_MAX == PCSC_FIDO_HID_PACKET_SIZE - 7u,
                        "CTAPHID init payload must fit init packet body");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_HID_CONT_PAYLOAD_MAX == PCSC_FIDO_HID_PACKET_SIZE - 5u,
                        "CTAPHID continuation payload must fit continuation packet body");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD == 7609u,
                        "CTAPHID seq range must frame exactly 7609 bytes");
PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD <= PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
                        "framed CTAPHID payload must fit internal buffers");

typedef int (*pcsc_fido_hid_write_fn)(void *ctx, const uint8_t *packet, size_t packet_len);
typedef int (*pcsc_fido_hid_read_fn)(void *ctx, uint8_t *packet, size_t packet_len, int timeout_ms);

typedef struct {
  void *ctx;
  pcsc_fido_hid_write_fn write_packet;
  pcsc_fido_hid_read_fn read_packet;
} pcsc_fido_hid_io_t;

PCSC_FIDO_NODISCARD bool
pcsc_fido_hid_encode_init_packet(uint32_t cid, uint8_t cmd, const uint8_t *payload,
                                 size_t payload_len, uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]);
PCSC_FIDO_NODISCARD bool
pcsc_fido_hid_encode_cont_packet(uint32_t cid, uint8_t seq, const uint8_t *payload,
                                 size_t payload_len, uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]);
PCSC_FIDO_NODISCARD bool
pcsc_fido_hid_decode_init_header(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t *cid,
                                 uint8_t *cmd, size_t *payload_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_hid_exchange(pcsc_fido_hid_io_t *io, uint8_t hid_cmd,
                                                const uint8_t *payload, size_t payload_len,
                                                uint8_t *response, size_t response_cap,
                                                size_t *response_len, int timeout_ms);
