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

#include "pcsc_fido/daemon_hid.h"

#include "pcsc_fido/pcsc_bridge_limits.h"

uint32_t pcsc_fido_daemon_hid_packet_cid(
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]) {
  if (packet == PCSC_FIDO_NULL) {
    return 0u;
  }
  return ((uint32_t)packet[PCSC_FIDO_HID_OFF_CID_B0]
          << PCSC_FIDO_U32_SHIFT_BYTE3) |
         ((uint32_t)packet[PCSC_FIDO_HID_OFF_CID_B1]
          << PCSC_FIDO_U32_SHIFT_BYTE2) |
         ((uint32_t)packet[PCSC_FIDO_HID_OFF_CID_B2]
          << PCSC_FIDO_U32_SHIFT_BYTE1) |
         packet[PCSC_FIDO_HID_OFF_CID_B3];
}

bool pcsc_fido_daemon_hid_is_cancel_packet(
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t cid) {
  if (packet == PCSC_FIDO_NULL) {
    return false;
  }
  return pcsc_fido_daemon_hid_packet_cid(packet) == cid &&
         packet[PCSC_FIDO_HID_OFF_CMD] ==
             (PCSC_FIDO_HID_TYPE_INIT | PCSC_FIDO_HID_CMD_CANCEL) &&
         packet[PCSC_FIDO_HID_OFF_BCNTH] == 0u &&
         packet[PCSC_FIDO_HID_OFF_BCNTL] == 0u;
}

bool pcsc_fido_daemon_hid_decode_init_header(
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t* cid,
    uint8_t* cmd, size_t* payload_len) {
  return pcsc_fido_hid_decode_init_header(packet, cid, cmd, payload_len);
}
