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

uint32_t pcsc_fido_daemon_hid_packet_cid(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]) {
  if (packet == nullptr) {
    return 0u;
  }
  return ((uint32_t)packet[0] << 24u) | ((uint32_t)packet[1] << 16u) | ((uint32_t)packet[2] << 8u) |
         packet[3];
}

bool pcsc_fido_daemon_hid_is_cancel_packet(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                           uint32_t cid) {
  if (packet == nullptr) {
    return false;
  }
  return pcsc_fido_daemon_hid_packet_cid(packet) == cid &&
         packet[4] == (0x80u | PCSC_FIDO_HID_CMD_CANCEL) && packet[5] == 0u && packet[6] == 0u;
}

bool pcsc_fido_daemon_hid_decode_init_header(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                             uint32_t *cid, uint8_t *cmd, size_t *payload_len) {
  return pcsc_fido_hid_decode_init_header(packet, cid, cmd, payload_len);
}
