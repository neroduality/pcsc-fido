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

#include "pcsc_fido/ctaphid.h"

#include "pcsc_fido/mem_util.h"

#include <string.h>

static void put_cid(uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE], uint32_t cid) {
  packet[0] = (uint8_t)((cid >> 24u) & 0xFFu);
  packet[1] = (uint8_t)((cid >> 16u) & 0xFFu);
  packet[2] = (uint8_t)((cid >> 8u) & 0xFFu);
  packet[3] = (uint8_t)(cid & 0xFFu);
}

static uint32_t get_cid(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]) {
  return ((uint32_t)packet[0] << 24u) | ((uint32_t)packet[1] << 16u) | ((uint32_t)packet[2] << 8u) |
         packet[3];
}

bool pcsc_fido_hid_encode_init_packet(uint32_t cid, uint8_t cmd, const uint8_t *payload,
                                      size_t payload_len, uint8_t packet[64]) {
  if (packet == nullptr || payload_len > PCSC_FIDO_HID_INIT_PAYLOAD_MAX ||
      (payload == nullptr && payload_len != 0u)) {
    return false;
  }
  memset(packet, 0, PCSC_FIDO_HID_PACKET_SIZE);
  put_cid(packet, cid);
  packet[4] = (uint8_t)(0x80u | cmd);
  packet[5] = (uint8_t)((payload_len >> 8u) & 0xFFu);
  packet[6] = (uint8_t)(payload_len & 0xFFu);
  if (payload_len != 0u &&
      !pcsc_fido_copy_bytes(packet, PCSC_FIDO_HID_PACKET_SIZE, 7u, payload, payload_len)) {
    return false;
  }
  return true;
}

bool pcsc_fido_hid_encode_cont_packet(uint32_t cid, uint8_t seq, const uint8_t *payload,
                                      size_t payload_len, uint8_t packet[64]) {
  if (packet == nullptr || seq > 0x7Fu || payload_len > PCSC_FIDO_HID_CONT_PAYLOAD_MAX ||
      (payload == nullptr && payload_len != 0u)) {
    return false;
  }
  memset(packet, 0, PCSC_FIDO_HID_PACKET_SIZE);
  put_cid(packet, cid);
  packet[4] = seq;
  if (payload_len != 0u &&
      !pcsc_fido_copy_bytes(packet, PCSC_FIDO_HID_PACKET_SIZE, 5u, payload, payload_len)) {
    return false;
  }
  return true;
}

bool pcsc_fido_hid_decode_init_header(const uint8_t packet[64], uint32_t *cid, uint8_t *cmd,
                                      size_t *payload_len) {
  if (packet == nullptr || cid == nullptr || cmd == nullptr || payload_len == nullptr ||
      (packet[4] & 0x80u) == 0u) {
    return false;
  }
  *cid = get_cid(packet);
  *cmd = (uint8_t)(packet[4] & 0x7Fu);
  *payload_len = ((size_t)packet[5] << 8u) | packet[6];
  return true;
}

static bool exchange_init(pcsc_fido_hid_io_t *io, uint32_t *cid, int timeout_ms) {
  static const uint8_t nonce[8] = {'N', 'E', 'R', 'O', 'F', 'I', 'D', 'O'};
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  uint8_t response[PCSC_FIDO_HID_PACKET_SIZE];
  uint32_t response_cid;
  uint8_t cmd;
  size_t len;

  if (io == nullptr || cid == nullptr) {
    return false;
  }
  if (!pcsc_fido_hid_encode_init_packet(PCSC_FIDO_HID_BROADCAST_CID, PCSC_FIDO_HID_CMD_INIT, nonce,
                                        sizeof(nonce), packet)) {
    return false;
  }
  if (io->write_packet(io->ctx, packet, sizeof(packet)) != 0 ||
      io->read_packet(io->ctx, response, sizeof(response), timeout_ms) != 0 ||
      !pcsc_fido_hid_decode_init_header(response, &response_cid, &cmd, &len)) {
    return false;
  }
  if (response_cid != PCSC_FIDO_HID_BROADCAST_CID || cmd != PCSC_FIDO_HID_CMD_INIT || len < 17u ||
      memcmp(response + 7u, nonce, sizeof(nonce)) != 0) {
    return false;
  }
  *cid = ((uint32_t)response[15] << 24u) | ((uint32_t)response[16] << 16u) |
         ((uint32_t)response[17] << 8u) | response[18];
  return *cid != 0u && *cid != PCSC_FIDO_HID_BROADCAST_CID;
}

static bool send_payload(pcsc_fido_hid_io_t *io, uint32_t cid, uint8_t hid_cmd,
                         const uint8_t *payload, size_t payload_len) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  size_t sent;
  uint8_t seq;

  if (io == nullptr || (payload == nullptr && payload_len != 0u)) {
    return false;
  }
  if (payload_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
    return false;
  }
  sent =
    payload_len < PCSC_FIDO_HID_INIT_PAYLOAD_MAX ? payload_len : PCSC_FIDO_HID_INIT_PAYLOAD_MAX;
  if (!pcsc_fido_hid_encode_init_packet(cid, hid_cmd, payload, sent, packet)) {
    return false;
  }
  packet[5] = (uint8_t)((payload_len >> 8u) & 0xFFu);
  packet[6] = (uint8_t)(payload_len & 0xFFu);
  if (io->write_packet(io->ctx, packet, sizeof(packet)) != 0) {
    return false;
  }
  seq = 0u;
  while (sent < payload_len) {
    const size_t remaining = payload_len - sent;
    const size_t chunk =
      remaining < PCSC_FIDO_HID_CONT_PAYLOAD_MAX ? remaining : PCSC_FIDO_HID_CONT_PAYLOAD_MAX;
    if (!pcsc_fido_hid_encode_cont_packet(cid, seq, payload + sent, chunk, packet)) {
      return false;
    }
    if (io->write_packet(io->ctx, packet, sizeof(packet)) != 0) {
      return false;
    }
    sent += chunk;
    seq++;
  }
  return true;
}

static bool receive_payload(pcsc_fido_hid_io_t *io, uint32_t cid, uint8_t hid_cmd,
                            uint8_t *response, size_t response_cap, size_t *response_len,
                            int timeout_ms) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  uint32_t response_cid;
  uint8_t cmd;
  uint8_t seq;
  size_t expected;
  size_t copied;

  if (io == nullptr || response == nullptr || response_len == nullptr) {
    return false;
  }
  for (;;) {
    if (io->read_packet(io->ctx, packet, sizeof(packet), timeout_ms) != 0) {
      return false;
    }
    if (!pcsc_fido_hid_decode_init_header(packet, &response_cid, &cmd, &expected)) {
      continue;
    }
    if (response_cid != cid) {
      continue;
    }
    if (cmd == PCSC_FIDO_HID_CMD_KEEPALIVE) {
      continue;
    }
    break;
  }
  if (cmd != hid_cmd || expected > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD ||
      expected > response_cap) {
    return false;
  }
  copied = expected < PCSC_FIDO_HID_INIT_PAYLOAD_MAX ? expected : PCSC_FIDO_HID_INIT_PAYLOAD_MAX;
  if (copied != 0u && !pcsc_fido_copy_bytes(response, response_cap, 0u, packet + 7u, copied)) {
    return false;
  }
  seq = 0u;
  while (copied < expected) {
    size_t chunk;
    if (io->read_packet(io->ctx, packet, sizeof(packet), timeout_ms) != 0 ||
        get_cid(packet) != cid || packet[4] != seq) {
      return false;
    }
    chunk = expected - copied;
    if (chunk > PCSC_FIDO_HID_CONT_PAYLOAD_MAX) {
      chunk = PCSC_FIDO_HID_CONT_PAYLOAD_MAX;
    }
    if (!pcsc_fido_copy_bytes(response, response_cap, copied, packet + 5u, chunk)) {
      return false;
    }
    copied += chunk;
    seq++;
  }
  *response_len = copied;
  return true;
}

bool pcsc_fido_hid_exchange(pcsc_fido_hid_io_t *io, uint8_t hid_cmd, const uint8_t *payload,
                            size_t payload_len, uint8_t *response, size_t response_cap,
                            size_t *response_len, int timeout_ms) {
  uint32_t cid;
  if (io == nullptr || io->write_packet == nullptr || io->read_packet == nullptr ||
      response == nullptr || response_len == nullptr || (payload == nullptr && payload_len != 0u)) {
    return false;
  }
  if (!exchange_init(io, &cid, timeout_ms)) {
    return false;
  }
  if (!send_payload(io, cid, hid_cmd, payload, payload_len)) {
    return false;
  }
  return receive_payload(io, cid, hid_cmd, response, response_cap, response_len, timeout_ms);
}
