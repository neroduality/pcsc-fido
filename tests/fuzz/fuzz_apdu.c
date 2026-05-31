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
#include "pcsc_fido/pcsc_bridge_limits.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t packed[PCSC_FIDO_SELECT_APDU_MAX];
  size_t packed_len = 0u;
  uint8_t cbor_out[PCSC_FIDO_BRIDGE_MAX_APDU];
  size_t cbor_len = 0u;

  if (data == nullptr) {
    return 0;
  }

  const pcsc_fido_apdu_t parsed = pcsc_fido_parse_apdu(data, size);
  (void)parsed;

  if (size > 0u) {
    (void)pcsc_fido_pack_select_fido_apdu(packed, sizeof(packed), &packed_len, (data[0] & 1u) != 0u);
    (void)pcsc_fido_pack_ctap2_cbor_apdu(data, size, cbor_out, sizeof(cbor_out), &cbor_len);
  }

  return 0;
}
