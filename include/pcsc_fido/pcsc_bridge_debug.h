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

PCSC_FIDO_NODISCARD bool pcsc_fido_bridge_debug_enabled(void);

void pcsc_fido_bridge_log_ctap2_request_summary(uint8_t hid_cmd, const uint8_t *payload,
                                                size_t payload_len);
void pcsc_fido_bridge_log_apdu_response_hex(const char *label, const uint8_t *rapdu,
                                            size_t rapdu_len);
void pcsc_fido_bridge_log_get_assertion_summary(const uint8_t *rapdu, size_t rapdu_len);
void pcsc_fido_bridge_log_make_credential_summary(const uint8_t *rapdu, size_t rapdu_len);
