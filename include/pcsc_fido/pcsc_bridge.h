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
#include <stdio.h>

PCSC_FIDO_NODISCARD bool pcsc_fido_bridge_exchange(const char *reader_needle, uint8_t hid_cmd,
                                                   const uint8_t *payload, size_t payload_len,
                                                   uint8_t *response, size_t response_cap,
                                                   size_t *response_len, char *err, size_t err_cap);
PCSC_FIDO_NODISCARD bool pcsc_fido_bridge_list_readers(FILE *out, char *err, size_t err_cap);
void pcsc_fido_bridge_cancel(void);
void pcsc_fido_bridge_reset(void);
