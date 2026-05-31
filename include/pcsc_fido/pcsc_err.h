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

#include <stddef.h>

#define PCSC_FIDO_ERR_MSG_CANCELLED "cancelled"
#define PCSC_FIDO_ERR_MSG_RATE_LIMIT "PC/SC exchange rate limit exceeded"
#define PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT "cancelled while waiting for FIDO NFC card"

void pcsc_fido_set_err(char *err, size_t err_cap, const char *msg);
void pcsc_fido_set_pcsc_err(char *err, size_t err_cap, const char *stage, long rv);
PCSC_FIDO_NODISCARD bool pcsc_fido_format_err(char *err, size_t err_cap, const char *fmt, ...);
