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

#include "pcsc_fido/ctaphid.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int fd;
  const uint32_t *assigned_cid;
} pcsc_fido_daemon_request_context_t;

void pcsc_fido_daemon_handle_hid_request(const pcsc_fido_daemon_request_context_t *ctx,
                                         uint32_t request_cid, uint8_t cmd, const uint8_t *payload,
                                         size_t payload_len);
