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

PCSC_FIDO_NODISCARD bool pcsc_fido_rate_limit_allow_ctaphid(void);
PCSC_FIDO_NODISCARD bool pcsc_fido_rate_limit_allow_exchange(void);
/* Consumes an exchange token and marks the next bridge exchange as already
 * charged, so the handler can refuse before it touches the PC/SC session.
 * The mark is per calling thread: one thread cannot drop another's. */
PCSC_FIDO_NODISCARD bool pcsc_fido_rate_limit_charge_exchange(void);
/* True when some caller already charged an exchange that nobody has adopted.
 * Adopts one such charge. */
PCSC_FIDO_NODISCARD bool pcsc_fido_rate_limit_take_exchange_charge(void);
/* Drops this thread's charges that no bridge exchange adopted. Another
 * thread's charge stays. The tokens stay spent. */
void pcsc_fido_rate_limit_release_exchange_charge(void);
/* Forgets this thread's charge count without returning those charges to the
 * pool. The worker calls this path's take before the joiner returns; the
 * joiner then drops only its thread-local count. */
void pcsc_fido_rate_limit_detach_local_charge(void);
void pcsc_fido_rate_limit_reset(void);
