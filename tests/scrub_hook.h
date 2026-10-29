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

#include <stdbool.h>
#include <stddef.h>

#include "pcsc_fido/attrs.h"

/*
 * Secure-wipe audit hook for unit tests.
 *
 * Link a test with `-Wl,--wrap=pcsc_fido_secure_clear` and add scrub_hook.c
 * to its sources; every secure_clear performed by the code under test is then
 * routed through __wrap_pcsc_fido_secure_clear, which performs the real wipe
 * and records it. Tests assert that the buffers holding CTAP material were
 * actually wiped (count, size, zeroed content) on both success and error
 * paths, so a dropped PCSC_FIDO_SCRUB_ON_EXIT guard fails a test instead of
 * silently leaving plaintext on the stack.
 */

void scrub_hook_reset(void);
unsigned scrub_hook_calls(void);
size_t scrub_hook_bytes(void);
size_t scrub_hook_max_len(void);
/* True while every observed wipe left its region all-zero afterwards. */
PCSC_FIDO_NODISCARD bool scrub_hook_all_zero(void);
/* Number of observed wipes whose length was exactly `len`. */
unsigned scrub_hook_calls_with_len(size_t len);
