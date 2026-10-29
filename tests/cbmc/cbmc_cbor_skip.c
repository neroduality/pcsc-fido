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

#include "cbmc_cprover.h"
#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/ctaphid.h"

#include <stddef.h>
#include <stdint.h>

/* Every input of at most PCSC_FIDO_CBMC_CBOR_SKIP_MAX bytes. Arrays and maps
 * claiming more than PCSC_FIDO_CBMC_CBOR_SKIP_ITEMS elements are excluded
 * (assumed away in cbor_skip_item_depth), and the walk stops at
 * PCSC_FIDO_CBMC_CBOR_SKIP_DEPTH instead of the production nesting cap, so
 * deeper objects are rejected by the proof model and not walked. A fully
 * nondeterministic skip of the 8192-byte payload does not finish. */
#ifndef PCSC_FIDO_CBMC_CBOR_SKIP_MAX
#define PCSC_FIDO_CBMC_CBOR_SKIP_MAX 32u
#endif

int main(void) {
  uint8_t data[PCSC_FIDO_CBMC_CBOR_SKIP_MAX] PCSC_FIDO_CBMC_NONDET;
  size_t len = PCSC_FIDO_CBMC_NONDET_SIZE();
  size_t off = PCSC_FIDO_CBMC_NONDET_SIZE();

  PCSC_FIDO_CBMC_ASSUME(len <= sizeof(data));
  PCSC_FIDO_CBMC_ASSUME(off <= len);

  (void)pcsc_fido_cbor_skip_item(data, len, &off);
  PCSC_FIDO_CBMC_ASSERT(off <= len, "skip offset stays inside the buffer");
  return 0;
}
