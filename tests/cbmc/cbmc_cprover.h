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

/* Project-prefixed spellings of the CBMC builtins so the harnesses also
 * compile under gcc/clang/clang-tidy (CMake target pcsc_fido_cbmc_harness_lint
 * keeps them in the hardened compile database; defining `__CPROVER_*` here
 * would be a reserved identifier). Under CBMC each maps to the real builtin;
 * elsewhere they evaluate their operands and do nothing.
 *
 * Proof inputs must be nondeterministic, not literal zeros: `size_t n = 0u;`
 * followed by an assume is a single concrete case and the solver never runs.
 * PCSC_FIDO_CBMC_NONDET follows the declarator of an aggregate the proof
 * leaves unconstrained: under CBMC it expands to nothing (an uninitialized
 * local is already nondeterministic); under an ordinary compiler it is a
 * `= {0}` initializer so -Werror=maybe-uninitialized does not reject the
 * harness. PCSC_FIDO_CBMC_NONDET_SIZE() / _U8() yield a nondeterministic
 * scalar under CBMC (bodyless `nondet_*` functions, the CBMC idiom); under an
 * ordinary compiler they read a volatile so neither the compiler nor cppcheck
 * can fold the value and judge the following assume/assert as constant. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__CPROVER__)
size_t nondet_size_t(void);
uint8_t nondet_uint8_t(void);
#define PCSC_FIDO_CBMC_ASSUME(cond) __CPROVER_assume(cond)
#define PCSC_FIDO_CBMC_ASSERT(cond, msg) __CPROVER_assert(cond, msg)
#define PCSC_FIDO_CBMC_SAME_OBJECT(a, b) __CPROVER_same_object(a, b)
#define PCSC_FIDO_CBMC_NONDET
#define PCSC_FIDO_CBMC_NONDET_SIZE() nondet_size_t()
#define PCSC_FIDO_CBMC_NONDET_U8() nondet_uint8_t()
#define PCSC_FIDO_CBMC_HAVOC(ptr) __CPROVER_havoc_object(ptr)
#else
static inline size_t pcsc_fido_cbmc_host_size(void) {
  volatile size_t value = 0u;
  return value;
}
static inline uint8_t pcsc_fido_cbmc_host_u8(void) {
  volatile uint8_t value = 0u;
  return value;
}
#define PCSC_FIDO_CBMC_ASSUME(cond) ((void)(cond))
#define PCSC_FIDO_CBMC_ASSERT(cond, msg) ((void)(cond), (void)(msg))
#define PCSC_FIDO_CBMC_SAME_OBJECT(a, b) ((void)(a), (void)(b), 1)
#define PCSC_FIDO_CBMC_NONDET = {0}
#define PCSC_FIDO_CBMC_NONDET_SIZE() pcsc_fido_cbmc_host_size()
#define PCSC_FIDO_CBMC_NONDET_U8() pcsc_fido_cbmc_host_u8()
#define PCSC_FIDO_CBMC_HAVOC(ptr) ((void)(ptr))
#endif
