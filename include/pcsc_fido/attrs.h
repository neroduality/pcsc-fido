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

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define PCSC_FIDO_NODISCARD [[nodiscard]]
#define PCSC_FIDO_UNREACHABLE() unreachable()
#define PCSC_FIDO_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define PCSC_FIDO_NODISCARD
#define PCSC_FIDO_UNREACHABLE() __builtin_unreachable()
#define PCSC_FIDO_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/*
 * Suffix placement on parameters (int x PCSC_FIDO_MAYBE_UNUSED). GCC/Clang
 * __attribute__((unused)) works there; C23 [[maybe_unused]] belongs before the
 * declarator and is not used here. Prefer the compiler attribute on supported
 * toolchains so -std=c2x builds (GCC 13: __STDC_VERSION__ 202000L) still
 * silence -Wunused-parameter from -Wextra.
 */
#if defined(__GNUC__) || defined(__clang__)
#define PCSC_FIDO_MAYBE_UNUSED __attribute__((unused))
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define PCSC_FIDO_MAYBE_UNUSED [[maybe_unused]]
#else
#define PCSC_FIDO_MAYBE_UNUSED
#endif

/*
 * C23 [[unsequenced]] / [[reproducible]] function-type attributes.
 *
 * Placed *after* the parameter list on a function declarator. They are probed
 * with __has_c_attribute so toolchains that do not implement them (for example
 * current Clang) silently fall back to no annotation. Use:
 *   - PCSC_FIDO_UNSEQUENCED for stateless, effectless, idempotent, independent
 *     functions whose result depends only on their scalar arguments and that do
 *     not read or write through any pointer (strongest contract).
 *   - PCSC_FIDO_REPRODUCIBLE for side-effect-free functions that may read memory
 *     reachable through their arguments and always return the same value for the
 *     same inputs (pure readers/parsers).
 * Do NOT annotate functions that write through out-pointers or touch globals.
 */
#if defined(__has_c_attribute)
#if __has_c_attribute(unsequenced)
#define PCSC_FIDO_UNSEQUENCED [[unsequenced]]
#endif
#if __has_c_attribute(reproducible)
#define PCSC_FIDO_REPRODUCIBLE [[reproducible]]
#endif
#endif
#ifndef PCSC_FIDO_UNSEQUENCED
#define PCSC_FIDO_UNSEQUENCED
#endif
#ifndef PCSC_FIDO_REPRODUCIBLE
#define PCSC_FIDO_REPRODUCIBLE
#endif

#if defined(PCSC_FIDO_HAVE_COUNTED_BY) && PCSC_FIDO_HAVE_COUNTED_BY
#if defined(__clang__)
#define PCSC_FIDO_COUNTED_BY(N) [[clang::counted_by(N)]]
#elif defined(__GNUC__)
#define PCSC_FIDO_COUNTED_BY(N) __attribute__((counted_by(N)))
#else
#define PCSC_FIDO_COUNTED_BY(N) [[counted_by(N)]]
#endif
#else
#define PCSC_FIDO_COUNTED_BY(N)
#endif
