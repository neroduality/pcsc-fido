# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Host-only compile/link hardening for pcsc-fido (ISO C23, glibc/Linux).
#
# Aligned with OpenSSF compiler-hardening recommendations (see C-STYLE-CODEFLOW.md):
# aggressive warnings, -ftrivial-auto-var-init=zero / -fzero-call-used-regs when probed,
# -fno-delete-null-pointer-checks / -fno-strict-overflow, -fstrict-flex-arrays=3 when probed,
# stack/CET or AArch64 branch protection, _FORTIFY_SOURCE=3 on optimized builds,
# -fexceptions (pthread), GCC -fzero-init-padding-bits=all when probed,
# ELF relro/now/noexecstack/nodlopen and --as-needed linker hygiene.
#
# Defines INTERFACE library target: pcsc_fido_host_hardening
#
# Requires: CMake 3.20+

add_library(pcsc_fido_host_hardening INTERFACE)

set(_pcsc_fido_fortify_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>)

include("${CMAKE_CURRENT_LIST_DIR}/CompilerHardeningProbes.cmake")

target_compile_options(
  pcsc_fido_host_hardening
  INTERFACE
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>,${_pcsc_fido_fortify_cfg}>:-U_FORTIFY_SOURCE>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>,${_pcsc_fido_fortify_cfg}>:-D_FORTIFY_SOURCE=3>)

target_compile_options(
  pcsc_fido_host_hardening
  INTERFACE
  $<$<COMPILE_LANGUAGE:C>:-Wall>
  $<$<COMPILE_LANGUAGE:C>:-Wextra>
  $<$<COMPILE_LANGUAGE:C>:-Wpedantic>
  $<$<COMPILE_LANGUAGE:C>:-Wformat=2>
  $<$<COMPILE_LANGUAGE:C>:-Wformat-security>
  $<$<COMPILE_LANGUAGE:C>:-Werror=format-security>
  $<$<COMPILE_LANGUAGE:C>:-Werror=implicit>
  $<$<COMPILE_LANGUAGE:C>:-Werror=incompatible-pointer-types>
  $<$<COMPILE_LANGUAGE:C>:-Werror=int-conversion>
  $<$<COMPILE_LANGUAGE:C>:-Wnull-dereference>
  $<$<COMPILE_LANGUAGE:C>:-Wshadow>
  $<$<COMPILE_LANGUAGE:C>:-Wcast-qual>
  $<$<COMPILE_LANGUAGE:C>:-Wundef>
  $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
  $<$<COMPILE_LANGUAGE:C>:-Wwrite-strings>
  $<$<COMPILE_LANGUAGE:C>:-Wconversion>
  $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
  $<$<COMPILE_LANGUAGE:C>:-Wvla>
  $<$<COMPILE_LANGUAGE:C>:-Walloca>
  $<$<COMPILE_LANGUAGE:C>:-Wdouble-promotion>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wshift-overflow=2>
  $<$<COMPILE_LANGUAGE:C>:-Wswitch-enum>
  $<$<COMPILE_LANGUAGE:C>:-Wunused-result>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wimplicit-fallthrough=5>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Warray-bounds=2>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wstringop-overflow=4>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wduplicated-cond>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wduplicated-branches>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wtrampolines>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_WBIDI_CHARS_ANY}>>:-Wbidi-chars=any>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_WIMPLICIT_FALLTHROUGH}>>:-Wimplicit-fallthrough>
  $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
  $<$<COMPILE_LANGUAGE:C>:-fno-delete-null-pointer-checks>
  $<$<COMPILE_LANGUAGE:C>:-fno-strict-overflow>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_EXCEPTIONS}>>:-fexceptions>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_STRICT_FLEX_ARRAYS_3}>>:-fstrict-flex-arrays=3>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO}>>:-ftrivial-auto-var-init=zero>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_ZERO_INIT_PADDING_BITS_ALL}>>:-fzero-init-padding-bits=all>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${PCSC_FIDO_HAVE_C_ZERO_CALL_USED_REGS_GPR}>>:-fzero-call-used-regs=used-gpr>)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$" AND NOT APPLE AND NOT CMAKE_CROSSCOMPILING)
  target_compile_options(
    pcsc_fido_host_hardening
    INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-fcf-protection=full>>)
elseif(NOT APPLE AND PCSC_FIDO_HAVE_ARM_BRANCH_PROTECTION_STANDARD)
  target_compile_options(
    pcsc_fido_host_hardening
    INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-mbranch-protection=standard>>)
endif()

target_compile_options(
  pcsc_fido_host_hardening
  INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-fstack-protector-strong>>)

if(NOT APPLE)
  target_compile_options(
    pcsc_fido_host_hardening
    INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-fstack-clash-protection>>)
endif()

if(UNIX AND NOT APPLE)
  target_link_options(
    pcsc_fido_host_hardening
    INTERFACE
    "LINKER:-z,relro"
    "LINKER:-z,now"
    "LINKER:-z,noexecstack"
    "LINKER:-z,nodlopen"
    "LINKER:--as-needed"
    "LINKER:--no-copy-dt-needed-entries")
endif()
