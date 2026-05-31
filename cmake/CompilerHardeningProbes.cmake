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

# Configure-time probes for optional hardening flags (hosted Linux ISO C23 builds).
# Sets cache booleans consumed by HostHardening.cmake.

include(CheckCCompilerFlag)

check_c_compiler_flag(-ftrivial-auto-var-init=zero PCSC_FIDO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO)
check_c_compiler_flag(-fzero-call-used-regs=used-gpr PCSC_FIDO_HAVE_C_ZERO_CALL_USED_REGS_GPR)
check_c_compiler_flag(-fstrict-flex-arrays=3 PCSC_FIDO_HAVE_C_STRICT_FLEX_ARRAYS_3)
check_c_compiler_flag(-fexceptions PCSC_FIDO_HAVE_C_EXCEPTIONS)

set(_pcsc_fido_probe_save_flags_c "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "-O2")
check_c_compiler_flag(-fhardened PCSC_FIDO_HAVE_C_FHARDENED)
check_c_compiler_flag(-fzero-init-padding-bits=all PCSC_FIDO_HAVE_C_ZERO_INIT_PADDING_BITS_ALL)
set(CMAKE_REQUIRED_FLAGS "${_pcsc_fido_probe_save_flags_c}")

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  check_c_compiler_flag(-Wbidi-chars=any PCSC_FIDO_HAVE_C_WBIDI_CHARS_ANY)
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  check_c_compiler_flag(-Wimplicit-fallthrough PCSC_FIDO_HAVE_C_WIMPLICIT_FALLTHROUGH)
else()
  set(PCSC_FIDO_HAVE_C_WBIDI_CHARS_ANY FALSE)
  set(PCSC_FIDO_HAVE_C_WIMPLICIT_FALLTHROUGH FALSE)
endif()

set(PCSC_FIDO_HAVE_ARM_BRANCH_PROTECTION_STANDARD 0)
if(UNIX
   AND NOT APPLE
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AArch64|arm64|ARM64)$")
  check_c_compiler_flag(-mbranch-protection=standard PCSC_FIDO_HAVE_ARM_BRANCH_PROTECTION_STANDARD)
endif()

mark_as_advanced(
  PCSC_FIDO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO
  PCSC_FIDO_HAVE_C_ZERO_CALL_USED_REGS_GPR
  PCSC_FIDO_HAVE_C_STRICT_FLEX_ARRAYS_3
  PCSC_FIDO_HAVE_C_EXCEPTIONS
  PCSC_FIDO_HAVE_C_FHARDENED
  PCSC_FIDO_HAVE_C_ZERO_INIT_PADDING_BITS_ALL
  PCSC_FIDO_HAVE_C_WBIDI_CHARS_ANY
  PCSC_FIDO_HAVE_C_WIMPLICIT_FALLTHROUGH
  PCSC_FIDO_HAVE_ARM_BRANCH_PROTECTION_STANDARD)
