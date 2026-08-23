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
#
# Generated from config/openssf-hardening-manifest.yaml -- do not hand-edit.
# Copy from .github/lint-c-cpp/cmake/; relax via policy.overrides.openssf-hardening.
#
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)

set(HAVE_INSTRUMENTED_SANITIZER 0)
foreach(_sanitizer_var IN ITEMS
    CMAKE_C_FLAGS
    CMAKE_CXX_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS_RELWITHDEBINFO)
  if(${_sanitizer_var} MATCHES "-fsanitize")
    set(HAVE_INSTRUMENTED_SANITIZER 1)
  endif()
endforeach()
# Also detect sanitizers enabled via add_compile_options/add_link_options
# (directory-scoped) when this module is included after that setup, so the
# fortify / -fhardened gating below is not silently defeated.
if(NOT HAVE_INSTRUMENTED_SANITIZER)
  get_directory_property(_hardening_dir_compile_options COMPILE_OPTIONS)
  get_directory_property(_hardening_dir_link_options LINK_OPTIONS)
  if("${_hardening_dir_compile_options};${_hardening_dir_link_options}" MATCHES "-fsanitize")
    set(HAVE_INSTRUMENTED_SANITIZER 1)
  endif()
endif()

if(CMAKE_C_COMPILER)
  check_c_compiler_flag(-Wbidi-chars=any HAVE_C_WBIDI_CHARS_ANY)
  check_c_compiler_flag(-Wtrampolines HAVE_C_WTRAMPOLINES)
  check_c_compiler_flag(-Werror=trampolines HAVE_C_WERROR_TRAMPOLINES)
  check_c_compiler_flag(-fstack-clash-protection HAVE_C_STACK_CLASH_PROTECTION)
  check_c_compiler_flag(-fstrict-flex-arrays=3 HAVE_C_STRICT_FLEX_ARRAYS_3)
  check_c_compiler_flag(-ftrivial-auto-var-init=zero HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO)
  check_c_compiler_flag(-Werror=implicit HAVE_C_WERROR_IMPLICIT)
  check_c_compiler_flag(-Werror=incompatible-pointer-types HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES)
  check_c_compiler_flag(-Werror=int-conversion HAVE_C_WERROR_INT_CONVERSION)
  set(_lint_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-O2")
  check_c_compiler_flag(-fzero-init-padding-bits=all HAVE_C_ZERO_INIT_PADDING_BITS_ALL)
  check_c_compiler_flag(-fzero-init-padding-bits=union HAVE_C_ZERO_INIT_PADDING_BITS_UNION)
  check_c_compiler_flag(-fhardened HAVE_C_FHARDENED)
  check_c_compiler_flag(-Whardened HAVE_C_WHARDENED)
  set(CMAKE_REQUIRED_FLAGS "${_lint_probe_save_flags}")
else()
  set(HAVE_C_WBIDI_CHARS_ANY 0)
  set(HAVE_C_WTRAMPOLINES 0)
  set(HAVE_C_WERROR_TRAMPOLINES 0)
  set(HAVE_C_STACK_CLASH_PROTECTION 0)
  set(HAVE_C_STRICT_FLEX_ARRAYS_3 0)
  set(HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO 0)
  set(HAVE_C_ZERO_INIT_PADDING_BITS_ALL 0)
  set(HAVE_C_ZERO_INIT_PADDING_BITS_UNION 0)
  set(HAVE_C_FHARDENED 0)
  set(HAVE_C_WHARDENED 0)
  set(HAVE_C_WERROR_IMPLICIT 0)
  set(HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES 0)
  set(HAVE_C_WERROR_INT_CONVERSION 0)
endif()

if(CMAKE_CXX_COMPILER)
  check_cxx_compiler_flag(-Wbidi-chars=any HAVE_CXX_WBIDI_CHARS_ANY)
  check_cxx_compiler_flag(-Wtrampolines HAVE_CXX_WTRAMPOLINES)
  check_cxx_compiler_flag(-Werror=trampolines HAVE_CXX_WERROR_TRAMPOLINES)
  check_cxx_compiler_flag(-fstack-clash-protection HAVE_CXX_STACK_CLASH_PROTECTION)
  check_cxx_compiler_flag(-fstrict-flex-arrays=3 HAVE_CXX_STRICT_FLEX_ARRAYS_3)
  check_cxx_compiler_flag(-ftrivial-auto-var-init=zero HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO)
  set(_lint_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-O2")
  check_cxx_compiler_flag(-fzero-init-padding-bits=all HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL)
  check_cxx_compiler_flag(-fzero-init-padding-bits=union HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION)
  check_cxx_compiler_flag(-fhardened HAVE_CXX_FHARDENED)
  check_cxx_compiler_flag(-Whardened HAVE_CXX_WHARDENED)
  set(CMAKE_REQUIRED_FLAGS "${_lint_probe_save_flags}")
else()
  set(HAVE_CXX_WBIDI_CHARS_ANY 0)
  set(HAVE_CXX_WTRAMPOLINES 0)
  set(HAVE_CXX_WERROR_TRAMPOLINES 0)
  set(HAVE_CXX_STACK_CLASH_PROTECTION 0)
  set(HAVE_CXX_STRICT_FLEX_ARRAYS_3 0)
  set(HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO 0)
  set(HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL 0)
  set(HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION 0)
  set(HAVE_CXX_FHARDENED 0)
  set(HAVE_CXX_WHARDENED 0)
endif()

set(HAVE_ARM_BRANCH_PROTECTION_STANDARD 0)
if(UNIX
   AND NOT APPLE
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AArch64|arm64|ARM64)$")
  if(CMAKE_C_COMPILER)
    check_c_compiler_flag(-mbranch-protection=standard HAVE_ARM_BRANCH_PROTECTION_STANDARD)
  elseif(CMAKE_CXX_COMPILER)
    check_cxx_compiler_flag(-mbranch-protection=standard HAVE_ARM_BRANCH_PROTECTION_STANDARD)
  endif()
endif()

if(UNIX AND NOT APPLE)
  check_linker_flag(C "LINKER:--as-needed" HAVE_LINK_AS_NEEDED)
  check_linker_flag(C "LINKER:--no-copy-dt-needed-entries" HAVE_LINK_NO_COPY_DT_NEEDED)
  check_linker_flag(C "LINKER:-z,nodlopen" HAVE_LINK_Z_NODLOPEN)
else()
  set(HAVE_LINK_AS_NEEDED 0)
  set(HAVE_LINK_NO_COPY_DT_NEEDED 0)
  set(HAVE_LINK_Z_NODLOPEN 0)
endif()

mark_as_advanced(
  HAVE_ARM_BRANCH_PROTECTION_STANDARD
  HAVE_CXX_FHARDENED
  HAVE_CXX_STACK_CLASH_PROTECTION
  HAVE_CXX_STRICT_FLEX_ARRAYS_3
  HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO
  HAVE_CXX_WBIDI_CHARS_ANY
  HAVE_CXX_WERROR_TRAMPOLINES
  HAVE_CXX_WHARDENED
  HAVE_CXX_WTRAMPOLINES
  HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL
  HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION
  HAVE_C_FHARDENED
  HAVE_C_STACK_CLASH_PROTECTION
  HAVE_C_STRICT_FLEX_ARRAYS_3
  HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO
  HAVE_C_WBIDI_CHARS_ANY
  HAVE_C_WERROR_IMPLICIT
  HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES
  HAVE_C_WERROR_INT_CONVERSION
  HAVE_C_WERROR_TRAMPOLINES
  HAVE_C_WHARDENED
  HAVE_C_WTRAMPOLINES
  HAVE_C_ZERO_INIT_PADDING_BITS_ALL
  HAVE_C_ZERO_INIT_PADDING_BITS_UNION
  HAVE_LINK_AS_NEEDED
  HAVE_LINK_NO_COPY_DT_NEEDED
  HAVE_LINK_Z_NODLOPEN
  HAVE_INSTRUMENTED_SANITIZER)
