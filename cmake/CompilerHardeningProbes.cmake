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
  check_c_compiler_flag(-fzero-call-used-regs=used-gpr HAVE_C_ZERO_CALL_USED_REGS)
  check_c_compiler_flag(-ffunction-sections HAVE_C_FUNCTION_SECTIONS)
  check_c_compiler_flag(-fdata-sections HAVE_C_DATA_SECTIONS)
  check_c_compiler_flag(-Werror=vla HAVE_C_WERROR_VLA)
  check_c_compiler_flag(-Walloca HAVE_C_WALLOCA)
  check_c_compiler_flag(-Wshadow HAVE_C_WSHADOW)
  check_c_compiler_flag(-Wundef HAVE_C_WUNDEF)
  check_c_compiler_flag(-Wformat-signedness HAVE_C_WFORMAT_SIGNEDNESS)
  check_c_compiler_flag(-Wtrampolines HAVE_C_WTRAMPOLINES)
  check_c_compiler_flag(-Werror=trampolines HAVE_C_WERROR_TRAMPOLINES)
  check_c_compiler_flag(-fstack-clash-protection HAVE_C_STACK_CLASH_PROTECTION)
  check_c_compiler_flag(-fstrict-flex-arrays=3 HAVE_C_STRICT_FLEX_ARRAYS_3)
  check_c_compiler_flag(-ftrivial-auto-var-init=zero HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO)
  check_c_compiler_flag(-Werror=implicit HAVE_C_WERROR_IMPLICIT)
  check_c_compiler_flag(-Werror=incompatible-pointer-types HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES)
  check_c_compiler_flag(-Werror=int-conversion HAVE_C_WERROR_INT_CONVERSION)
  check_c_compiler_flag(-Wstrict-prototypes HAVE_C_WSTRICT_PROTOTYPES)
  check_c_compiler_flag(-Wold-style-definition HAVE_C_WOLD_STYLE_DEFINITION)
  set(_lint_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-O2")
  check_c_compiler_flag(-fzero-init-padding-bits=all HAVE_C_ZERO_INIT_PADDING_BITS_ALL)
  check_c_compiler_flag(-fzero-init-padding-bits=unions HAVE_C_ZERO_INIT_PADDING_BITS_UNION)
  check_c_compiler_flag(-fhardened HAVE_C_FHARDENED)
  check_c_compiler_flag(-Whardened HAVE_C_WHARDENED)
  set(CMAKE_REQUIRED_FLAGS "${_lint_probe_save_flags}")
else()
  set(HAVE_C_WBIDI_CHARS_ANY 0)
  set(HAVE_C_ZERO_CALL_USED_REGS 0)
  set(HAVE_C_FUNCTION_SECTIONS 0)
  set(HAVE_C_DATA_SECTIONS 0)
  set(HAVE_C_WERROR_VLA 0)
  set(HAVE_C_WALLOCA 0)
  set(HAVE_C_WSHADOW 0)
  set(HAVE_C_WUNDEF 0)
  set(HAVE_C_WFORMAT_SIGNEDNESS 0)
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
  set(HAVE_C_WSTRICT_PROTOTYPES 0)
  set(HAVE_C_WOLD_STYLE_DEFINITION 0)
endif()

if(CMAKE_CXX_COMPILER)
  check_cxx_compiler_flag(-Wbidi-chars=any HAVE_CXX_WBIDI_CHARS_ANY)
  check_cxx_compiler_flag(-fzero-call-used-regs=used-gpr HAVE_CXX_ZERO_CALL_USED_REGS)
  check_cxx_compiler_flag(-ffunction-sections HAVE_CXX_FUNCTION_SECTIONS)
  check_cxx_compiler_flag(-fdata-sections HAVE_CXX_DATA_SECTIONS)
  check_cxx_compiler_flag(-Werror=vla HAVE_CXX_WERROR_VLA)
  check_cxx_compiler_flag(-Walloca HAVE_CXX_WALLOCA)
  check_cxx_compiler_flag(-Wshadow HAVE_CXX_WSHADOW)
  check_cxx_compiler_flag(-Wundef HAVE_CXX_WUNDEF)
  check_cxx_compiler_flag(-Wformat-signedness HAVE_CXX_WFORMAT_SIGNEDNESS)
  check_cxx_compiler_flag(-Wtrampolines HAVE_CXX_WTRAMPOLINES)
  check_cxx_compiler_flag(-Werror=trampolines HAVE_CXX_WERROR_TRAMPOLINES)
  check_cxx_compiler_flag(-fstack-clash-protection HAVE_CXX_STACK_CLASH_PROTECTION)
  check_cxx_compiler_flag(-fstrict-flex-arrays=3 HAVE_CXX_STRICT_FLEX_ARRAYS_3)
  check_cxx_compiler_flag(-ftrivial-auto-var-init=zero HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO)
  set(_lint_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-O2")
  check_cxx_compiler_flag(-fzero-init-padding-bits=all HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL)
  check_cxx_compiler_flag(-fzero-init-padding-bits=unions HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION)
  check_cxx_compiler_flag(-fhardened HAVE_CXX_FHARDENED)
  check_cxx_compiler_flag(-Whardened HAVE_CXX_WHARDENED)
  set(CMAKE_REQUIRED_FLAGS "${_lint_probe_save_flags}")
else()
  set(HAVE_CXX_WBIDI_CHARS_ANY 0)
  set(HAVE_CXX_ZERO_CALL_USED_REGS 0)
  set(HAVE_CXX_FUNCTION_SECTIONS 0)
  set(HAVE_CXX_DATA_SECTIONS 0)
  set(HAVE_CXX_WERROR_VLA 0)
  set(HAVE_CXX_WALLOCA 0)
  set(HAVE_CXX_WSHADOW 0)
  set(HAVE_CXX_WUNDEF 0)
  set(HAVE_CXX_WFORMAT_SIGNEDNESS 0)
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

# Link probes run through whichever language is enabled (C-only, C++-only, both).
if(CMAKE_C_COMPILER)
  set(_hardening_link_lang C)
elseif(CMAKE_CXX_COMPILER)
  set(_hardening_link_lang CXX)
else()
  set(_hardening_link_lang "")
endif()
include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
# GNU ld accepts unknown -z keywords with only a warning ('-z <keyword> ignored',
# e.g. -z pack-relative-relocs on a target whose ld lacks DT_RELR support), and
# check_linker_flag builds its 'ignored' FAIL_REGEX from the literal
# 'LINKER:-z,<keyword>' token, which never matches that diagnostic. Re-link each
# supported -z probe with the bare ld spelling in FAIL_REGEX and demote on a hit so
# the generated genex does not emit a flag the target linker silently drops.
# Link probes (check_linker_flag and this guard) only reach ld when try-compiles
# build executables: with CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY (common in
# cross toolchain files) they pass without linking, so probe as EXECUTABLE around
# include(Hardening.cmake).
include(CMakePushCheckState)
function(_hardening_linker_z_flag_not_ignored flag var)
  if(NOT ${var} OR NOT _hardening_link_lang)
    return()
  endif()
  string(REGEX REPLACE "^LINKER:" "" _hardening_z_bare "${flag}")
  string(REPLACE "," " " _hardening_z_bare "${_hardening_z_bare}")
  string(REGEX REPLACE "^-z " "" _hardening_z_keyword "${_hardening_z_bare}")
  string(REGEX REPLACE "([][+.*?()^$|\\])" "\\\\\\1" _hardening_z_bare_re "${_hardening_z_bare}")
  string(REGEX REPLACE "([][+.*?()^$|\\])" "\\\\\\1" _hardening_z_keyword_re "${_hardening_z_keyword}")
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LINK_OPTIONS "${flag}")
  # GNU ld: "warning: -z X ignored"; lld: "warning: unknown -z value: X".
  set(_hardening_z_fail_regex "warning: [^\n]*${_hardening_z_bare_re}[^\n]* ignored"
      "warning: unknown -z value: ${_hardening_z_keyword_re}")
  if(_hardening_link_lang STREQUAL "C")
    check_c_source_compiles("int main(void) { return 0; }" ${var}_NOT_IGNORED
      FAIL_REGEX ${_hardening_z_fail_regex})
  else()
    check_cxx_source_compiles("int main(void) { return 0; }" ${var}_NOT_IGNORED
      FAIL_REGEX ${_hardening_z_fail_regex})
  endif()
  cmake_pop_check_state()
  if(NOT ${var}_NOT_IGNORED)
    message(STATUS "Performing Test ${var} - Failed (linker ignores ${_hardening_z_bare})")
    set(${var} 0 CACHE INTERNAL "Test ${var}" FORCE)
  endif()
endfunction()

if(UNIX AND NOT APPLE AND _hardening_link_lang)
  check_linker_flag(${_hardening_link_lang} "LINKER:--as-needed" HAVE_LINK_AS_NEEDED)
  check_linker_flag(${_hardening_link_lang} "LINKER:--no-copy-dt-needed-entries" HAVE_LINK_NO_COPY_DT_NEEDED)
  check_linker_flag(${_hardening_link_lang} "LINKER:-z,nodlopen" HAVE_LINK_Z_NODLOPEN)
  check_linker_flag(${_hardening_link_lang} "LINKER:--gc-sections" HAVE_LINK_GC_SECTIONS)
  check_linker_flag(${_hardening_link_lang} "LINKER:-z,pack-relative-relocs" HAVE_LINK_Z_PACK_RELATIVE_RELOCS)
  check_linker_flag(${_hardening_link_lang} "LINKER:-z,text" HAVE_LINK_Z_TEXT)
  check_linker_flag(${_hardening_link_lang} "LINKER:--error-execstack" HAVE_LINK_ERROR_EXECSTACK)
  check_linker_flag(${_hardening_link_lang} "LINKER:--error-rwx-segments" HAVE_LINK_ERROR_RWX_SEGMENTS)
  _hardening_linker_z_flag_not_ignored("LINKER:-z,nodlopen" HAVE_LINK_Z_NODLOPEN)
  _hardening_linker_z_flag_not_ignored("LINKER:-z,pack-relative-relocs" HAVE_LINK_Z_PACK_RELATIVE_RELOCS)
  _hardening_linker_z_flag_not_ignored("LINKER:-z,text" HAVE_LINK_Z_TEXT)
else()
  set(HAVE_LINK_AS_NEEDED 0)
  set(HAVE_LINK_NO_COPY_DT_NEEDED 0)
  set(HAVE_LINK_Z_NODLOPEN 0)
  set(HAVE_LINK_GC_SECTIONS 0)
  set(HAVE_LINK_Z_PACK_RELATIVE_RELOCS 0)
  set(HAVE_LINK_Z_TEXT 0)
  set(HAVE_LINK_ERROR_EXECSTACK 0)
  set(HAVE_LINK_ERROR_RWX_SEGMENTS 0)
endif()

# Sysroot libc capability probes. The decision is made by the preprocessor
# against the active toolchain's libc headers (features.h), so they are valid
# for cross builds too; nothing is run. GNU ld emits the
# GLIBC_ABI_DT_RELR verneed for -z pack-relative-relocs even when libc.so
# predates glibc 2.36, so the linker probe alone would pass and the loader
# would then reject the binary; this probe closes that gap.
set(_hardening_libc_probe_source [=[
#include <features.h>
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if !__GLIBC_PREREQ(2, 36)
#error DT_RELR needs glibc >= 2.36 (GLIBC_ABI_DT_RELR)
#endif
#else
#error DT_RELR loader support is only probed for glibc
#endif
int main(void) { return 0; }
]=])
if(UNIX AND NOT APPLE AND CMAKE_C_COMPILER)
  check_c_source_compiles("${_hardening_libc_probe_source}" HAVE_LIBC_DT_RELR)
elseif(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER)
  check_cxx_source_compiles("${_hardening_libc_probe_source}" HAVE_LIBC_DT_RELR)
else()
  set(HAVE_LIBC_DT_RELR 0)
endif()
unset(_hardening_libc_probe_source)

mark_as_advanced(
  HAVE_ARM_BRANCH_PROTECTION_STANDARD
  HAVE_CXX_DATA_SECTIONS
  HAVE_CXX_FHARDENED
  HAVE_CXX_FUNCTION_SECTIONS
  HAVE_CXX_STACK_CLASH_PROTECTION
  HAVE_CXX_STRICT_FLEX_ARRAYS_3
  HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO
  HAVE_CXX_WALLOCA
  HAVE_CXX_WBIDI_CHARS_ANY
  HAVE_CXX_WERROR_TRAMPOLINES
  HAVE_CXX_WERROR_VLA
  HAVE_CXX_WFORMAT_SIGNEDNESS
  HAVE_CXX_WHARDENED
  HAVE_CXX_WSHADOW
  HAVE_CXX_WTRAMPOLINES
  HAVE_CXX_WUNDEF
  HAVE_CXX_ZERO_CALL_USED_REGS
  HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL
  HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION
  HAVE_C_DATA_SECTIONS
  HAVE_C_FHARDENED
  HAVE_C_FUNCTION_SECTIONS
  HAVE_C_STACK_CLASH_PROTECTION
  HAVE_C_STRICT_FLEX_ARRAYS_3
  HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO
  HAVE_C_WALLOCA
  HAVE_C_WBIDI_CHARS_ANY
  HAVE_C_WERROR_IMPLICIT
  HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES
  HAVE_C_WERROR_INT_CONVERSION
  HAVE_C_WERROR_TRAMPOLINES
  HAVE_C_WERROR_VLA
  HAVE_C_WFORMAT_SIGNEDNESS
  HAVE_C_WHARDENED
  HAVE_C_WOLD_STYLE_DEFINITION
  HAVE_C_WSHADOW
  HAVE_C_WSTRICT_PROTOTYPES
  HAVE_C_WTRAMPOLINES
  HAVE_C_WUNDEF
  HAVE_C_ZERO_CALL_USED_REGS
  HAVE_C_ZERO_INIT_PADDING_BITS_ALL
  HAVE_C_ZERO_INIT_PADDING_BITS_UNION
  HAVE_LINK_AS_NEEDED
  HAVE_LINK_ERROR_EXECSTACK
  HAVE_LINK_ERROR_RWX_SEGMENTS
  HAVE_LINK_GC_SECTIONS
  HAVE_LINK_NO_COPY_DT_NEEDED
  HAVE_LINK_Z_NODLOPEN
  HAVE_LINK_Z_PACK_RELATIVE_RELOCS
  HAVE_LINK_Z_TEXT
  HAVE_LIBC_DT_RELR
  HAVE_INSTRUMENTED_SANITIZER)
