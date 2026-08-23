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
# Sync via policy.overrides.openssf-hardening (fail-on-change rewrite).
#
include(${CMAKE_CURRENT_LIST_DIR}/CompilerHardeningProbes.cmake)
include(CMakeParseArguments)
function(define_hardening)
  cmake_parse_arguments(HARDENING "" "TARGET;C_STANDARD;CXX_STANDARD" "" ${ARGN})
  if(NOT HARDENING_TARGET)
    message(FATAL_ERROR "define_hardening requires TARGET")
  endif()
  if(TARGET "${HARDENING_TARGET}")
    return()
  endif()
  add_library("${HARDENING_TARGET}" INTERFACE)
  set(_hardening_host $<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>)
  set(_hardening_fortify_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>)
  set(_hardening_production_cfg $<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>)
  set(_hardening_relwithdebinfo_cfg $<CONFIG:RelWithDebInfo>)
  set(_hardening_debug_cfg $<CONFIG:Debug>)
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<BOOL:${HAVE_C_FHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:-fhardened>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<BOOL:${HAVE_C_WHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:-Whardened>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-D_FORTIFY_SOURCE=3>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-U_FORTIFY_SOURCE>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:${_hardening_host},$<OR:$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>,$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},AMD64>>>:-fcf-protection=full>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_ARM_BRANCH_PROTECTION_STANDARD}>:-mbranch-protection=standard>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_STACK_CLASH_PROTECTION}>:-fstack-clash-protection>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_STRICT_FLEX_ARRAYS_3}>:-fstrict-flex-arrays=3>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO}>:-ftrivial-auto-var-init=zero>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WBIDI_CHARS_ANY}>:-Wbidi-chars=any>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_IMPLICIT}>:-Werror=implicit>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES}>:-Werror=incompatible-pointer-types>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INT_CONVERSION}>:-Werror=int-conversion>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_ZERO_INIT_PADDING_BITS_ALL}>:-fzero-init-padding-bits=all>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_ZERO_INIT_PADDING_BITS_UNION}>:-fzero-init-padding-bits=union>>
    $<$<COMPILE_LANGUAGE:C>:$<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:-O2>>
    $<$<COMPILE_LANGUAGE:C>:$<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:-fexceptions>>
    $<$<COMPILE_LANGUAGE:C>:$<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-fPIC>>
    $<$<COMPILE_LANGUAGE:C>:$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fPIE>>
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wconversion>
    $<$<COMPILE_LANGUAGE:C>:-Werror>
    $<$<COMPILE_LANGUAGE:C>:-Werror=format-security>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Wformat>
    $<$<COMPILE_LANGUAGE:C>:-Wformat=2>
    $<$<COMPILE_LANGUAGE:C>:-Wimplicit-fallthrough>
    $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
    $<$<COMPILE_LANGUAGE:C>:-fno-delete-null-pointer-checks>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-overflow>
    $<$<COMPILE_LANGUAGE:C>:-fstack-protector-strong>
  )
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<BOOL:${HAVE_CXX_FHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:-fhardened>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<BOOL:${HAVE_CXX_WHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:-Whardened>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-D_FORTIFY_SOURCE=3>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-U_FORTIFY_SOURCE>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:${_hardening_host},$<OR:$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>,$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},AMD64>>>:-fcf-protection=full>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_ARM_BRANCH_PROTECTION_STANDARD}>:-mbranch-protection=standard>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_STACK_CLASH_PROTECTION}>:-fstack-clash-protection>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_STRICT_FLEX_ARRAYS_3}>:-fstrict-flex-arrays=3>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO}>:-ftrivial-auto-var-init=zero>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WBIDI_CHARS_ANY}>:-Wbidi-chars=any>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL}>:-fzero-init-padding-bits=all>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION}>:-fzero-init-padding-bits=union>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:-O2>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-fPIC>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fPIE>>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall>
    $<$<COMPILE_LANGUAGE:CXX>:-Wconversion>
    $<$<COMPILE_LANGUAGE:CXX>:-Werror>
    $<$<COMPILE_LANGUAGE:CXX>:-Werror=format-security>
    $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Wformat>
    $<$<COMPILE_LANGUAGE:CXX>:-Wformat=2>
    $<$<COMPILE_LANGUAGE:CXX>:-Wimplicit-fallthrough>
    $<$<COMPILE_LANGUAGE:CXX>:-Wsign-conversion>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-delete-null-pointer-checks>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-overflow>
    $<$<COMPILE_LANGUAGE:CXX>:-fstack-protector-strong>
  )
  target_link_options("${HARDENING_TARGET}" INTERFACE
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>>:-pie>
    $<$<BOOL:${HAVE_LINK_AS_NEEDED}>:LINKER:--as-needed>
    $<$<BOOL:${HAVE_LINK_NO_COPY_DT_NEEDED}>:LINKER:--no-copy-dt-needed-entries>
    $<$<BOOL:${HAVE_LINK_Z_NODLOPEN}>:LINKER:-z,nodlopen>
    $<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:LINKER:-z,noexecstack>
    $<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:LINKER:-z,now>
    $<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:LINKER:-z,relro>
    $<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-shared>
  )
  target_compile_definitions("${HARDENING_TARGET}" INTERFACE
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_debug_cfg}>:_GLIBCXX_DEBUG>
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_debug_cfg}>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG>
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_production_cfg},$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:_GLIBCXX_ASSERTIONS>
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_production_cfg},$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>
    $<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_relwithdebinfo_cfg},$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE>
  )
endfunction()
