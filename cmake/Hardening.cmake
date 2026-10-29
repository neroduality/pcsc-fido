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
# Generated from kit openssf-hardening-manifest + global policy.overrides.openssf-hardening -- do not hand-edit.
#
include(${CMAKE_CURRENT_LIST_DIR}/CompilerHardeningProbes.cmake)
include(CMakeParseArguments)
# Blanket -Werror is for development builds. Source packages set
# -DHARDENING_WERROR=OFF so a newer compiler's new warnings do not
# fail a rebuild (OpenSSF: do not ship blanket -Werror).
if(NOT DEFINED HARDENING_WERROR)
  set(HARDENING_WERROR ON)
endif()
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
  set(_hardening_speed_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>)
  set(_hardening_production_cfg $<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>)
  set(_hardening_relwithdebinfo_cfg $<CONFIG:RelWithDebInfo>)
  set(_hardening_debug_cfg $<CONFIG:Debug>)
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-U_FORTIFY_SOURCE>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<BOOL:${HAVE_C_FHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,${_hardening_fortify_cfg}>:-fhardened>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<BOOL:${HAVE_C_WHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,${_hardening_fortify_cfg}>:-Whardened>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<BOOL:${HAVE_C_ZERO_INIT_PADDING_BITS_UNION}>,$<NOT:$<BOOL:${HAVE_C_ZERO_INIT_PADDING_BITS_ALL}>>>:-fzero-init-padding-bits=unions>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>>:-D_FORTIFY_SOURCE=3>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_speed_cfg}>:-O2>>
    $<$<COMPILE_LANGUAGE:C>:$<$<AND:${_hardening_host},$<OR:$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>,$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},AMD64>>>:-fcf-protection=full>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HARDENING_WERROR}>:-Werror>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_ARM_BRANCH_PROTECTION_STANDARD}>:-mbranch-protection=standard>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_DATA_SECTIONS}>:-fdata-sections>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_FUNCTION_SECTIONS}>:-ffunction-sections>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_STACK_CLASH_PROTECTION}>:-fstack-clash-protection>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_STRICT_FLEX_ARRAYS_3}>:-fstrict-flex-arrays=3>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO}>:-ftrivial-auto-var-init=zero>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WALLOCA}>:-Walloca>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WBIDI_CHARS_ANY}>:-Wbidi-chars=any>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_IMPLICIT}>:-Werror=implicit>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES}>:-Werror=incompatible-pointer-types>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INT_CONVERSION}>:-Werror=int-conversion>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_VLA}>:-Werror=vla>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WFORMAT_SIGNEDNESS}>:-Wformat-signedness>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WOLD_STYLE_DEFINITION}>:-Wold-style-definition>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WSHADOW}>:-Wshadow>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WSTRICT_PROTOTYPES}>:-Wstrict-prototypes>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WUNDEF}>:-Wundef>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_ZERO_CALL_USED_REGS}>:-fzero-call-used-regs=used-gpr>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_ZERO_INIT_PADDING_BITS_ALL}>:-fzero-init-padding-bits=all>>
    $<$<COMPILE_LANGUAGE:C>:$<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-fPIC>>
    $<$<COMPILE_LANGUAGE:C>:$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fPIE>>
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wconversion>
    $<$<COMPILE_LANGUAGE:C>:-Werror=format-security>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Wformat>
    $<$<COMPILE_LANGUAGE:C>:-Wformat=2>
    $<$<COMPILE_LANGUAGE:C>:-Wimplicit-fallthrough>
    $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
    $<$<COMPILE_LANGUAGE:C>:-fexceptions>
    $<$<COMPILE_LANGUAGE:C>:-fno-delete-null-pointer-checks>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-overflow>
    $<$<COMPILE_LANGUAGE:C>:-fstack-protector-strong>
  )
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_CXX_FHARDENED}>>>:-U_FORTIFY_SOURCE>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<BOOL:${HAVE_CXX_FHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,${_hardening_fortify_cfg}>:-fhardened>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<BOOL:${HAVE_CXX_WHARDENED}>,$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,${_hardening_fortify_cfg}>:-Whardened>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<BOOL:${HAVE_CXX_ZERO_INIT_PADDING_BITS_UNION}>,$<NOT:$<BOOL:${HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL}>>>:-fzero-init-padding-bits=unions>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>,$<NOT:$<BOOL:${HAVE_CXX_FHARDENED}>>>:-D_FORTIFY_SOURCE=3>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_speed_cfg}>:-O2>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:${_hardening_host},$<OR:$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>,$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},AMD64>>>:-fcf-protection=full>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HARDENING_WERROR}>:-Werror>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_ARM_BRANCH_PROTECTION_STANDARD}>:-mbranch-protection=standard>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_DATA_SECTIONS}>:-fdata-sections>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_FUNCTION_SECTIONS}>:-ffunction-sections>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_STACK_CLASH_PROTECTION}>:-fstack-clash-protection>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_STRICT_FLEX_ARRAYS_3}>:-fstrict-flex-arrays=3>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO}>:-ftrivial-auto-var-init=zero>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WALLOCA}>:-Walloca>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WBIDI_CHARS_ANY}>:-Wbidi-chars=any>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WERROR_VLA}>:-Werror=vla>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WFORMAT_SIGNEDNESS}>:-Wformat-signedness>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WSHADOW}>:-Wshadow>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WUNDEF}>:-Wundef>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_ZERO_CALL_USED_REGS}>:-fzero-call-used-regs=used-gpr>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_ZERO_INIT_PADDING_BITS_ALL}>:-fzero-init-padding-bits=all>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-fPIC>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fPIE>>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall>
    $<$<COMPILE_LANGUAGE:CXX>:-Wconversion>
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
    $<$<AND:$<BOOL:${HAVE_LINK_ERROR_EXECSTACK}>>:LINKER:--error-execstack>
    $<$<AND:$<BOOL:${HAVE_LINK_ERROR_RWX_SEGMENTS}>>:LINKER:--error-rwx-segments>
    $<$<AND:$<BOOL:${HAVE_LINK_Z_PACK_RELATIVE_RELOCS}>,$<BOOL:${HAVE_LIBC_DT_RELR}>>:LINKER:-z,pack-relative-relocs>
    $<$<AND:$<BOOL:${HAVE_LINK_Z_TEXT}>>:LINKER:-z,text>
    $<$<BOOL:${HAVE_LINK_AS_NEEDED}>:LINKER:--as-needed>
    $<$<BOOL:${HAVE_LINK_GC_SECTIONS}>:LINKER:--gc-sections>
    $<$<BOOL:${HAVE_LINK_NO_COPY_DT_NEEDED}>:LINKER:--no-copy-dt-needed-entries>
    $<$<BOOL:${HAVE_LINK_Z_NODLOPEN}>:LINKER:-z,nodlopen>
    $<$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-shared>
    $<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-pie>
    "LINKER:-z,noexecstack"
    "LINKER:-z,now"
    "LINKER:-z,relro"
  )
  target_compile_definitions("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_debug_cfg}>:_GLIBCXX_DEBUG>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_debug_cfg}>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_fortify_cfg},$<OR:$<NOT:$<BOOL:${HAVE_CXX_FHARDENED}>>,$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:_GLIBCXX_ASSERTIONS>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_production_cfg},$<OR:$<NOT:$<BOOL:${HAVE_CXX_FHARDENED}>>,$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>,${_hardening_relwithdebinfo_cfg},$<OR:$<NOT:$<BOOL:${HAVE_CXX_FHARDENED}>>,$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE>>
  )
endfunction()
