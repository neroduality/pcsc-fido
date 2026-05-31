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

# Require a toolchain that can compile ISO C23 sources (nullptr, etc.).

include(CheckCSourceCompiles)

if(CMAKE_C_COMPILER_ID MATCHES "GNU")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS "13.0")
    message(FATAL_ERROR
      "pcsc-fido requires GCC 13 or newer for ISO C23 (found ${CMAKE_C_COMPILER_VERSION})")
  endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS "16.0")
    message(FATAL_ERROR
      "pcsc-fido requires Clang 16 or newer for ISO C23 (found ${CMAKE_C_COMPILER_VERSION})")
  endif()
else()
  message(WARNING "pcsc-fido: untested compiler ${CMAKE_C_COMPILER_ID}; C23 support not verified")
endif()

set(_pcsc_fido_c23_std_candidates c23 c2x gnu2x)
set(_pcsc_fido_c23_probe_source
  "#include <stddef.h>\nint main(void){ void *p = nullptr; (void)p; return 0; }\n")

set(PCSC_FIDO_C23_NULLPTR_OK FALSE)
foreach(_std IN LISTS _pcsc_fido_c23_std_candidates)
  set(CMAKE_REQUIRED_FLAGS "-std=${_std}")
  set(_probe_var "PCSC_FIDO_C23_NULLPTR_${_std}")
  check_c_source_compiles("${_pcsc_fido_c23_probe_source}" "${_probe_var}")
  if(${_probe_var})
    set(PCSC_FIDO_C23_NULLPTR_OK TRUE)
    break()
  endif()
endforeach()
unset(CMAKE_REQUIRED_FLAGS)

if(NOT PCSC_FIDO_C23_NULLPTR_OK)
  message(FATAL_ERROR
    "Compiler does not accept ISO C23 nullptr (tried -std=c23, -std=c2x, -std=gnu2x)")
endif()

set(_pcsc_fido_ckd_probe_source
  "#include <stdckdint.h>\n#include <stddef.h>\nint main(void){ size_t r; return ckd_add(&r,(size_t)1,(size_t)2)?1:0; }\n")
set(PCSC_FIDO_HAVE_STDCKDINT FALSE)
foreach(_std IN LISTS _pcsc_fido_c23_std_candidates)
  set(CMAKE_REQUIRED_FLAGS "-std=${_std}")
  set(_probe_var "PCSC_FIDO_HAVE_STDCKDINT_${_std}")
  check_c_source_compiles("${_pcsc_fido_ckd_probe_source}" "${_probe_var}")
  if(${_probe_var})
    set(PCSC_FIDO_HAVE_STDCKDINT TRUE)
    break()
  endif()
endforeach()
unset(CMAKE_REQUIRED_FLAGS)

set(_pcsc_fido_memset_probe_source
  "#include <string.h>\nint main(void){ char b[4]; memset_explicit(b,0,sizeof b); return 0; }\n")
set(PCSC_FIDO_HAVE_MEMSET_EXPLICIT FALSE)
foreach(_std IN LISTS _pcsc_fido_c23_std_candidates)
  set(CMAKE_REQUIRED_FLAGS "-std=${_std}")
  set(_probe_var "PCSC_FIDO_HAVE_MEMSET_EXPLICIT_${_std}")
  check_c_source_compiles("${_pcsc_fido_memset_probe_source}" "${_probe_var}")
  if(${_probe_var})
    set(PCSC_FIDO_HAVE_MEMSET_EXPLICIT TRUE)
    break()
  endif()
endforeach()
unset(CMAKE_REQUIRED_FLAGS)

if(PCSC_FIDO_HAVE_STDCKDINT)
  message(STATUS "pcsc-fido: ISO C23 stdckdint.h available")
else()
  message(STATUS "pcsc-fido: stdckdint.h unavailable; using overflow fallbacks")
endif()

# counted_by on struct pointer fields (see pcsc_fido_apdu_t in apdu.h). GCC 15 accepts
# [[counted_by]] in C23 but ignores it on pointers; probe the spelling we actually emit.
set(_pcsc_fido_counted_by_probe_source
  "#include <stddef.h>\nstruct _pcsc_fido_counted_by_probe {\n  unsigned char hid_cmd;\n  const unsigned char *payload ATTR;\n  size_t payload_len;\n};\nint main(void){return 0;}\n")
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(_pcsc_fido_counted_by_attr "[[clang::counted_by(payload_len)]]")
  set(_pcsc_fido_counted_by_werror "-Werror=ignored-attributes -Werror=unknown-attributes")
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
  set(_pcsc_fido_counted_by_attr "__attribute__((counted_by(payload_len)))")
  set(_pcsc_fido_counted_by_werror "-Werror=attributes")
else()
  set(_pcsc_fido_counted_by_attr "[[counted_by(payload_len)]]")
  set(_pcsc_fido_counted_by_werror "")
endif()
string(REPLACE "ATTR" "${_pcsc_fido_counted_by_attr}" _pcsc_fido_counted_by_probe_source
  "${_pcsc_fido_counted_by_probe_source}")

set(PCSC_FIDO_HAVE_COUNTED_BY FALSE)
foreach(_std IN LISTS _pcsc_fido_c23_std_candidates)
  set(CMAKE_REQUIRED_FLAGS "-std=${_std} ${_pcsc_fido_counted_by_werror}")
  set(_probe_var "PCSC_FIDO_HAVE_COUNTED_BY_${_std}")
  check_c_source_compiles("${_pcsc_fido_counted_by_probe_source}" "${_probe_var}")
  if(${_probe_var})
    set(PCSC_FIDO_HAVE_COUNTED_BY TRUE)
    break()
  endif()
endforeach()
unset(CMAKE_REQUIRED_FLAGS)

if(PCSC_FIDO_HAVE_COUNTED_BY)
  message(STATUS "pcsc-fido: counted_by available for struct pointer fields")
else()
  message(STATUS "pcsc-fido: counted_by unavailable for struct pointer fields")
endif()

if(PCSC_FIDO_HAVE_MEMSET_EXPLICIT)
  add_compile_definitions(PCSC_FIDO_HAVE_MEMSET_EXPLICIT=1)
endif()
if(PCSC_FIDO_HAVE_COUNTED_BY)
  add_compile_definitions(PCSC_FIDO_HAVE_COUNTED_BY=1)
endif()
