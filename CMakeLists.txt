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


cmake_minimum_required(VERSION 3.21)
# Release version: bump `project(... VERSION ...)` below before tagging (v* tag
# without the leading v). CMake generates `include/pcsc_fido/version.h` from
# that value; it feeds CPACK, packages, and `pcsc-fido --version`. See RELEASE.md.
project(pcsc_fido VERSION 0.3.0 LANGUAGES C)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/pcsc_fido/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/pcsc_fido/version.h"
  @ONLY
)

include(GNUInstallDirs)
option(BUILD_TESTING "Build unit test executables" OFF)
include(CTest)
if(BUILD_TESTING)
  find_program(VALGRIND_EXECUTABLE valgrind)
  if(VALGRIND_EXECUTABLE)
    set(MEMORYCHECK_COMMAND "${VALGRIND_EXECUTABLE}")
    set(MEMORYCHECK_COMMAND_OPTIONS
        "--error-exitcode=1;--leak-check=full;--track-origins=yes")
  endif()
endif()
find_package(Threads REQUIRED)

# ISO C23 + OpenSSF hardening (org lint kit: cmake/Hardening.cmake, generated).
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# POSIX.1-2008 surface, defined via the build (not reserved-identifier #defines in .c).
add_compile_definitions(_POSIX_C_SOURCE=200809L)

include(CheckIPOSupported)
check_ipo_supported(RESULT _pcsc_fido_ipo_ok OUTPUT _pcsc_fido_ipo_msg)

# Cross toolchains (cmake/toolchains/linux-cross-common.cmake) set
# CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY so ordinary compiler-flag probes never
# need a runnable executable. Link probes are different: the -pie check_linker_flag
# below must prove the target compiler can link a PIE executable, and the kit's probes
# (-z pack-relative-relocs / --as-needed / --gc-sections / ...) never reach ld under
# STATIC_LIBRARY, so they would pass vacuously and a linker that only *ignores* a flag
# (e.g. no DT_RELR support) would go undetected. Both windows therefore probe as
# EXECUTABLE and restore afterwards.
# Restore carefully: assigning an empty string is not the same as unset, and an empty
# CMAKE_TRY_COMPILE_TARGET_TYPE can break later check_c_compiler_flag try_compiles.
macro(pcsc_fido_push_executable_try_compile)
  set(_pcsc_fido_try_compile_target_type_saved "")
  set(_pcsc_fido_try_compile_target_type_was_set FALSE)
  if(DEFINED CMAKE_TRY_COMPILE_TARGET_TYPE)
    set(_pcsc_fido_try_compile_target_type_saved "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
    set(_pcsc_fido_try_compile_target_type_was_set TRUE)
  endif()
  if(CMAKE_CROSSCOMPILING AND CMAKE_TRY_COMPILE_TARGET_TYPE STREQUAL "STATIC_LIBRARY")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  endif()
endmacro()
macro(pcsc_fido_pop_try_compile)
  if(_pcsc_fido_try_compile_target_type_was_set)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_pcsc_fido_try_compile_target_type_saved}")
  else()
    unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
  endif()
  unset(_pcsc_fido_try_compile_target_type_saved)
  unset(_pcsc_fido_try_compile_target_type_was_set)
endmacro()

# PIE is mandatory. The `-pie` link flag itself comes from the kit's generated
# cmake/Hardening.cmake (EXECUTABLE targets), so probe linker support directly
# instead of via check_pie_supported(): that module also makes CMake append its
# own `-pie` for CMAKE_POSITION_INDEPENDENT_CODE targets, duplicating the flag.
pcsc_fido_push_executable_try_compile()
include(CheckLinkerFlag)
check_linker_flag(C "-pie" PCSC_FIDO_LINK_PIE_SUPPORTED)
pcsc_fido_pop_try_compile()
if(NOT PCSC_FIDO_LINK_PIE_SUPPORTED)
  message(FATAL_ERROR "PIE linking is required for pcsc-fido (the C linker rejected -pie)")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyCompiler.cmake")

# The guaranteed-erase tier is a src/mem_util.c implementation detail: keep both
# feature macros (and glibc's _DEFAULT_SOURCE, which declares explicit_bzero) on
# that one TU so no other file can branch on them. The macro set matches the
# VerifyCompiler.cmake probes.
if(PCSC_FIDO_HAVE_MEMSET_EXPLICIT)
  set_source_files_properties(src/mem_util.c PROPERTIES
    COMPILE_DEFINITIONS "PCSC_FIDO_HAVE_MEMSET_EXPLICIT=1")
elseif(PCSC_FIDO_HAVE_EXPLICIT_BZERO)
  set_source_files_properties(src/mem_util.c PROPERTIES
    COMPILE_DEFINITIONS "PCSC_FIDO_HAVE_EXPLICIT_BZERO=1;_DEFAULT_SOURCE=1")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCSC REQUIRED IMPORTED_TARGET libpcsclite)

option(PCSC_FIDO_ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(PCSC_FIDO_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)
option(PCSC_FIDO_ENABLE_TSAN "Build with ThreadSanitizer" OFF)
option(PCSC_FIDO_ENABLE_COVERAGE "Build with gcov/lcov line coverage instrumentation" OFF)
option(PCSC_FIDO_BUILD_FUZZING "Build libFuzzer harnesses (use Clang; see run-local-fuzz.sh)" OFF)
option(PCSC_FIDO_ENABLE_EXTENDED_SANITIZERS
       "With ASan/UBSan enabled, probe extra -fsanitize flags (pointer-*, bounds-strict on GCC)" ON)
option(PCSC_FIDO_STRIP_RELEASE "Strip symbols from Release/MinSizeRel installs and packages" ON)

if(PCSC_FIDO_ENABLE_COVERAGE
   AND (PCSC_FIDO_ENABLE_ASAN OR PCSC_FIDO_ENABLE_UBSAN OR PCSC_FIDO_ENABLE_TSAN))
  message(FATAL_ERROR "Coverage builds cannot mix with sanitizers")
endif()

if(PCSC_FIDO_BUILD_FUZZING
   AND (PCSC_FIDO_ENABLE_ASAN OR PCSC_FIDO_ENABLE_UBSAN OR PCSC_FIDO_ENABLE_TSAN
        OR PCSC_FIDO_ENABLE_COVERAGE))
  message(FATAL_ERROR "Fuzz builds cannot mix with other sanitizer or coverage options")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  option(PCSC_FIDO_DEBUG_SANITIZERS
         "With CMAKE_BUILD_TYPE=Debug, enable ASan+UBSan on host binaries and tests" ON)
  if(PCSC_FIDO_DEBUG_SANITIZERS
     AND NOT PCSC_FIDO_ENABLE_COVERAGE
     AND NOT PCSC_FIDO_ENABLE_ASAN
     AND NOT PCSC_FIDO_ENABLE_UBSAN
     AND NOT PCSC_FIDO_ENABLE_TSAN)
    set(PCSC_FIDO_ENABLE_ASAN ON)
    set(PCSC_FIDO_ENABLE_UBSAN ON)
  endif()
endif()

if(PCSC_FIDO_ENABLE_TSAN AND (PCSC_FIDO_ENABLE_ASAN OR PCSC_FIDO_ENABLE_UBSAN))
  message(FATAL_ERROR "ThreadSanitizer must be built separately from ASan/UBSan")
endif()

set(PCSC_FIDO_SANITIZER_FLAGS "")
if(PCSC_FIDO_ENABLE_ASAN)
  list(APPEND PCSC_FIDO_SANITIZER_FLAGS address)
endif()
if(PCSC_FIDO_ENABLE_UBSAN)
  list(APPEND PCSC_FIDO_SANITIZER_FLAGS undefined)
endif()
if(PCSC_FIDO_ENABLE_TSAN)
  list(APPEND PCSC_FIDO_SANITIZER_FLAGS thread)
endif()

if(PCSC_FIDO_BUILD_FUZZING)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU|AppleClang")
    message(FATAL_ERROR "Fuzz builds require Clang or GCC with libFuzzer support")
  endif()
  include(CMakePushCheckState)
  include(CheckCSourceCompiles)
  set(_pcsc_fido_fuzz_san "fuzzer,address,undefined")
  cmake_push_check_state()
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=${_pcsc_fido_fuzz_san} -fno-omit-frame-pointer")
  set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=${_pcsc_fido_fuzz_san}")
  check_c_source_compiles(
    "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  (void)data;\n  (void)size;\n  return 0;\n}\n"
    PCSC_FIDO_LIBFUZZER_UBSAN_OK)
  cmake_pop_check_state()
  if(NOT PCSC_FIDO_LIBFUZZER_UBSAN_OK)
    set(_pcsc_fido_fuzz_san "fuzzer,address")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=${_pcsc_fido_fuzz_san} -fno-omit-frame-pointer")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=${_pcsc_fido_fuzz_san}")
    check_c_source_compiles(
      "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  (void)data;\n  (void)size;\n  return 0;\n}\n"
      PCSC_FIDO_LIBFUZZER_OK)
    cmake_pop_check_state()
    if(NOT PCSC_FIDO_LIBFUZZER_OK)
      message(FATAL_ERROR "Compiler does not support -fsanitize=fuzzer,address")
    endif()
  endif()
  add_compile_options(-fsanitize=${_pcsc_fido_fuzz_san} -fno-omit-frame-pointer)
  add_link_options(-fsanitize=${_pcsc_fido_fuzz_san})
  include(CheckCCompilerFlag)
  check_c_compiler_flag(-fno-sanitize-recover=all PCSC_FIDO_FUZZ_FNO_SANITIZE_RECOVER)
  if(PCSC_FIDO_FUZZ_FNO_SANITIZE_RECOVER)
    add_compile_options(-fno-sanitize-recover=all)
  endif()
elseif(PCSC_FIDO_SANITIZER_FLAGS)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "Sanitizer builds require GCC or Clang")
  endif()

  if(PCSC_FIDO_ENABLE_EXTENDED_SANITIZERS AND NOT PCSC_FIDO_ENABLE_TSAN)
    set(_pcsc_fido_san_extra "")
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set(_pcsc_fido_san_extra ",pointer-compare,pointer-subtract,bounds-strict")
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
      set(_pcsc_fido_san_extra ",pointer-compare,pointer-subtract")
    endif()
    if(NOT _pcsc_fido_san_extra STREQUAL "")
      set(_pcsc_fido_san_extended "${PCSC_FIDO_SANITIZER_FLAGS}${_pcsc_fido_san_extra}")
      include(CMakePushCheckState)
      include(CheckCSourceCompiles)
      cmake_push_check_state()
      set(CMAKE_REQUIRED_FLAGS "-fsanitize=${_pcsc_fido_san_extended} -fno-omit-frame-pointer")
      set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=${_pcsc_fido_san_extended}")
      check_c_source_compiles("int main(void){return 0;}" PCSC_FIDO_SANITIZER_EXTENDED_OK)
      cmake_pop_check_state()
      if(PCSC_FIDO_SANITIZER_EXTENDED_OK)
        set(PCSC_FIDO_SANITIZER_FLAGS "${_pcsc_fido_san_extended}")
      endif()
    endif()
  endif()

  string(REPLACE ";" "," _pcsc_fido_san_join "${PCSC_FIDO_SANITIZER_FLAGS}")
  add_compile_options(-fsanitize=${_pcsc_fido_san_join} -fno-omit-frame-pointer)
  add_link_options(-fsanitize=${_pcsc_fido_san_join})

  include(CheckCCompilerFlag)
  check_c_compiler_flag(-fno-sanitize-recover=all PCSC_FIDO_FNO_SANITIZE_RECOVER)
  if(PCSC_FIDO_FNO_SANITIZE_RECOVER)
    add_compile_options(-fno-sanitize-recover=all)
  endif()
elseif(PCSC_FIDO_ENABLE_COVERAGE)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "Coverage builds require GCC or Clang")
  endif()
  add_compile_options(--coverage)
  add_link_options(--coverage)
elseif(_pcsc_fido_ipo_ok)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
else()
  message(STATUS "IPO/LTO not enabled for pcsc-fido: ${_pcsc_fido_ipo_msg}")
endif()

# OpenSSF hardening (org lint kit): include after sanitizer/coverage flag setup so the
# HAVE_INSTRUMENTED_SANITIZER fortify probe is not defeated by later add_compile_options.
# Probe as EXECUTABLE so the kit's check_linker_flag probes really link on cross
# toolchains (see pcsc_fido_push_executable_try_compile above). The cross link flags
# themselves (-pie, -z now/relro/noexecstack/pack-relative-relocs) are opted in via
# policy.overrides.openssf-hardening.cross in .github/lint-c-cpp.yaml; the generated
# cmake/Hardening.cmake must never be hand-edited (make lint regenerates it).
pcsc_fido_push_executable_try_compile()
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hardening.cmake")
define_hardening(TARGET hardening C_STANDARD 23)
pcsc_fido_pop_try_compile()
# CET/BTI: kit Hardening.cmake is compile-only, and its ARM probe presets 0 before
# check_*_compiler_flag (skipped). Distro CRT also drops GNU notes unless forced.
# Keep these workarounds in CMakeLists.txt — make lint regenerates cmake/Hardening*.cmake.
if(NOT CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  target_link_options(hardening INTERFACE
    -fcf-protection=full
    "LINKER:-z,ibt"
    "LINKER:-z,shstk")
endif()
set(_pcsc_fido_arm_bti 0)
if(UNIX AND NOT APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AArch64|arm64|ARM64)$")
  include(CheckCCompilerFlag)
  unset(PCSC_FIDO_HAVE_ARM_BTI)
  unset(PCSC_FIDO_HAVE_ARM_BTI CACHE)
  if(CMAKE_C_COMPILER)
    check_c_compiler_flag(-mbranch-protection=standard PCSC_FIDO_HAVE_ARM_BTI)
  endif()
  if(PCSC_FIDO_HAVE_ARM_BTI)
    set(_pcsc_fido_arm_bti 1)
  endif()
endif()
if(_pcsc_fido_arm_bti)
  target_compile_options(hardening INTERFACE
    $<$<COMPILE_LANGUAGE:C>:-mbranch-protection=standard>
    $<$<COMPILE_LANGUAGE:CXX>:-mbranch-protection=standard>)
  target_link_options(hardening INTERFACE
    -mbranch-protection=standard
    "LINKER:-z,force-bti")
endif()

set(PCSC_FIDO_CORE_SOURCES
  src/apdu.c
  src/apdu_chain.c
  src/cbor_util.c
  src/ctaphid.c
  src/daemon_channels.c
  src/daemon_config.c
  src/daemon_hid.c
  src/daemon_policy.c
  src/daemon_rate_limit.c
  src/daemon_signals.c
  src/daemon_uhid_loop.c
  src/mem_util.c
  src/pcsc_bridge.c
  src/pcsc_bridge_debug.c
  src/pcsc_err.c
  src/pcsc_fido_io.c
  src/pcsc_log.c
  src/pcsc_reader_ops.c
  src/pcsc_session.c
  src/reader_select.c
  src/tap_arm.c
)

# pcsc_fido_core is the archive the shipped daemon links. It is never compiled
# with PCSC_FIDO_TESTING: the test-only hooks (tap-arm 10 ms dormant poll,
# pcsc_fido_hid_exchange, signal/job accessors) live in pcsc_fido_core_testing
# (BUILD_TESTING block below), so a BUILD_TESTING=ON tree -- native package
# builds run ctest from the same tree -- still produces a production binary.
# Both archives are spelled out rather than built by a function so the lint
# kit's hardeninglint can follow the literal `hardening` link chain.
add_library(pcsc_fido_core STATIC ${PCSC_FIDO_CORE_SOURCES})
target_include_directories(pcsc_fido_core PUBLIC
  include
  "${CMAKE_CURRENT_BINARY_DIR}/include"
  PRIVATE ${PCSC_INCLUDE_DIRS})
target_link_libraries(pcsc_fido_core PUBLIC Threads::Threads hardening)

add_executable(pcsc-fido
  src/browser_daemon.c
  src/card_monitor.c
  src/daemon_request_handler.c
  src/exchange_orchestrator.c
  src/request_assembly.c
  src/uhid_transport.c
)
target_link_libraries(pcsc-fido PRIVATE pcsc_fido_core PkgConfig::PCSC Threads::Threads)

# Strip the Release build-tree binary (CMAKE_STRIP is toolchain-provided, including
# for cross ports), then drop `.comment` (compiler-version) so the artifact matches
# hardened system binaries like /bin/ls. This runs on the link output because
# install only copies it: CPack's own strip pass (CPACK_STRIP_FILES) does not remove
# `.comment`, so it has to be gone before install. release-build-package.sh
# verifies the CPack-staged install copy (which additionally has the build RUNPATH
# removed), not this file. `-fno-ident` only
# suppresses our own TUs: the distro's crt1.o / crti.o / crtbegin.o /
# libc_nonshared.a carry their own `.comment`, and LTO emits one again at link
# time, so the section survives strip. Gated on the strip option and build type so
# symbol-retaining and debug builds leave the binary untouched.
if(PCSC_FIDO_STRIP_RELEASE AND CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
  if(CMAKE_STRIP)
    add_custom_command(TARGET pcsc-fido POST_BUILD
      COMMAND "${CMAKE_STRIP}" "$<TARGET_FILE:pcsc-fido>"
      VERBATIM
      COMMENT "Stripping release pcsc-fido")
  endif()
  if(CMAKE_OBJCOPY)
    add_custom_command(TARGET pcsc-fido POST_BUILD
      COMMAND "${CMAKE_OBJCOPY}" -R .comment "$<TARGET_FILE:pcsc-fido>"
      VERBATIM
      COMMENT "Removing .comment from release pcsc-fido (/bin/ls parity)")
  endif()
endif()

if(BUILD_TESTING)
  set(PCSC_FIDO_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
  # Same sources and flags as pcsc_fido_core plus the test-only hooks; every
  # unit test links this archive, the daemon never does. The test headers
  # (scrub_hook.h, mock_pcsc.h, test_caps.h) reach the tests through its
  # interface rather than a directory-wide include_directories(), which would
  # also apply to pcsc_fido_core and pcsc-fido.
  add_library(pcsc_fido_core_testing STATIC ${PCSC_FIDO_CORE_SOURCES})
  target_include_directories(pcsc_fido_core_testing PUBLIC
    include
    "${CMAKE_CURRENT_BINARY_DIR}/include"
    INTERFACE "${PCSC_FIDO_TESTS_DIR}"
    PRIVATE ${PCSC_INCLUDE_DIRS})
  target_link_libraries(pcsc_fido_core_testing PUBLIC Threads::Threads hardening)
  target_compile_definitions(pcsc_fido_core_testing PRIVATE PCSC_FIDO_TESTING)

  # Compile the libFuzzer harness TUs under the standard hardening flags so the
  # OpenSSF compile-DB audit covers them. The runnable fuzzers are built
  # separately via PCSC_FIDO_BUILD_FUZZING (make fuzz); here we only need the
  # translation units in the compile database, so an OBJECT library suffices.
  add_library(pcsc_fido_fuzz_harness_lint OBJECT
    tests/fuzz/fuzz_apdu.c
    tests/fuzz/fuzz_cbor_util.c
    tests/fuzz/fuzz_request_assembly.c)
  target_link_libraries(pcsc_fido_fuzz_harness_lint PRIVATE pcsc_fido_core_testing)

  # Same for the CBMC harnesses (tests/cbmc, run by run-local-cbmc.sh): without a
  # target the lint kit synthesizes bare compile entries for them and the OpenSSF
  # audit reports every hardening flag missing. cbmc_cprover.h maps the
  # __CPROVER_* builtins to no-ops under a normal compiler, and the stubs dir
  # mirrors the -I the proof driver passes (linux/uhid.h without a kernel tree).
  add_library(pcsc_fido_cbmc_harness_lint OBJECT
    tests/cbmc/cbmc_apdu.c
    tests/cbmc/cbmc_cbor_read.c
    tests/cbmc/cbmc_cbor_skip.c
    tests/cbmc/cbmc_request_assembly.c)
  target_include_directories(pcsc_fido_cbmc_harness_lint PRIVATE tests/cbmc/stubs)
  target_compile_definitions(pcsc_fido_cbmc_harness_lint PRIVATE PCSC_FIDO_CBMC)
  target_link_libraries(pcsc_fido_cbmc_harness_lint PRIVATE pcsc_fido_core_testing)

  # Scrub-audited tests link scrub_hook.c with -Wl,--wrap=pcsc_fido_secure_clear.
  # Under LTO the IR definition in libpcsc_fido_core_testing is resolved inside the
  # compiler and the linker never sees a reference to wrap, so those tests
  # shadow the archive member with this non-LTO copy of mem_util.c; callers
  # stay LTO-compiled exactly as shipped, only the wipe primitive is an
  # ordinary linker symbol the wrap can route.
  add_library(pcsc_fido_mem_util_wrappable OBJECT src/mem_util.c)
  target_link_libraries(pcsc_fido_mem_util_wrappable PRIVATE pcsc_fido_core_testing)
  set_target_properties(pcsc_fido_mem_util_wrappable PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF)
  function(pcsc_fido_enable_scrub_hook target)
    target_sources(${target} PRIVATE tests/scrub_hook.c
      $<TARGET_OBJECTS:pcsc_fido_mem_util_wrappable>)
    target_link_options(${target} PRIVATE "-Wl,--wrap=pcsc_fido_secure_clear")
  endfunction()
  # Tests that wrap read/poll also need FORTIFY's __read_chk/__poll_chk routed to
  # those wraps (tests/fortify_wrap.c), or optimized builds bypass them.
  function(pcsc_fido_wrap_fortified_io target)
    target_sources(${target} PRIVATE tests/fortify_wrap.c)
    target_link_options(${target} PRIVATE "-Wl,--wrap=__read_chk" "-Wl,--wrap=__poll_chk")
  endfunction()

  add_executable(test_apdu tests/test_apdu.c)
  target_link_libraries(test_apdu PRIVATE pcsc_fido_core_testing)
  add_test(NAME apdu COMMAND test_apdu)

  add_executable(test_cbor_util tests/test_cbor_util.c)
  target_link_libraries(test_cbor_util PRIVATE pcsc_fido_core_testing)
  add_test(NAME cbor_util COMMAND test_cbor_util)

  add_executable(test_mem_util tests/test_mem_util.c)
  target_link_libraries(test_mem_util PRIVATE pcsc_fido_core_testing)
  pcsc_fido_enable_scrub_hook(test_mem_util)
  add_test(NAME mem_util COMMAND test_mem_util)

  # Same tests against the portable volatile-store tier of pcsc_fido_secure_clear:
  # this copy of mem_util.c is compiled with both libc tiers undefined (-U in the
  # target options follows the source-file -D on the command line: CMake emits
  # DEFINES before FLAGS), so the fallback that ships on toolchains without
  # memset_explicit/explicit_bzero is exercised on every host instead of only
  # where the probes fail. Non-LTO for the same reason as
  # pcsc_fido_mem_util_wrappable (the copy shadows the archive member). Only the
  # object is non-LTO: the executable keeps the build's IPO setting, because it
  # links the LTO archive and Clang only loads its linker plugin when -flto is
  # on the link line.
  add_library(pcsc_fido_mem_util_fallback OBJECT src/mem_util.c)
  target_compile_options(pcsc_fido_mem_util_fallback PRIVATE
    -UPCSC_FIDO_HAVE_MEMSET_EXPLICIT -UPCSC_FIDO_HAVE_EXPLICIT_BZERO)
  target_link_libraries(pcsc_fido_mem_util_fallback PRIVATE pcsc_fido_core_testing)
  set_target_properties(pcsc_fido_mem_util_fallback PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF)
  add_executable(test_mem_util_fallback tests/test_mem_util.c tests/scrub_hook.c
    $<TARGET_OBJECTS:pcsc_fido_mem_util_fallback>)
  target_link_libraries(test_mem_util_fallback PRIVATE pcsc_fido_core_testing)
  target_link_options(test_mem_util_fallback PRIVATE "-Wl,--wrap=pcsc_fido_secure_clear")
  add_test(NAME mem_util_fallback COMMAND test_mem_util_fallback)

  add_executable(test_ctaphid tests/test_ctaphid.c)
  target_link_libraries(test_ctaphid PRIVATE pcsc_fido_core_testing)
  target_compile_definitions(test_ctaphid PRIVATE PCSC_FIDO_TESTING)
  pcsc_fido_enable_scrub_hook(test_ctaphid)
  add_test(NAME ctaphid COMMAND test_ctaphid)

  add_executable(test_reader_select tests/test_reader_select.c)
  target_link_libraries(test_reader_select PRIVATE pcsc_fido_core_testing)
  add_test(NAME reader_select COMMAND test_reader_select)

  add_executable(test_reader_ops tests/test_reader_ops.c tests/mock_pcsc.c)
  target_include_directories(test_reader_ops PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_reader_ops PRIVATE pcsc_fido_core_testing)
  pcsc_fido_enable_scrub_hook(test_reader_ops)
  add_test(NAME reader_ops COMMAND test_reader_ops)

  add_executable(test_daemon_config tests/test_daemon_config.c)
  target_link_libraries(test_daemon_config PRIVATE pcsc_fido_core_testing)
  add_test(NAME daemon_config COMMAND test_daemon_config)

  add_executable(test_thread_safety tests/test_thread_safety.c tests/mock_pcsc.c)
  target_include_directories(test_thread_safety PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_thread_safety PRIVATE pcsc_fido_core_testing Threads::Threads)
  add_test(NAME thread_safety COMMAND test_thread_safety)

  add_executable(test_pcsc_bridge tests/test_pcsc_bridge.c tests/mock_pcsc.c)
  target_include_directories(test_pcsc_bridge PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_pcsc_bridge PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_link_options(test_pcsc_bridge PRIVATE "-Wl,--wrap=nanosleep" "-Wl,--wrap=clock_gettime")
  pcsc_fido_enable_scrub_hook(test_pcsc_bridge)
  add_test(NAME pcsc_bridge COMMAND test_pcsc_bridge)

  add_executable(test_pcsc_session tests/test_pcsc_session.c tests/mock_pcsc.c)
  target_include_directories(test_pcsc_session PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_pcsc_session PRIVATE pcsc_fido_core_testing)
  add_test(NAME pcsc_session COMMAND test_pcsc_session)

  add_executable(test_uhid_transport tests/test_uhid_transport.c src/uhid_transport.c)
  target_link_libraries(test_uhid_transport PRIVATE pcsc_fido_core_testing)
  target_link_options(test_uhid_transport PRIVATE "-Wl,--wrap=write")
  pcsc_fido_enable_scrub_hook(test_uhid_transport)
  add_test(NAME uhid_transport COMMAND test_uhid_transport)

  add_executable(test_exchange_orchestrator tests/test_exchange_orchestrator.c tests/mock_pcsc.c
    src/exchange_orchestrator.c src/uhid_transport.c)
  target_include_directories(test_exchange_orchestrator PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_exchange_orchestrator PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_compile_definitions(test_exchange_orchestrator PRIVATE PCSC_FIDO_TESTING)
  target_link_options(test_exchange_orchestrator PRIVATE "-Wl,--wrap=nanosleep"
    "-Wl,--wrap=clock_gettime" "-Wl,--wrap=pthread_create" "-Wl,--wrap=pthread_join")
  pcsc_fido_enable_scrub_hook(test_exchange_orchestrator)
  add_test(NAME exchange_orchestrator COMMAND test_exchange_orchestrator)

  add_executable(test_daemon_request_handler tests/test_daemon_request_handler.c tests/mock_pcsc.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/uhid_transport.c)
  target_include_directories(test_daemon_request_handler PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_daemon_request_handler PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_compile_definitions(test_daemon_request_handler PRIVATE PCSC_FIDO_TESTING)
  target_link_options(test_daemon_request_handler PRIVATE "-Wl,--wrap=nanosleep"
    "-Wl,--wrap=clock_gettime" "-Wl,--wrap=pthread_create")
  pcsc_fido_enable_scrub_hook(test_daemon_request_handler)
  add_test(NAME daemon_request_handler COMMAND test_daemon_request_handler)

  add_executable(test_browser_daemon_cli tests/test_browser_daemon_cli.c tests/mock_pcsc.c
    src/browser_daemon.c src/card_monitor.c src/daemon_request_handler.c src/exchange_orchestrator.c
    src/request_assembly.c src/uhid_transport.c)
  target_compile_definitions(test_browser_daemon_cli PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_browser_daemon_cli PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_browser_daemon_cli PRIVATE pcsc_fido_core_testing Threads::Threads)
  add_test(NAME browser_daemon_cli COMMAND test_browser_daemon_cli)

  add_executable(test_browser_daemon_loop tests/test_browser_daemon_loop.c tests/mock_pcsc.c
    src/browser_daemon.c src/card_monitor.c src/daemon_request_handler.c src/exchange_orchestrator.c
    src/request_assembly.c src/uhid_transport.c)
  target_compile_definitions(test_browser_daemon_loop PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_browser_daemon_loop PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_browser_daemon_loop PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_link_options(test_browser_daemon_loop PRIVATE "-Wl,--wrap=open" "-Wl,--wrap=__open_2"
    "-Wl,--wrap=read" "-Wl,--wrap=write" "-Wl,--wrap=close" "-Wl,--wrap=poll"
    "-Wl,--wrap=nanosleep" "-Wl,--wrap=clock_gettime")
  pcsc_fido_wrap_fortified_io(test_browser_daemon_loop)
  add_test(NAME browser_daemon_loop COMMAND test_browser_daemon_loop)

  add_executable(test_tap_arm tests/test_tap_arm.c tests/mock_pcsc.c src/card_monitor.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/request_assembly.c
    src/uhid_transport.c)
  target_compile_definitions(test_tap_arm PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_tap_arm PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_tap_arm PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_link_options(test_tap_arm PRIVATE "-Wl,--wrap=read" "-Wl,--wrap=write" "-Wl,--wrap=poll"
    "-Wl,--wrap=clock_gettime" "-Wl,--wrap=nanosleep" "-Wl,--wrap=pthread_create")
  pcsc_fido_wrap_fortified_io(test_tap_arm)
  add_test(NAME tap_arm COMMAND test_tap_arm)

  add_executable(test_daemon_uhid_loop tests/test_daemon_uhid_loop.c tests/mock_pcsc.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/request_assembly.c
    src/uhid_transport.c)
  target_compile_definitions(test_daemon_uhid_loop PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_daemon_uhid_loop PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_daemon_uhid_loop PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_link_options(test_daemon_uhid_loop PRIVATE "-Wl,--wrap=read" "-Wl,--wrap=write"
    "-Wl,--wrap=poll" "-Wl,--wrap=clock_gettime" "-Wl,--wrap=nanosleep")
  pcsc_fido_wrap_fortified_io(test_daemon_uhid_loop)
  pcsc_fido_enable_scrub_hook(test_daemon_uhid_loop)
  add_test(NAME daemon_uhid_loop COMMAND test_daemon_uhid_loop)

  add_executable(test_apdu_chain tests/test_apdu_chain.c)
  target_link_libraries(test_apdu_chain PRIVATE pcsc_fido_core_testing)
  pcsc_fido_enable_scrub_hook(test_apdu_chain)
  add_test(NAME apdu_chain COMMAND test_apdu_chain)

  add_executable(test_daemon_policy tests/test_daemon_policy.c)
  target_link_libraries(test_daemon_policy PRIVATE pcsc_fido_core_testing)
  add_test(NAME daemon_policy COMMAND test_daemon_policy)

  add_executable(test_daemon_hid tests/test_daemon_hid.c)
  target_link_libraries(test_daemon_hid PRIVATE pcsc_fido_core_testing)
  add_test(NAME daemon_hid COMMAND test_daemon_hid)

  add_executable(test_daemon_rate_limit tests/test_daemon_rate_limit.c)
  target_compile_definitions(test_daemon_rate_limit PRIVATE PCSC_FIDO_TESTING)
  target_link_libraries(test_daemon_rate_limit PRIVATE pcsc_fido_core_testing)
  target_link_options(test_daemon_rate_limit PRIVATE "-Wl,--wrap=clock_gettime"
    "-Wl,--wrap=time")
  add_test(NAME daemon_rate_limit COMMAND test_daemon_rate_limit)

  add_executable(test_card_monitor tests/test_card_monitor.c tests/mock_pcsc.c src/card_monitor.c)
  target_include_directories(test_card_monitor PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_card_monitor PRIVATE pcsc_fido_core_testing Threads::Threads)
  target_link_options(test_card_monitor PRIVATE "-Wl,--wrap=nanosleep")
  add_test(NAME card_monitor COMMAND test_card_monitor)

  add_executable(test_request_assembly tests/test_request_assembly.c tests/stub_uhid_transport.c
    src/request_assembly.c)
  target_link_libraries(test_request_assembly PRIVATE pcsc_fido_core_testing)
  target_link_options(test_request_assembly PRIVATE "-Wl,--wrap=clock_gettime")
  pcsc_fido_enable_scrub_hook(test_request_assembly)
  add_test(NAME request_assembly COMMAND test_request_assembly)

  set(PCSC_FIDO_UNIT_TEST_TARGETS
    test_apdu
    test_cbor_util
    test_mem_util
    test_mem_util_fallback
    test_ctaphid
    test_reader_select
    test_reader_ops
    test_daemon_config
    test_thread_safety
    test_pcsc_bridge
    test_pcsc_session
    test_uhid_transport
    test_exchange_orchestrator
    test_daemon_request_handler
    test_browser_daemon_cli
    test_browser_daemon_loop
    test_tap_arm
    test_daemon_uhid_loop
    test_apdu_chain
    test_daemon_policy
    test_daemon_hid
    test_daemon_rate_limit
    test_card_monitor
    test_request_assembly
  )
  add_custom_target(pcsc_fido_unit_tests DEPENDS ${PCSC_FIDO_UNIT_TEST_TARGETS})
endif()

if(PCSC_FIDO_BUILD_FUZZING)
  add_executable(fuzz_cbor_util tests/fuzz/fuzz_cbor_util.c)
  target_link_libraries(fuzz_cbor_util PRIVATE pcsc_fido_core)

  add_executable(fuzz_request_assembly tests/fuzz/fuzz_request_assembly.c tests/stub_uhid_transport.c
                 src/request_assembly.c)
  target_link_libraries(fuzz_request_assembly PRIVATE pcsc_fido_core)

  add_executable(fuzz_apdu tests/fuzz/fuzz_apdu.c)
  target_link_libraries(fuzz_apdu PRIVATE pcsc_fido_core)

  add_custom_target(pcsc_fido_fuzzers DEPENDS fuzz_cbor_util fuzz_request_assembly fuzz_apdu)
endif()

# Configure-time guard, evaluated after every target above: the shipped archive
# and binary must never carry PCSC_FIDO_TESTING, whatever BUILD_TESTING is
# (native package builds run ctest from the same tree). Checked here rather
# than trusted from a comment; test hooks belong in pcsc_fido_core_testing.
get_directory_property(_pcsc_fido_dir_defs COMPILE_DEFINITIONS)
if("${_pcsc_fido_dir_defs}" MATCHES "(^|;)PCSC_FIDO_TESTING(=[^;]*)?(;|$)")
  message(FATAL_ERROR "PCSC_FIDO_TESTING must not be a directory-wide definition")
endif()
foreach(_pcsc_fido_guard_target pcsc_fido_core pcsc-fido)
  foreach(_pcsc_fido_guard_prop COMPILE_DEFINITIONS INTERFACE_COMPILE_DEFINITIONS)
    get_target_property(_pcsc_fido_guard_defs ${_pcsc_fido_guard_target} ${_pcsc_fido_guard_prop})
    if(_pcsc_fido_guard_defs AND
       "${_pcsc_fido_guard_defs}" MATCHES "(^|;)PCSC_FIDO_TESTING(=[^;]*)?(;|$)")
      message(FATAL_ERROR
        "${_pcsc_fido_guard_target} must not define PCSC_FIDO_TESTING "
        "(${_pcsc_fido_guard_prop}); test-only hooks belong in pcsc_fido_core_testing")
    endif()
  endforeach()
endforeach()
# Likewise the tests/ include directory (test headers, mocks).
set(_pcsc_fido_tests_include_dir "${CMAKE_CURRENT_SOURCE_DIR}/tests")
get_directory_property(_pcsc_fido_dir_includes INCLUDE_DIRECTORIES)
if(_pcsc_fido_tests_include_dir IN_LIST _pcsc_fido_dir_includes)
  message(FATAL_ERROR "tests/ must not be a directory-wide include directory")
endif()
foreach(_pcsc_fido_guard_target pcsc_fido_core pcsc-fido)
  foreach(_pcsc_fido_guard_prop INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
    get_target_property(_pcsc_fido_guard_dirs ${_pcsc_fido_guard_target} ${_pcsc_fido_guard_prop})
    if(_pcsc_fido_guard_dirs AND _pcsc_fido_tests_include_dir IN_LIST _pcsc_fido_guard_dirs)
      message(FATAL_ERROR
        "${_pcsc_fido_guard_target} must not include tests/ (${_pcsc_fido_guard_prop}); "
        "test headers belong to pcsc_fido_core_testing")
    endif()
  endforeach()
endforeach()

set(CMAKE_INSTALL_UDEVRULESDIR "lib/udev/rules.d" CACHE PATH "udev rules install directory")
set(CMAKE_INSTALL_SYSTEMDUNITDIR "lib/systemd/system" CACHE PATH "systemd unit install directory")
set(CMAKE_INSTALL_SYSUSERSDIR "lib/sysusers.d" CACHE PATH "systemd sysusers install directory")
set(CMAKE_INSTALL_DOCDIR "share/doc/pcsc-fido")

install(TARGETS pcsc-fido RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES packaging/modules-load/pcsc-fido-uhid.conf
        DESTINATION "lib/modules-load.d")
install(FILES packaging/udev/70-pcsc-fido.rules DESTINATION "${CMAKE_INSTALL_UDEVRULESDIR}")
install(FILES packaging/systemd/pcsc-fido.service
        DESTINATION "${CMAKE_INSTALL_SYSTEMDUNITDIR}")
install(FILES packaging/systemd/60-pcsc-fido.preset
        DESTINATION "lib/systemd/system-preset")
install(FILES packaging/systemd/pcsc-fido.conf DESTINATION "${CMAKE_INSTALL_SYSUSERSDIR}")
install(FILES packaging/polkit/50-pcsc-fido.rules DESTINATION "share/polkit-1/rules.d")
install(PROGRAMS packaging/scripts/ensure-pcsc-fido-user.sh
        DESTINATION "lib/pcsc-fido"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
install(FILES INSTALLATION.md NOTICE DESTINATION "${CMAKE_INSTALL_DOCDIR}")

set(CPACK_PACKAGE_NAME "pcsc-fido")
set(CPACK_PACKAGE_VENDOR "Nero Duality")
set(CPACK_PACKAGE_CONTACT "200@neroduality.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/neroduality/pcsc-fido")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Middleware bridging PC/SC NFC FIDO to browser WebAuthn (daemon side)")
# Shared long description. Applied to both generators below so neither falls back
# to CPack's generic placeholder (the RPM otherwise ships "This is an installer
# created using CPack ..."). Wrapped at <80 columns for RPM %description limits;
# CPack indents the DEB continuation lines.
set(PCSC_FIDO_PACKAGE_DESCRIPTION
"Daemon-side stopgap middleware for Linux: exposes a virtual FIDO HID
device via UHID to relay browser CTAP/U2F requests to NFC security keys
over the PC/SC stack.")
set(CPACK_PACKAGE_DESCRIPTION "${PCSC_FIDO_PACKAGE_DESCRIPTION}")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "${PCSC_FIDO_PACKAGE_DESCRIPTION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${PCSC_FIDO_PACKAGE_DESCRIPTION}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ")
find_program(DPKG_DEB_EXECUTABLE dpkg-deb)
if(DPKG_DEB_EXECUTABLE)
  list(APPEND CPACK_GENERATOR "DEB")
endif()
find_program(RPMBUILD_EXECUTABLE rpmbuild)
if(RPMBUILD_EXECUTABLE)
  list(APPEND CPACK_GENERATOR "RPM")
endif()
set(CPACK_DEBIAN_PACKAGE_NAME "pcsc-fido")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nero Duality <200@neroduality.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/neroduality/pcsc-fido")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpcsclite1, pcscd, libccid, udev, systemd, polkitd | policykit-1")
set(CPACK_DEBIAN_PACKAGE_SECTION "misc")
if(CMAKE_CROSSCOMPILING OR (DEFINED PCSC_FIDO_CROSS_BUILD AND PCSC_FIDO_CROSS_BUILD))
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
  if(PCSC_FIDO_DEBIAN_PACKAGE_ARCHITECTURE)
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${PCSC_FIDO_DEBIAN_PACKAGE_ARCHITECTURE}")
  endif()
  if(PCSC_FIDO_RPM_PACKAGE_ARCHITECTURE)
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "${PCSC_FIDO_RPM_PACKAGE_ARCHITECTURE}")
  endif()
  # Host rpmbuild brp-strip cannot handle foreign-arch binaries.
  set(CPACK_RPM_SPEC_MORE_DEFINE "%global __os_install_post %{nil}")
endif()
if(PCSC_FIDO_STRIP_RELEASE AND CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
  set(CPACK_STRIP_FILES TRUE)
endif()
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
  "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postinst;${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/prerm;${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postrm"
)
set(CPACK_RPM_PACKAGE_NAME "pcsc-fido")
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_URL "https://github.com/neroduality/pcsc-fido")
set(CPACK_RPM_PACKAGE_VENDOR "Nero Duality")
set(CPACK_RPM_PACKAGE_REQUIRES "pcsc-lite, pcsc-lite-libs, pcsc-lite-ccid, udev, systemd, polkit")
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/prerm")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postrm")
include(CPack)
