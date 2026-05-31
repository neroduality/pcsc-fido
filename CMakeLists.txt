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


cmake_minimum_required(VERSION 3.20)
# Release version: bump `project(... VERSION ...)` below before tagging (v* tag
# without the leading v). CMake generates `include/pcsc_fido/version.h` from
# that value; it feeds CPACK, packages, and `pcsc-fido --version`. See RELEASE.md.
project(pcsc_fido VERSION 0.1.0 LANGUAGES C)

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

# ISO C23 + HostHardening.cmake (OpenSSF-style hosted Linux hardening).
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT _pcsc_fido_ipo_ok OUTPUT _pcsc_fido_ipo_msg)

# Cross toolchains use static-library try-compiles for feature probes, but the PIE probe must
# prove that the target compiler can link an executable with PIE enabled.
set(_pcsc_fido_try_compile_target_type_saved "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
if(CMAKE_CROSSCOMPILING AND CMAKE_TRY_COMPILE_TARGET_TYPE STREQUAL "STATIC_LIBRARY")
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
endif()
include(CheckPIESupported)
check_pie_supported(LANGUAGES C OUTPUT_VARIABLE _pcsc_fido_pie_msg)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_pcsc_fido_try_compile_target_type_saved}")
if(NOT CMAKE_C_LINK_PIE_SUPPORTED)
  message(FATAL_ERROR "PIE linking is required for pcsc-fido: ${_pcsc_fido_pie_msg}")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/HostHardening.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyCompiler.cmake")

if(PCSC_FIDO_HAVE_MEMSET_EXPLICIT)
  add_compile_definitions(PCSC_FIDO_HAVE_MEMSET_EXPLICIT=1)
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

add_library(pcsc_fido_core STATIC
  src/apdu.c
  src/apdu_chain.c
  src/cbor_util.c
  src/ctaphid.c
  src/daemon_config.c
  src/daemon_hid.c
  src/daemon_policy.c
  src/daemon_rate_limit.c
  src/daemon_signals.c
  src/daemon_uhid_loop.c
  src/pcsc_bridge.c
  src/pcsc_bridge_debug.c
  src/pcsc_err.c
  src/pcsc_log.c
  src/pcsc_reader_ops.c
  src/pcsc_session.c
  src/reader_select.c
  src/tap_arm.c
)
target_include_directories(pcsc_fido_core PUBLIC
  include
  "${CMAKE_CURRENT_BINARY_DIR}/include"
  PRIVATE ${PCSC_INCLUDE_DIRS})
target_link_libraries(pcsc_fido_core PUBLIC Threads::Threads pcsc_fido_host_hardening)

add_executable(pcsc-fido
  src/browser_daemon.c
  src/card_monitor.c
  src/daemon_request_handler.c
  src/exchange_orchestrator.c
  src/request_assembly.c
  src/uhid_transport.c
)
target_link_libraries(pcsc-fido PRIVATE pcsc_fido_core PkgConfig::PCSC Threads::Threads)

if(BUILD_TESTING)
  set(PCSC_FIDO_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
  target_compile_definitions(pcsc_fido_core PRIVATE PCSC_FIDO_TESTING)

  add_executable(test_apdu tests/test_apdu.c)
  target_link_libraries(test_apdu PRIVATE pcsc_fido_core)
  add_test(NAME apdu COMMAND test_apdu)

  add_executable(test_cbor_util tests/test_cbor_util.c)
  target_link_libraries(test_cbor_util PRIVATE pcsc_fido_core)
  add_test(NAME cbor_util COMMAND test_cbor_util)

  add_executable(test_mem_util tests/test_mem_util.c)
  target_link_libraries(test_mem_util PRIVATE pcsc_fido_core)
  add_test(NAME mem_util COMMAND test_mem_util)

  add_executable(test_ctaphid tests/test_ctaphid.c)
  target_link_libraries(test_ctaphid PRIVATE pcsc_fido_core)
  add_test(NAME ctaphid COMMAND test_ctaphid)

  add_executable(test_reader_select tests/test_reader_select.c)
  target_link_libraries(test_reader_select PRIVATE pcsc_fido_core)
  add_test(NAME reader_select COMMAND test_reader_select)

  add_executable(test_reader_ops tests/test_reader_ops.c tests/mock_pcsc.c)
  target_include_directories(test_reader_ops PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_reader_ops PRIVATE pcsc_fido_core)
  add_test(NAME reader_ops COMMAND test_reader_ops)

  add_executable(test_daemon_config tests/test_daemon_config.c)
  target_link_libraries(test_daemon_config PRIVATE pcsc_fido_core)
  add_test(NAME daemon_config COMMAND test_daemon_config)

  add_executable(test_thread_safety tests/test_thread_safety.c tests/mock_pcsc.c)
  target_include_directories(test_thread_safety PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_thread_safety PRIVATE pcsc_fido_core Threads::Threads)
  add_test(NAME thread_safety COMMAND test_thread_safety)

  add_executable(test_pcsc_bridge tests/test_pcsc_bridge.c tests/mock_pcsc.c)
  target_include_directories(test_pcsc_bridge PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_pcsc_bridge PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_pcsc_bridge PRIVATE "-Wl,--wrap=nanosleep" "-Wl,--wrap=time")
  add_test(NAME pcsc_bridge COMMAND test_pcsc_bridge)

  add_executable(test_pcsc_session tests/test_pcsc_session.c tests/mock_pcsc.c)
  target_include_directories(test_pcsc_session PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_pcsc_session PRIVATE pcsc_fido_core)
  add_test(NAME pcsc_session COMMAND test_pcsc_session)

  add_executable(test_uhid_transport tests/test_uhid_transport.c src/uhid_transport.c)
  target_link_libraries(test_uhid_transport PRIVATE pcsc_fido_core)
  target_link_options(test_uhid_transport PRIVATE "-Wl,--wrap=write")
  add_test(NAME uhid_transport COMMAND test_uhid_transport)

  add_executable(test_exchange_orchestrator tests/test_exchange_orchestrator.c tests/mock_pcsc.c
    src/exchange_orchestrator.c src/uhid_transport.c)
  target_include_directories(test_exchange_orchestrator PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_exchange_orchestrator PRIVATE pcsc_fido_core Threads::Threads)
  target_compile_definitions(test_exchange_orchestrator PRIVATE PCSC_FIDO_TESTING)
  target_link_options(test_exchange_orchestrator PRIVATE "-Wl,--wrap=nanosleep"
    "-Wl,--wrap=time" "-Wl,--wrap=pthread_create")
  add_test(NAME exchange_orchestrator COMMAND test_exchange_orchestrator)

  add_executable(test_daemon_request_handler tests/test_daemon_request_handler.c tests/mock_pcsc.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/uhid_transport.c)
  target_include_directories(test_daemon_request_handler PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_daemon_request_handler PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_daemon_request_handler PRIVATE "-Wl,--wrap=nanosleep" "-Wl,--wrap=time")
  add_test(NAME daemon_request_handler COMMAND test_daemon_request_handler)

  add_executable(test_browser_daemon_cli tests/test_browser_daemon_cli.c tests/mock_pcsc.c
    src/browser_daemon.c src/card_monitor.c src/daemon_request_handler.c src/exchange_orchestrator.c
    src/request_assembly.c src/uhid_transport.c)
  target_compile_definitions(test_browser_daemon_cli PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_browser_daemon_cli PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_browser_daemon_cli PRIVATE pcsc_fido_core Threads::Threads)
  add_test(NAME browser_daemon_cli COMMAND test_browser_daemon_cli)

  add_executable(test_browser_daemon_loop tests/test_browser_daemon_loop.c tests/mock_pcsc.c
    src/browser_daemon.c src/card_monitor.c src/daemon_request_handler.c src/exchange_orchestrator.c
    src/request_assembly.c src/uhid_transport.c)
  target_compile_definitions(test_browser_daemon_loop PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_browser_daemon_loop PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_browser_daemon_loop PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_browser_daemon_loop PRIVATE "-Wl,--wrap=open" "-Wl,--wrap=read"
    "-Wl,--wrap=write" "-Wl,--wrap=close" "-Wl,--wrap=poll" "-Wl,--wrap=nanosleep"
    "-Wl,--wrap=time")
  add_test(NAME browser_daemon_loop COMMAND test_browser_daemon_loop)

  add_executable(test_tap_arm tests/test_tap_arm.c tests/mock_pcsc.c src/card_monitor.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/request_assembly.c
    src/uhid_transport.c)
  target_compile_definitions(test_tap_arm PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_tap_arm PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_tap_arm PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_tap_arm PRIVATE "-Wl,--wrap=read" "-Wl,--wrap=write" "-Wl,--wrap=poll"
    "-Wl,--wrap=time" "-Wl,--wrap=nanosleep")
  add_test(NAME tap_arm COMMAND test_tap_arm)

  add_executable(test_daemon_uhid_loop tests/test_daemon_uhid_loop.c tests/mock_pcsc.c
    src/daemon_request_handler.c src/exchange_orchestrator.c src/request_assembly.c
    src/uhid_transport.c)
  target_compile_definitions(test_daemon_uhid_loop PRIVATE PCSC_FIDO_TESTING)
  target_include_directories(test_daemon_uhid_loop PRIVATE "${PCSC_FIDO_TESTS_DIR}"
    ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_daemon_uhid_loop PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_daemon_uhid_loop PRIVATE "-Wl,--wrap=read" "-Wl,--wrap=write"
    "-Wl,--wrap=poll" "-Wl,--wrap=time" "-Wl,--wrap=nanosleep")
  add_test(NAME daemon_uhid_loop COMMAND test_daemon_uhid_loop)

  add_executable(test_apdu_chain tests/test_apdu_chain.c)
  target_link_libraries(test_apdu_chain PRIVATE pcsc_fido_core)
  add_test(NAME apdu_chain COMMAND test_apdu_chain)

  add_executable(test_daemon_policy tests/test_daemon_policy.c)
  target_link_libraries(test_daemon_policy PRIVATE pcsc_fido_core)
  add_test(NAME daemon_policy COMMAND test_daemon_policy)

  add_executable(test_daemon_hid tests/test_daemon_hid.c)
  target_link_libraries(test_daemon_hid PRIVATE pcsc_fido_core)
  add_test(NAME daemon_hid COMMAND test_daemon_hid)

  add_executable(test_daemon_rate_limit tests/test_daemon_rate_limit.c)
  target_compile_definitions(test_daemon_rate_limit PRIVATE PCSC_FIDO_TESTING)
  target_link_libraries(test_daemon_rate_limit PRIVATE pcsc_fido_core)
  target_link_options(test_daemon_rate_limit PRIVATE "-Wl,--wrap=time")
  add_test(NAME daemon_rate_limit COMMAND test_daemon_rate_limit)

  add_executable(test_card_monitor tests/test_card_monitor.c tests/mock_pcsc.c src/card_monitor.c)
  target_include_directories(test_card_monitor PRIVATE "${PCSC_FIDO_TESTS_DIR}" ${PCSC_INCLUDE_DIRS})
  target_link_libraries(test_card_monitor PRIVATE pcsc_fido_core Threads::Threads)
  target_link_options(test_card_monitor PRIVATE "-Wl,--wrap=nanosleep")
  add_test(NAME card_monitor COMMAND test_card_monitor)

  add_executable(test_request_assembly tests/test_request_assembly.c tests/stub_uhid_transport.c
    src/request_assembly.c)
  target_link_libraries(test_request_assembly PRIVATE pcsc_fido_core)
  add_test(NAME request_assembly COMMAND test_request_assembly)

  set(PCSC_FIDO_UNIT_TEST_TARGETS
    test_apdu
    test_cbor_util
    test_mem_util
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
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Middleware bridging PC/SC NFC FIDO to browser WebAuthn (daemon side)")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
    "Daemon-side stopgap middleware for Linux: Exposes a virtual FIDO HID device via 
    UHID to relay browser CTAP/U2F requests to NFC security keys over the PC/SC stack."
)
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
set(CPACK_RPM_PACKAGE_REQUIRES "pcsc-lite, pcsc-lite-libs, pcsc-lite-ccid, udev, systemd, polkit")
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/prerm")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/scripts/postrm")
include(CPack)
