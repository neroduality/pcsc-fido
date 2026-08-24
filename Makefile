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


BUILD_DIR ?= build
# Plain unit tests use a dedicated tree (nero-nfc: tests/build) so wipe/test never
# races make build/package TryCompile under build/CMakeFiles/CMakeScratch.
TEST_BUILD_DIR ?= $(BUILD_DIR)/unit
BUILD_TREES ?= $(BUILD_DIR) $(TEST_BUILD_DIR) $(BUILD_DIR)-asan $(BUILD_DIR)-ubsan $(BUILD_DIR)-valgrind $(BUILD_DIR)-tsan $(BUILD_DIR)/lint $(BUILD_DIR)/ci .fuzz build-fuzz .lint-kit-org
CMAKE_BUILD_TYPE ?= Debug
INSTALL_PREFIX ?= /usr
INSTALL_BUILD_TYPE ?= Release
LINT_FLAGS ?=
INSTALL_DEPS ?= 0
PCSC_FIDO_DEPS_SCOPE ?= full
CI_LOCAL_FLAGS ?=
# Honor CI_LOCAL_FLAGS only from the make command line, not the shell environment.
_CI_LOCAL_FLAGS :=
ifeq ($(origin CI_LOCAL_FLAGS),command line)
  _CI_LOCAL_FLAGS := $(CI_LOCAL_FLAGS)
endif

# Org C/C++ lint kit (neroduality/.github -> lint-c-cpp). Cloned on demand into
# .lint-kit-org via .github/scripts/lint-kit-config.sh (ref from lint-c-cpp.yaml).
# Override with `make lint LINT_KIT=/path/to/lint-c-cpp` for local kit iteration.
# LINT_KIT may point either at the kit dir (contains lint-c-cpp.sh) or at a
# checkout of neroduality/.github (contains lint-c-cpp/lint-c-cpp.sh).
DEFAULT_LINT_KIT := $(CURDIR)/.lint-kit-org/lint-c-cpp
LINT_KIT ?= $(DEFAULT_LINT_KIT)
# Capture before override below (which would reset origin to "file").
_LINT_KIT_ORIGIN := $(origin LINT_KIT)
_LINT_KIT_RAW := $(abspath $(LINT_KIT))
override LINT_KIT := $(if $(wildcard $(_LINT_KIT_RAW)/lint-c-cpp.sh),$(_LINT_KIT_RAW),$(if $(wildcard $(_LINT_KIT_RAW)/lint-c-cpp/lint-c-cpp.sh),$(_LINT_KIT_RAW)/lint-c-cpp,$(_LINT_KIT_RAW)))
export LINT_KIT
export LINT_REPO_ROOT := $(CURDIR)

.DEFAULT_GOAL := all

.PHONY: all build debug test verify asan ubsan valgrind tsan sanitizers coverage lint require-lint-kit lint-self-test security-lint ci-local ci-local-help codeql-local lima deps maybe-deps install install-debug post-install uninstall package clean help refuse-root ensure-build-owner fuzz

# Build/test targets must not run as root -- keeps build/ user-owned.
refuse-root:
	@bash "$(CURDIR)/.github/scripts/helper-build-tree-ownership.sh" refuse-root-make

ensure-build-owner: refuse-root
	@bash "$(CURDIR)/.github/scripts/helper-ensure-build-tree-owner.sh" $(BUILD_TREES)

all: build

build: PCSC_FIDO_DEPS_SCOPE=build
debug: PCSC_FIDO_DEPS_SCOPE=build
test: PCSC_FIDO_DEPS_SCOPE=build
asan: PCSC_FIDO_DEPS_SCOPE=build
ubsan: PCSC_FIDO_DEPS_SCOPE=build
valgrind: PCSC_FIDO_DEPS_SCOPE=verify
tsan: PCSC_FIDO_DEPS_SCOPE=build
lint: PCSC_FIDO_DEPS_SCOPE=full
verify: PCSC_FIDO_DEPS_SCOPE=verify

build: ensure-build-owner maybe-deps
	@cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CMAKE_BUILD_TYPE)" \
	  -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" -DBUILD_TESTING=OFF
	@cmake --build "$(BUILD_DIR)" --target pcsc-fido -j$$(nproc 2>/dev/null || echo 2)

debug: CMAKE_BUILD_TYPE=Debug
debug: build

test: ensure-build-owner maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@cmake -S . -B "$(TEST_BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CMAKE_BUILD_TYPE)" \
	  -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" -DBUILD_TESTING=ON \
	  -DPCSC_FIDO_DEBUG_SANITIZERS=OFF
	@cmake --build "$(TEST_BUILD_DIR)" --target pcsc_fido_unit_tests \
	  -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(TEST_BUILD_DIR)" --output-on-failure

asan: ensure-build-owner maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@cmake -S . -B "$(BUILD_DIR)-asan" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_ENABLE_ASAN=ON
	@cmake --build "$(BUILD_DIR)-asan" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-asan" --output-on-failure

ubsan: ensure-build-owner maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@cmake -S . -B "$(BUILD_DIR)-ubsan" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_ENABLE_UBSAN=ON
	@cmake --build "$(BUILD_DIR)-ubsan" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-ubsan" --output-on-failure

valgrind: ensure-build-owner maybe-deps
	@if ! command -v valgrind >/dev/null 2>&1; then \
	  printf 'error: valgrind not found (install via: make deps or INSTALL_DEPS=1 make verify)\n' >&2; \
	  exit 1; \
	fi
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@cmake -S . -B "$(BUILD_DIR)-valgrind" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_DEBUG_SANITIZERS=OFF
	@cmake --build "$(BUILD_DIR)-valgrind" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-valgrind" -T memcheck --output-on-failure

verify: ensure-build-owner maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" verify
	@PCSC_FIDO_KEEP_HOST_BUILDS=1 $(MAKE) test INSTALL_DEPS=0
	@PCSC_FIDO_KEEP_HOST_BUILDS=1 $(MAKE) asan INSTALL_DEPS=0
	@PCSC_FIDO_KEEP_HOST_BUILDS=1 $(MAKE) ubsan INSTALL_DEPS=0
	@PCSC_FIDO_KEEP_HOST_BUILDS=1 $(MAKE) tsan INSTALL_DEPS=0
	@PCSC_FIDO_KEEP_HOST_BUILDS=1 $(MAKE) valgrind INSTALL_DEPS=0

tsan: ensure-build-owner maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@tsan_mode=$$(bash "$(CURDIR)/.github/scripts/helper-tsan-probe.sh"); \
	if [ "$$tsan_mode" = "skip" ]; then \
	  printf '%s\n' \
	    'warning: ThreadSanitizer unavailable at runtime (common on Debian with high ASLR / older libtsan); skipping TSan tests'; \
	  exit 0; \
	fi; \
	cmake -S . -B "$(BUILD_DIR)-tsan" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_ENABLE_TSAN=ON && \
	cmake --build "$(BUILD_DIR)-tsan" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2) && \
	if [ "$$tsan_mode" = "setarch" ]; then \
	  setarch $$(uname -m) -R ctest --test-dir "$(BUILD_DIR)-tsan" --output-on-failure; \
	else \
	  ctest --test-dir "$(BUILD_DIR)-tsan" --output-on-failure; \
	fi

sanitizers: asan ubsan tsan

coverage: ensure-build-owner
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@AUTO_INSTALL_LINUX_DEPS=0 bash .github/scripts/run-local-line-coverage.sh

lint: require-lint-kit ensure-build-owner maybe-deps lint-self-test
	@case ' $(LINT_FLAGS) ' in \
	  *' --custom-lints-only '*) ;; \
	  *) \
	    if [ "$${CI:-}" = "true" ]; then \
	      bash "$(CURDIR)/make/wipe-host-build-trees.sh" ci; \
	    else \
	      bash "$(CURDIR)/make/wipe-host-build-trees.sh" lint; \
	    fi ;; \
	esac
	@bash "$(LINT_KIT)/lint-c-cpp.sh" precheck
	@bash "$(LINT_KIT)/lint-c-cpp.sh" lint $(LINT_FLAGS)

require-lint-kit:
	@bash "$(CURDIR)/.github/scripts/lint-kit-config.sh" --prepare-writable "$(CURDIR)" || true
	@if [ "$(LINT_KIT)" != "$(abspath $(DEFAULT_LINT_KIT))" ] && [ ! -d "$(LINT_KIT)" ]; then \
	  echo "ERROR: lint kit not found: $(LINT_KIT)" >&2; \
	  echo "fix: make lint LINT_KIT=/path/to/lint-c-cpp" >&2; \
	  exit 1; \
	fi
	@if [ "$(LINT_KIT)" = "$(abspath $(DEFAULT_LINT_KIT))" ]; then \
	  bash "$(CURDIR)/.github/scripts/lint-kit-config.sh" --ensure-cloned "$(CURDIR)"; \
	fi
	@if [ ! -x "$(LINT_KIT)/lint-c-cpp.sh" ]; then \
	  echo "ERROR: lint kit missing lint-c-cpp.sh: $(LINT_KIT)" >&2; \
	  exit 1; \
	fi

lint-self-test: require-lint-kit
	@bash "$(LINT_KIT)/lint-c-cpp.sh" self-test

fuzz: refuse-root
	@PCSC_FIDO_AUTO_FUZZ_DEPS=1 bash "$(CURDIR)/.github/scripts/run-local-fuzz.sh" $(FUZZ_FLAGS)

security-lint:
	@bash "$(CURDIR)/.github/scripts/run-security-suite-locally.sh"

# Forward LINT_KIT when set on the command line or in the environment; otherwise
# unset Make's default so scripts clone toolchain.lint_kit from lint-c-cpp.yaml.
_CI_LOCAL_LINT_ENV := $(if $(filter command line environment,$(_LINT_KIT_ORIGIN)),LINT_KIT=$(LINT_KIT),env -u LINT_KIT)

ci-local: ensure-build-owner
	@AUTO_INSTALL_LINUX_DEPS=0 $(_CI_LOCAL_LINT_ENV) bash .github/scripts/run-ci-locally.sh $(_CI_LOCAL_FLAGS)

ci-local-help:
	@bash .github/scripts/run-ci-locally.sh --help

codeql-local:
	@AUTO_INSTALL_LINUX_DEPS=0 bash .github/scripts/run-codeql-locally.sh $(_CI_LOCAL_FLAGS)

lima: ensure-build-owner
	@AUTO_INSTALL_LINUX_DEPS=0 $(_CI_LOCAL_LINT_ENV) bash .github/scripts/run-ci-locally.sh --lima $(_CI_LOCAL_FLAGS)

deps:
	@PCSC_FIDO_ALLOW_SUDO_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 \
	  PCSC_FIDO_DEPS_SCOPE="$(PCSC_FIDO_DEPS_SCOPE)" \
	  bash .github/scripts/install-linux-deps.sh

maybe-deps:
	@if [ "$(INSTALL_DEPS)" != "0" ]; then \
	  $(MAKE) deps INSTALL_DEPS="$(INSTALL_DEPS)" PCSC_FIDO_DEPS_SCOPE="$(PCSC_FIDO_DEPS_SCOPE)"; \
	fi

# Install: stage a Release pcsc-fido binary into the prefix (no unit tests). Rebuild runs as
# the build/ owner, not root. Run `make test` separately before install when you want tests.
install:
	@if [ "$(INSTALL_DEPS)" != "0" ]; then \
	  $(MAKE) deps INSTALL_DEPS="$(INSTALL_DEPS)" PCSC_FIDO_DEPS_SCOPE=build; \
	fi
	@BUILD_DIR="$(BUILD_DIR)" INSTALL_PREFIX="$(INSTALL_PREFIX)" INSTALL_BUILD_TYPE="$(INSTALL_BUILD_TYPE)" \
	  bash "$(CURDIR)/.github/scripts/install-built-tree.sh"
	@$(MAKE) post-install INSTALL_BUILD_TYPE="$(INSTALL_BUILD_TYPE)"

install-debug: INSTALL_BUILD_TYPE=Debug
install-debug: install
	@if command -v systemctl >/dev/null 2>&1; then \
	  install -d -m 0755 /etc/systemd/system/pcsc-fido.service.d; \
	  printf '%s\n' '[Service]' 'Environment=PCSC_FIDO_DEBUG=1' \
	    >/etc/systemd/system/pcsc-fido.service.d/90-pcsc-fido-debug.conf; \
	  systemctl daemon-reload || true; \
	  systemctl restart pcsc-fido.service || true; \
	  printf '%s\n' 'pcsc-fido debug logging enabled via /etc/systemd/system/pcsc-fido.service.d/90-pcsc-fido-debug.conf'; \
	fi

post-install:
	@INSTALL_BUILD_TYPE="$(INSTALL_BUILD_TYPE)" bash .github/scripts/install-post-linux.sh

uninstall:
	@BUILD_DIR="$(BUILD_DIR)" INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  bash "$(CURDIR)/.github/scripts/uninstall-built-tree.sh"

package:
	@$(MAKE) build INSTALL_DEPS="$(INSTALL_DEPS)" PCSC_FIDO_DEPS_SCOPE=package
	@if ! command -v dpkg-deb >/dev/null 2>&1 && ! command -v rpmbuild >/dev/null 2>&1; then \
	  printf 'warning: neither dpkg-deb nor rpmbuild found; CPack emits TGZ only (install via: make deps)\n' >&2; \
	fi
	@cmake --build "$(BUILD_DIR)" --target package

clean: refuse-root
	@bash .github/scripts/helper-clean-build-tree.sh $(BUILD_TREES)

help:
	@printf '%s\n' \
	  'Targets:' \
	  '  make                      Build pcsc-fido binary only (no unit tests)' \
	  '  make debug                Build pcsc-fido with CMAKE_BUILD_TYPE=Debug' \
	  '  sudo make install         Install Release pcsc-fido + packaging files (no tests)' \
	  '  sudo make install-debug   Install Debug pcsc-fido and enable PCSC_FIDO_DEBUG logs' \
	  '  sudo make uninstall       Strictly purge source install only (use dnf/apt remove for release packages)' \
	  '  make test                 Run unit tests (plain build)' \
	  '  make fuzz                 Local libFuzzer (FUZZ_SECONDS=180 default; FUZZ_FLAGS for script opts)' \
	  '  make verify               Full verification: plain, ASan, UBSan, TSan, Valgrind (needs valgrind)' \
	  '  make lint                 Org lint kit: format, clang-tidy, cppcheck, OpenSSF flag audit, policy checks' \
	  '  make security-lint        zizmor, actionlint and TruffleHog' \
	  '  make ci-local             Local CI replay (lint + container matrix; CI_LOCAL_FLAGS; default --main)' \
	  '  make coverage             gcov/lcov line coverage (build/coverage-html/)' \
	  '  make codeql-local         Local CodeQL database/analyze replay' \
	  '  make lima                 Local CI in Lima VM (lint container; default --quick)' \
	  '  make package              CPack TGZ/DEB/RPM (TGZ always; .deb/.rpm need dpkg-deb or rpmbuild)' \
	  '  make clean                Remove build/, build-*, .fuzz, scan-build-report, .lint-kit-org, and tool caches (not dist/)' \
	  '  make deps                 Install Linux build/test/lint deps (run once on new machines)' \
	  '' \
	  'ci-local flags (make ci-local-help): --quick --main --full --coverage --release --all-release --release-arch --security --openssf --lima' \
	  '  example: make ci-local CI_LOCAL_FLAGS="--release-arch riscv64"' \
	  '' \
	  'Variables: INSTALL_DEPS=1 auto-runs make deps before build/test/package/verify (default 0); PCSC_FIDO_DEPS_SCOPE=build|package|verify|full; BUILD_DIR, TEST_BUILD_DIR, INSTALL_PREFIX, INSTALL_BUILD_TYPE' \
	  '  PCSC_FIDO_KEEP_HOST_BUILDS=1  Skip wipe for make test/lint/verify only (CI always wipes CMake trees)'
