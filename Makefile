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
BUILD_TREES ?= $(BUILD_DIR) $(BUILD_DIR)-asan $(BUILD_DIR)-ubsan $(BUILD_DIR)-valgrind $(BUILD_DIR)-tsan $(BUILD_DIR)/lint $(BUILD_DIR)/ci .fuzz build-fuzz
CMAKE_BUILD_TYPE ?= Debug
INSTALL_PREFIX ?= /usr
INSTALL_BUILD_TYPE ?= Release
LINT_FLAGS ?=
INSTALL_DEPS ?= 1

.DEFAULT_GOAL := all

.PHONY: all build debug test verify asan ubsan valgrind tsan sanitizers sanitiziers lint security-lint ci-suite ci-suite-help deps maybe-deps install install-debug post-install uninstall package package-release-deb clean help refuse-root ensure-build-owner fuzz

# Build/test targets must not run as root — keeps build/ user-owned.
refuse-root:
	@bash "$(CURDIR)/.github/scripts/helper-build-tree-ownership.sh" refuse-root-make

ensure-build-owner: refuse-root
	@bash "$(CURDIR)/.github/scripts/helper-ensure-build-tree-owner.sh" $(BUILD_TREES)

all: build

build: ensure-build-owner maybe-deps
	@cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CMAKE_BUILD_TYPE)" \
	  -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" -DBUILD_TESTING=OFF
	@cmake --build "$(BUILD_DIR)" --target pcsc-fido -j$$(nproc 2>/dev/null || echo 2)

debug: CMAKE_BUILD_TYPE=Debug
debug: build

test: ensure-build-owner maybe-deps
	@cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CMAKE_BUILD_TYPE)" \
	  -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" -DBUILD_TESTING=ON \
	  -DPCSC_FIDO_DEBUG_SANITIZERS=OFF
	@cmake --build "$(BUILD_DIR)" --target pcsc_fido_unit_tests \
	  -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)" --output-on-failure

asan: ensure-build-owner maybe-deps
	@cmake -S . -B "$(BUILD_DIR)-asan" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_ENABLE_ASAN=ON
	@cmake --build "$(BUILD_DIR)-asan" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-asan" --output-on-failure

ubsan: ensure-build-owner maybe-deps
	@cmake -S . -B "$(BUILD_DIR)-ubsan" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_ENABLE_UBSAN=ON
	@cmake --build "$(BUILD_DIR)-ubsan" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-ubsan" --output-on-failure

valgrind: ensure-build-owner maybe-deps
	@if ! command -v valgrind >/dev/null 2>&1; then \
	  printf 'error: valgrind not found (install via: make deps INSTALL_DEPS=1)\n' >&2; \
	  exit 1; \
	fi
	@cmake -S . -B "$(BUILD_DIR)-valgrind" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$(INSTALL_PREFIX)" \
	  -DBUILD_TESTING=ON -DPCSC_FIDO_DEBUG_SANITIZERS=OFF
	@cmake --build "$(BUILD_DIR)-valgrind" --target pcsc_fido_unit_tests -j$$(nproc 2>/dev/null || echo 2)
	@ctest --test-dir "$(BUILD_DIR)-valgrind" -T memcheck --output-on-failure

verify: test asan ubsan tsan valgrind

tsan: ensure-build-owner maybe-deps
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

sanitiziers: sanitizers

lint: ensure-build-owner maybe-deps
	@LINT_BUILD_DIR="$(BUILD_DIR)/lint" bash .github/linters/ci-lint.sh $(LINT_FLAGS)

fuzz: refuse-root
	@PCSC_FIDO_AUTO_FUZZ_DEPS=1 bash "$(CURDIR)/.github/scripts/run-local-fuzz.sh" $(FUZZ_FLAGS)

security-lint:
	@AUTO_INSTALL_LINUX_DEPS=0 bash .github/scripts/run-local-security-suite.sh $(SECURITY_LINT_FLAGS)

ci-suite: ensure-build-owner
	@AUTO_INSTALL_LINUX_DEPS=0 bash .github/scripts/run-local-ci-suite.sh $(CI_SUITE_FLAGS)

ci-suite-help:
	@bash .github/scripts/run-local-ci-suite.sh --help

deps:
	@PCSC_FIDO_ALLOW_SUDO_DEPS=1 AUTO_INSTALL_LINUX_DEPS="$(INSTALL_DEPS)" \
	  bash .github/scripts/install-linux-deps.sh

maybe-deps:
	@if [ "$(INSTALL_DEPS)" != "0" ]; then $(MAKE) deps INSTALL_DEPS="$(INSTALL_DEPS)"; fi

# Install: stage a Release pcsc-fido binary into the prefix (no unit tests). Rebuild runs as
# the build/ owner, not root. Run `make test` separately before install when you want tests.
install:
	@if [ "$(INSTALL_DEPS)" != "0" ]; then $(MAKE) deps INSTALL_DEPS="$(INSTALL_DEPS)"; fi
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

package: build
	@cmake --build "$(BUILD_DIR)" --target package

package-release-deb:
	@bash .github/scripts/release-build-package.sh --format deb --arch amd64

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
	  '  make verify               Full verification: plain, ASan, UBSan, TSan, Valgrind' \
	  '  make lint                 Format, spec coverage, shell, spelling, build, tests, cppcheck' \
	  '  make security-lint        License headers, zizmor, supply-chain, and secret scans' \
	  '  make ci-suite             Local CI replay (CI_SUITE_FLAGS; default --quick)' \
	  '  make package              CPack TGZ/DEB/RPM when supported' \
	  '  make clean                Remove build/, build-*, .fuzz, scan-build-report (not dist/)' \
	  '' \
	  'ci-suite flags (make ci-suite-help): --quick --main --full --coverage --release --all-release --release-arch --security --openssf' \
	  '  example: make ci-suite CI_SUITE_FLAGS="--release-arch riscv64"' \
	  '' \
	  'Variables: INSTALL_DEPS=0 skips automatic Linux dependency bootstrap; BUILD_DIR, INSTALL_PREFIX, INSTALL_BUILD_TYPE'
