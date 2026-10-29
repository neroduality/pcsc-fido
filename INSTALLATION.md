<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
Copyright (C) 2026 Nero Duality, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

<!-- Upstream: https://github.com/neroduality/pcsc-fido -->

# Installation (Linux)

Pick one path. Do not mix both under `/usr`.

| Path | Use for | Uninstall with |
| ---- | ------- | -------------- |
| [Release package](#1-release-package-install) | Normal use | `dnf remove` / `apt-get remove` |
| [Source install](#2-source-install) | Development, Debug builds, unsupported distros | `sudo make uninstall` |

Both install the same files and run the same `packaging/scripts/postinst`.

## 1. Release package install

Download the `.rpm` or `.deb` for your CPU from [GitHub Releases](https://github.com/neroduality/pcsc-fido/releases). Dependencies (`pcscd`, CCID driver, `libpcsclite`, systemd, udev, polkit) are pulled in automatically. Minimum glibc per package: [RELEASE.md](RELEASE.md#builders-and-glibc-floors).

Fedora/RHEL:

```bash
sudo dnf install ./pcsc-fido-*.rpm
sudo systemctl enable --now pcscd.socket pcsc-fido.service
```

Debian/Ubuntu:

```bash
sudo dpkg -i ./pcsc-fido_*.deb && sudo apt-get install -f
sudo systemctl enable --now pcscd.socket pcsc-fido.service
```

Enable `pcscd.socket`, not `pcscd.service`: `pcscd` then starts on first use. `pcsc-tools` (for `pcsc_scan`) is optional; `pcsc-fido --list-readers` does the same job.

After an upgrade, run `sudo systemctl restart pcsc-fido.service`.

Installed files:

```text
/usr/bin/pcsc-fido
/usr/lib/pcsc-fido/ensure-pcsc-fido-user.sh   # root 0700, install hook only
/usr/lib/modules-load.d/pcsc-fido-uhid.conf
/usr/lib/sysusers.d/pcsc-fido.conf
/usr/lib/systemd/system/pcsc-fido.service
/usr/lib/systemd/system-preset/60-pcsc-fido.preset
/usr/lib/udev/rules.d/70-pcsc-fido.rules
/usr/share/doc/pcsc-fido/INSTALLATION.md
/usr/share/doc/pcsc-fido/NOTICE
/usr/share/polkit-1/rules.d/50-pcsc-fido.rules
/usr/share/licenses/pcsc-fido/LICENSE          # RPM only
```

### Uninstall packages

```bash
sudo dnf remove pcsc-fido        # Fedora/RHEL
sudo apt-get remove pcsc-fido    # Debian/Ubuntu
```

This stops the service and removes the files above. It keeps the `pcsc-fido` user, your overrides in `/etc/systemd/system/pcsc-fido.service.d/`, and the PC/SC packages.

## 2. Source install

Dependencies:

```bash
# Fedora/RHEL
sudo dnf install -y cmake gcc make pkgconf-pkg-config pcsc-lite pcsc-lite-devel pcsc-lite-ccid pcsc-tools systemd udev libasan libubsan libtsan valgrind

# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y cmake gcc make pkg-config pcscd libpcsclite-dev libccid pcsc-tools systemd udev libasan8 libubsan1 libtsan2 valgrind
```

These cover `make`, `make test`, and `make verify`. `make lint` also needs clang-format, clang-tidy, cppcheck, shellcheck, codespell, yamllint, shfmt, Node.js, and PyYAML. `make deps` installs everything; `INSTALL_DEPS=1 make <target>` installs only what that target needs. Plain `make` never installs packages. `make help` lists all targets.

Build, test, install:

```bash
make && make test
sudo make install INSTALL_PREFIX=/usr
sudo systemctl enable --now pcscd.socket pcsc-fido.service
```

`make install` builds a Release binary and does not run tests or enable services.

### Debug install

```bash
make debug
sudo make install-debug INSTALL_PREFIX=/usr
```

This adds `/etc/systemd/system/pcsc-fido.service.d/90-pcsc-fido-debug.conf` (`PCSC_FIDO_DEBUG=1`). Debug logs contain credential data; see [DEBUGGING](docs/DEBUGGING.md#debug-build). Reinstall Release or delete that file when done.

### Uninstall a source install

```bash
sudo make uninstall INSTALL_PREFIX=/usr
```

Stricter than package removal: also deletes the `pcsc-fido` user and group and the whole `/etc/systemd/system/pcsc-fido.service.d/` directory (including your overrides), then fails if anything is left behind.

## Configuration

Set environment variables in a drop-in:

```bash
sudo systemctl edit pcsc-fido.service
```

```ini
[Service]
Environment=PCSC_FIDO_READER=omnikey
```

`systemctl edit` reloads systemd; then run `sudo systemctl restart pcsc-fido.service`.

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `PCSC_FIDO_READER` | auto | Case-insensitive substring of the reader name. |
| `PCSC_FIDO_VIRTUAL_KEY` | `tap-arm` | `always` keeps the virtual key (the FIDO device the browser sees) visible; for diagnostics. Other values: daemon won't start. |
| `PCSC_FIDO_ARM_SEC` | `60` | Seconds the virtual key stays visible after a tap. `1`-`86400`; `0` stops the daemon from starting; other invalid values use the default. Does not change the 60 s wait for the NFC security key. |
| `PCSC_FIDO_RATE_LIMIT` | on | `0` disables rate limiting (diagnostics only). |
| `PCSC_FIDO_RATE_WINDOW_SEC` | `90` | Time for an empty budget to refill. |
| `PCSC_FIDO_RATE_CTAPHID` | `60` | Budget of CTAPHID INIT frames (CANCEL and continuation frames are free). |
| `PCSC_FIDO_RATE_EXCHANGE` | `24` | Budget of commands sent to the NFC security key. |

The three `RATE_*` values accept `1`-`1000000`; anything else uses the default.

Reader auto-selection and presence checks: [Safeguards](docs/REMEDIATIONS.md#safeguards).

### CLI

These exit without opening `/dev/uhid`:

```bash
pcsc-fido --help
pcsc-fido --version
pcsc-fido --print-config    # resolved virtual-key mode and arm window
pcsc-fido --list-readers    # readers visible to pcscd
```

## Local package builds

```bash
make package                                     # host-arch .deb/.rpm into dist/; PACKAGE_FORMAT=auto|deb|rpm|both
make ci-local CI_LOCAL_FLAGS=--release           # every arch, native + cross (slow)
make ci-local CI_LOCAL_FLAGS="--release-arch riscv64"   # one arch
bash .github/scripts/run-local-release-packages.sh --all
```

`make package` runs the same build, `ctest`, and glibc/ELF checks as `--release-arch`, without a container.
