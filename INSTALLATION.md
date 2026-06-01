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

Use one install path only:

| Path | Use for |
| ---- | ------- |
| [Release package](#1-release-package-install) | Normal `.deb` / `.rpm` install from GitHub Releases. |
| [Source install](#2-source-install) | Development, local testing, unsupported distributions, or Debug builds. |

## Release packages vs source install

Install is equivalent (same CMake files and `packaging/scripts/postinst`); uninstall is not — use `dnf remove` / `apt remove` for packages and `sudo make uninstall` only for source installs (which also deletes the `pcsc-fido` user and the entire `/etc/systemd/system/pcsc-fido.service.d/` drop-in directory, including custom overrides). Do not mix both paths under `/usr`.

## 1. Release package install

Installed layout under `/usr` (same for `.deb` and `.rpm`; RPM also ships `/usr/share/licenses/pcsc-fido/LICENSE`):

```bash
# Packaged files
/usr/bin/pcsc-fido
/usr/lib/pcsc-fido/ensure-pcsc-fido-user.sh   # mode 0700 root; install hook only
/usr/lib/modules-load.d/pcsc-fido-uhid.conf
/usr/lib/sysusers.d/pcsc-fido.conf
/usr/lib/systemd/system/pcsc-fido.service
/usr/lib/systemd/system-preset/60-pcsc-fido.preset
/usr/lib/udev/rules.d/70-pcsc-fido.rules
/usr/share/doc/pcsc-fido/INSTALLATION.md
/usr/share/doc/pcsc-fido/NOTICE
/usr/share/polkit-1/rules.d/50-pcsc-fido.rules
```

Download the package for your distro/CPU from the GitHub release and install it with the distro package manager. The packages declare runtime dependencies for PC/SC, the USB CCID reader driver, systemd, udev, the PC/SC client library, and PolicyKit (`polkit` on Fedora/RHEL; `polkitd` on Debian/Ubuntu).

Fedora/RHEL:

```bash
sudo dnf install ./pcsc-fido-*.rpm
sudo systemctl enable --now pcscd.socket
sudo systemctl enable --now pcsc-fido.service
```

Debian/Ubuntu:

```bash
# Install and enable services
sudo dpkg -i ./pcsc-fido_*.deb && sudo apt-get install -f
sudo systemctl enable --now pcscd.socket
sudo systemctl enable --now pcsc-fido.service

# Alternative: If apt-get fails in a private home directory
cp ./pcsc-fido_*.deb /tmp/
sudo apt-get install /tmp/pcsc-fido_*.deb
```

Enable **`pcscd.socket`** (not **`pcscd.service`**) for socket activation. The PC/SC listener opens at boot, and **`pcscd`** starts when the first client (e.g., **`pcsc-fido`**) connects.

Install **`pcsc-tools`** only if you want **`pcsc_scan`**; otherwise use **`pcsc-fido --list-readers`** after the bridge is installed.

After upgrading an already-enabled install, restart **`pcsc-fido.service`** so the running daemon uses the new binary.

### Uninstall release packages

Use the distro package manager — not **`sudo make uninstall`** (see [Release packages vs source install](#release-packages-vs-source-install)):

```bash
# Fedora/RHEL
sudo dnf remove pcsc-fido

# Debian/Ubuntu
sudo apt-get remove pcsc-fido
```

Package removal stops/disables **`pcsc-fido.service`** and deletes the **`/usr`** files above. It does **not** remove the **`pcsc-fido`** system user, optional **`systemctl edit`** overrides under **`/etc/systemd/system/pcsc-fido.service.d/`**, or PC/SC stack packages (`pcscd`, CCID driver). Delete overrides yourself if you no longer need them.

## 2. Source install

Install build/runtime dependencies for the source tree:

Fedora/RHEL:

```bash
sudo dnf install -y cmake gcc make pkgconf-pkg-config pcsc-lite pcsc-lite-devel pcsc-lite-ccid pcsc-tools systemd udev libasan libubsan libtsan valgrind
```

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y cmake gcc make pkg-config pcscd libpcsclite-dev libccid pcsc-tools systemd udev libasan8 libubsan1 libtsan2 valgrind nodejs npm shfmt
```

Build and verify as your normal user. Install the packages above manually, or run `make deps` once to bootstrap them via apt/dnf. Plain `make` does not install packages; prefix a command with `INSTALL_DEPS=1` to auto-install only what that target needs (for example, `INSTALL_DEPS=1 make verify`):

```bash
make help
make clean
make
make lint
make test
make verify
...
```

Install into `/usr`:

```bash
sudo make install INSTALL_PREFIX=/usr
sudo systemctl enable --now pcscd.socket
sudo systemctl enable --now pcsc-fido.service
```

Notes:

- `sudo make install` builds/stages a **Release** daemon only; run tests first when you want verification.
- It installs the same **`/usr`** layout as release packages and runs the same **`packaging/scripts/postinst`** hook.
- It does **not** enable/start **`pcscd.socket`** or **`pcsc-fido.service`**; run the commands above.

Explicit first-time dependency bootstrap:

```bash
make deps
```

Debug install for protocol logs:

```bash
make debug
sudo make install-debug INSTALL_PREFIX=/usr
```

Release binaries compile out **`PCSC_FIDO_DEBUG`**. **`install-debug`** writes **`/etc/systemd/system/pcsc-fido.service.d/90-pcsc-fido-debug.conf`** (`PCSC_FIDO_DEBUG=1`). Reinstall Release or delete that file when finished.

### Uninstall source builds

Use this only for source installs (stricter than `dnf`/`apt remove` — see [Release packages vs source install](#release-packages-vs-source-install)):

```bash
sudo make uninstall INSTALL_PREFIX=/usr
```

Source uninstall stops/disables the service, removes the **`/usr`** install tree, deletes the entire **`/etc/systemd/system/pcsc-fido.service.d/`** drop-in directory if present, removes the **`pcsc-fido`** user/group, reloads systemd/udev, and fails if known leftovers remain. It does not remove `.deb` / `.rpm` package records.

Do not mix a release package and a source install under the same prefix.

## Configuration

Optional overrides under **`/etc/systemd/system/pcsc-fido.service.d/`** (not shipped in the package — only from **`systemctl edit`** or **`install-debug`**):

```bash
sudo systemctl edit pcsc-fido.service
```

Example:

```ini
[Service]
Environment=PCSC_FIDO_READER=omnikey
```

Reload after changing overrides:

```bash
sudo systemctl daemon-reload
sudo systemctl restart pcsc-fido.service
```

Common environment variables:

| Variable | Purpose |
| -------- | ------- |
| `PCSC_FIDO_READER` | Case-insensitive PC/SC reader substring when auto-selection is not desired. |
| `PCSC_FIDO_VIRTUAL_KEY` | `tap-arm` default virtual key or `always` legacy visible mode. |
| `PCSC_FIDO_ARM_SEC` | Tap-arm virtual-key window (seconds); default `60`; valid `1`–`86400` (`0` rejected; invalid/oob → default). Does **not** change the fixed 60s PC/SC card-wait timeout. |
| `PCSC_FIDO_RATE_LIMIT` | Set to `0` to disable CTAPHID/PCSC rate limiting for diagnostics only. |
| `PCSC_FIDO_RATE_WINDOW_SEC` | Rolling rate-limit window (seconds); default `90`; valid `1`–`1000000` (invalid/`0`/oob → default). |
| `PCSC_FIDO_RATE_CTAPHID` | CTAPHID frame budget per window; default `30`; valid `1`–`1000000` (invalid/`0`/oob → default). |
| `PCSC_FIDO_RATE_EXCHANGE` | PC/SC exchange budget per window; default `10`; valid `1`–`1000000` (invalid/`0`/oob → default). |

Reader selection is automatic when unambiguous: a single matching reader is used; a single contactless non-SAM slot may be auto-selected from a SAM/PICC pair; otherwise card-present readers win when several attached readers report cards, with a FIDO AID probe as the final tiebreaker. After a reader is chosen, the bridge **re-checks card presence** immediately before `SCardConnect`, and reuses an existing PC/SC session only after **`SCardStatus`** confirms the card is still in the field (see [REMEDIATIONS.md](docs/REMEDIATIONS.md#safeguards-for-pcsc-fido-nfc-specific)).

### CLI (no daemon start)

These exit without opening `/dev/uhid`:

```bash
pcsc-fido --help
pcsc-fido --version
pcsc-fido --print-config    # resolved env (virtual-key mode, arm timing)
pcsc-fido --list-readers    # PC/SC readers visible to pcscd
```

## Local package builds

```bash
INSTALL_DEPS=1 make package    # CPack in build/ (TGZ; DEB/RPM when tools present)
make ci-suite CI_SUITE_FLAGS=--release
make ci-suite CI_SUITE_FLAGS="--release-arch riscv64"
bash .github/scripts/run-local-release-packages.sh --all
```

Last Updated: 2026-05-30
