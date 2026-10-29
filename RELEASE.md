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

# Release

Pushing an annotated `v*` tag runs [`release.yml`](.github/workflows/release.yml): Main CI, then all packages, `SHA256SUMS`, and a GitHub Release whose body is [`.github/release-notes.md`](.github/release-notes.md) with `@TAG@` / `@VERSION@` filled in.

## Checklist

1. Main CI is green on `main`. Run the supply-chain workflow manually (produces the SBOM).
2. Set `project(pcsc_fido VERSION x.y.z)` in [`CMakeLists.txt`](CMakeLists.txt) and commit. This is the only version source (`--version` and package versions).
3. Tag and push together:

   ```bash
   git tag -a v0.3.0 -m "v0.3.0"
   git push origin main v0.3.0
   ```

4. After CI finishes, add release notes in the GitHub UI.

Optional local checks before tagging:

```bash
make verify
make lint
make ci-local CI_LOCAL_FLAGS=--release                 # all packages, all arches
TAG=v0.3.0 bash .github/scripts/release-render-notes.sh # preview release body
```

## Assets

- `.deb`: amd64, arm64, armhf, ppc64el, riscv64, s390x
- `.rpm`: x86_64, aarch64, armv7hl, ppc64le, riscv64, s390x
- `pcsc-fido-VERSION.tar.gz`
- `SHA256SUMS` for the 13 files above

Each file has a SLSA provenance attestation on GitHub (not a release file). The SPDX SBOM is an Actions artifact of the supply-chain workflow; its Grype scan reports `high`+ findings without failing the job.

Native builds run `ctest`; cross builds skip it. Every binary must pass the glibc ceiling check and an ELF check allowing only `libc.so.6`, `libpcsclite.so.1`, `libgcc_s.so.1`, and the dynamic linker as `DT_NEEDED`.

### Builders and glibc floors

Since 0.2.1 (ISO C23). A package needs at least the glibc of the system that built it. `verify-glibc-ceiling.sh` rejects any binary that references a newer `GLIBC_*` symbol version.

| Assets | Builder | Min. target glibc |
| ------ | ------- | ----------------- |
| `.deb` amd64, arm64 | `debian:trixie-slim` | 2.41 |
| `.deb` armhf, ppc64el, riscv64, s390x | `debian:trixie` cross | 2.41 |
| `.rpm` x86_64, aarch64 | `fedora:38` | 2.37 |
| `.rpm` armv7hl, ppc64le, riscv64, s390x | `debian:trixie` cross + `rpmbuild` | 2.41 |

Cross `.rpm`s therefore need a newer glibc than native ones. Native `.deb`s get their `libc6` dependency from `dpkg-shlibdeps`; cross `.deb`s disable it and declare no `libc6` version.

## Verify downloads

```bash
sha256sum -c SHA256SUMS
gh attestation verify pcsc-fido_VERSION_amd64.deb --repo neroduality/pcsc-fido
```

Same command for any other file, including the source tarball.
