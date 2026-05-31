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

Publish **`pcsc-fido`** packages, source, and checksums from an annotated `v*` tag.

Pushing a tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml). CI builds packages, writes `SHA256SUMS`, and creates the GitHub Release from [`.github/release-notes.md`](.github/release-notes.md) (`release-render-notes.sh` substitutes `@TAG@` / `@VERSION@`). For release-specific notes, edit the release description in the GitHub UI after CI finishes.

## Maintainer checklist

1. Merge to **`main`** with green **Main CI**.
2. Bump `project(pcsc_fido VERSION ...)` in [`CMakeLists.txt`](CMakeLists.txt) to match the tag without `v`, and commit. That is the **only** version source: CMake generates `include/pcsc_fido/version.h` for `pcsc-fido --version`, and the same value feeds CPACK / `.deb` / `.rpm` package versions.
3. Tag **that commit**, then push **`main`** and the tag together:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin main v0.1.0
```

The tag should point at the commit that contains the version bump so packages and the source tarball report the correct version.

Local verification before tagging (optional):

```bash
make verify
make lint
make ci-suite CI_SUITE_FLAGS=--release   # optional local amd64 .deb smoke
```

Preview rendered release notes (optional):

```bash
TAG=v0.1.0 bash .github/scripts/release-render-notes.sh
```

## Assets

The release publishes **14 files**:

- `.deb`: amd64, arm64, armhf, ppc64el, riscv64, s390x
- `.rpm`: x86_64, aarch64, armv7hl, ppc64le, riscv64, s390x
- Source tarball: `pcsc-fido-VERSION.tar.gz`
- Checksums: `SHA256SUMS`

CI verifies asset counts and filenames. Unit tests run in the release lint gate on amd64 (`ci-lint.sh`). Native package builds also run `ctest` with `BUILD_TESTING=ON`; cross-compiled ports skip unit tests (`SKIP_CTEST=1`) and are file-checked only.

## Verify downloads

```bash
sha256sum -c SHA256SUMS
```

GitHub also displays a SHA-256 digest per release asset.

Last Updated: 2026-05-30
